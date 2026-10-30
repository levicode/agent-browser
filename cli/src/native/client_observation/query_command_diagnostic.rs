//! Bounded, failure-only command observations for the existing field-read future.
//! No command arguments, session IDs, renderer data, or authority are retained.
use crate::native::client_settlement_trace::{self as trace, QueryReadStage};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const LIMIT: usize = 24;
const CAP: u16 = 1;
const LOST: u16 = 2;
const UNFINISHED: u16 = 4;
const SATURATED: u16 = 8;

tokio::task_local! {
    static ACTIVE: Arc<Collector>;
}

#[derive(Clone, Copy)]
struct Row {
    stage: QueryReadStage,
    command: [u16; 3],
    ms: [u16; 5],
}
struct State {
    stage: QueryReadStage,
    rows: [Option<Row>; LIMIT],
    seen: u16,
    captured: usize,
    flags: u16,
    frozen: bool,
}
pub(crate) struct Collector {
    state: Mutex<State>,
    lost: AtomicBool,
}
impl Collector {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                stage: QueryReadStage::ReadAdmission,
                rows: [None; LIMIT],
                seen: 0,
                captured: 0,
                flags: 0,
                frozen: false,
            }),
            lost: AtomicBool::new(false),
        })
    }
    pub(crate) fn stage(&self, stage: QueryReadStage) {
        if let Ok(mut state) = self.state.try_lock() {
            if !state.frozen {
                state.stage = stage;
            }
        } else {
            self.lost.store(true, Ordering::Relaxed);
        }
    }
    fn begin(self: &Arc<Self>, method: &str) -> Option<Timer> {
        let Ok(mut state) = self.state.try_lock() else {
            self.lost.store(true, Ordering::Relaxed);
            return None;
        };
        if state.frozen {
            return None;
        }
        state.seen = state.seen.saturating_add(1);
        if state.captured == LIMIT {
            state.flags |= CAP;
            return None;
        }
        let ordinal = state.captured;
        state.rows[ordinal] = Some(Row {
            stage: state.stage,
            command: [ordinal as u16, method_code(method), 0],
            ms: [0; 5],
        });
        state.captured += 1;
        Some(Timer {
            collector: self.clone(),
            ordinal,
            last: now(),
            bucket: 0,
            micros: [0; 5],
            finished: false,
        })
    }
    fn freeze(&self) -> ([Option<Row>; LIMIT], [u16; 3]) {
        let Ok(mut state) = self.state.try_lock() else {
            self.lost.store(true, Ordering::Relaxed);
            return ([None; LIMIT], [0, 0, LOST]);
        };
        state.frozen = true;
        let mut flags = state.flags;
        if self.lost.load(Ordering::Relaxed) {
            flags |= LOST;
        }
        if state.rows.iter().flatten().any(|row| row.command[2] == 0) {
            flags |= UNFINISHED;
        }
        (state.rows, [state.seen, state.captured as u16, flags])
    }
    #[cfg(test)]
    pub(crate) fn test_commands(&self) -> (Vec<[u16; 3]>, [u16; 3]) {
        let (rows, summary) = self.freeze();
        (
            rows.into_iter().flatten().map(|row| row.command).collect(),
            summary,
        )
    }
    pub(crate) fn emit_failure(&self, generation: u64, sequence: u64) {
        let (rows, summary) = self.freeze();
        for row in rows.into_iter().flatten() {
            trace::query_command_timing(generation, sequence, row.stage, row.command, row.ms);
        }
        trace::query_command_summary(generation, sequence, summary);
    }
}

pub(crate) async fn scope<T>(collector: Arc<Collector>, future: impl Future<Output = T>) -> T {
    // No spawn: inherited authority, cancellation and polling order are unchanged.
    ACTIVE.scope(collector, future).await
}

fn method_code(method: &str) -> u16 {
    match method {
        "Page.getFrameTree" => 1,
        "Page.createIsolatedWorld" => 2,
        "DOM.getDocument" => 3,
        "DOM.describeNode" => 4,
        "DOM.resolveNode" => 5,
        "Runtime.callFunctionOn" => 6,
        "DOM.getFrameOwner" => 7,
        _ => 0,
    }
}

#[derive(Clone, Copy)]
#[repr(u16)]
pub(crate) enum Outcome {
    Success = 1,
    ErrorAck = 2,
    LocalFailure = 3,
    ChannelClosed = 4,
    WaitDeadline = 5,
    Abandoned = 6,
}

/// Five disjoint local intervals: prepare, writer wait, pending-map wait,
/// submission/write, and post-send wait. The last includes browser, wire,
/// reader parsing/settlement and scheduling; it is not browser execution time.
/// Drop means abandonment OR a synchronous submission refusal, not proof that
/// a CDP command was transmitted or that application cancellation caused it.
pub(crate) struct Timer {
    collector: Arc<Collector>,
    ordinal: usize,
    last: Instant,
    bucket: usize,
    micros: [u64; 5],
    finished: bool,
}
impl Timer {
    pub(crate) fn start(method: &str) -> Option<Self> {
        // With no opted-in field scope: no clock, lock, allocation or output.
        ACTIVE
            .try_with(|collector| collector.begin(method))
            .ok()
            .flatten()
    }
    pub(crate) fn advance(timer: &mut Option<Self>, bucket: usize) {
        if let Some(timer) = timer {
            timer.advance_at(bucket, now());
        }
    }
    fn advance_at(&mut self, bucket: usize, now: Instant) {
        self.micros[self.bucket] = self.micros[self.bucket].saturating_add(
            now.saturating_duration_since(self.last)
                .as_micros()
                .min(u64::MAX as u128) as u64,
        );
        self.last = now;
        self.bucket = bucket;
    }
    pub(crate) fn finish(timer: &mut Option<Self>, outcome: Outcome) {
        if let Some(timer) = timer {
            timer.finish_at(outcome, now());
        }
    }
    fn finish_at(&mut self, outcome: Outcome, now: Instant) {
        if self.finished {
            return;
        }
        self.advance_at(self.bucket, now);
        self.finished = true;
        let Ok(mut state) = self.collector.state.try_lock() else {
            self.collector.lost.store(true, Ordering::Relaxed);
            return;
        };
        if state.frozen {
            // The frozen row already says unfinished; a late ACK cannot repair it.
            return;
        }
        let ms = self.micros.map(|value| {
            let value = value / 1000;
            if value > u16::MAX as u64 {
                state.flags |= SATURATED;
            }
            value.min(u16::MAX as u64) as u16
        });
        if let Some(row) = state.rows[self.ordinal].as_mut() {
            row.command[2] = outcome as u16;
            row.ms = ms;
        } else {
            self.collector.lost.store(true, Ordering::Relaxed);
        }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        if !self.finished {
            self.finish_at(Outcome::Abandoned, now());
        }
    }
}
fn now() -> Instant {
    #[cfg(test)]
    CLOCK_READS.with(|reads| reads.set(reads.get() + 1));
    Instant::now()
}
#[cfg(test)]
thread_local! {
    static CLOCK_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn disabled_scope_does_not_read_clock_or_start_timer() {
        let before = CLOCK_READS.with(|reads| reads.get());
        let mut timer = Timer::start("Page.getFrameTree");
        assert!(timer.is_none());
        Timer::advance(&mut timer, 1);
        Timer::finish(&mut timer, Outcome::Success);
        drop(timer);
        assert_eq!(CLOCK_READS.with(|reads| reads.get()), before);
    }
    #[tokio::test]
    async fn command_drop_and_late_completion_never_become_success() {
        let collector = Collector::new();
        let mut pending = Box::pin(scope(collector.clone(), async {
            let _timer = Timer::start("Page.getFrameTree").unwrap();
            std::future::pending::<()>().await;
        }));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        drop(pending);
        let (rows, summary) = collector.freeze();
        assert_eq!(summary, [1, 1, 0]);
        assert_eq!(rows[0].unwrap().command, [0, 1, Outcome::Abandoned as u16]);

        let collector = Collector::new();
        let timer = scope(collector.clone(), async {
            Timer::start("DOM.resolveNode").unwrap()
        })
        .await;
        let (rows, summary) = collector.freeze();
        assert_eq!(summary, [1, 1, UNFINISHED]);
        assert_eq!(rows[0].unwrap().command[2], 0);
        drop(timer);
        assert_eq!(collector.freeze().1, [1, 1, UNFINISHED]);
    }
    #[tokio::test]
    async fn fixed_cap_contention_and_saturation_are_explicit() {
        let collector = Collector::new();
        scope(collector.clone(), async {
            for _ in 0..=LIMIT {
                let mut timer = Timer::start("Page.getFrameTree");
                Timer::finish(&mut timer, Outcome::Success);
            }
        })
        .await;
        assert_eq!(collector.freeze().1, [25, 24, CAP]);

        let collector = Collector::new();
        scope(collector.clone(), async {
            let held = collector.state.lock().unwrap();
            assert!(Timer::start("secret-non-enumerated-method").is_none());
            drop(held);
        })
        .await;
        assert_eq!(collector.freeze().1, [0, 0, LOST]);

        let collector = Collector::new();
        scope(collector.clone(), async {
            let mut timer = Timer::start("DOM.getDocument").unwrap();
            timer.finish_at(Outcome::Success, timer.last + Duration::from_secs(70));
        })
        .await;
        let (rows, summary) = collector.freeze();
        assert_eq!(summary, [1, 1, SATURATED]);
        assert_eq!(rows[0].unwrap().ms[0], u16::MAX);
    }
    #[tokio::test]
    async fn scopes_keep_stage_and_ordinal_local_without_inheriting_into_workers() {
        let collector = Collector::new();
        collector.stage(QueryReadStage::ReadFramesAfter);
        scope(collector.clone(), async {
            let mut timer = Timer::start("not-a-serialized-method");
            Timer::advance(&mut timer, 1);
            Timer::advance(&mut timer, 2);
            Timer::advance(&mut timer, 3);
            Timer::advance(&mut timer, 4);
            Timer::finish(&mut timer, Outcome::ErrorAck);
            assert!(
                tokio::spawn(async { Timer::start("Page.getFrameTree").is_none() })
                    .await
                    .unwrap()
            );
        })
        .await;
        let (rows, summary) = collector.freeze();
        assert_eq!(summary, [1, 1, 0]);
        assert_eq!(rows[0].unwrap().stage, QueryReadStage::ReadFramesAfter);
        assert_eq!(rows[0].unwrap().command, [0, 0, Outcome::ErrorAck as u16]);
        assert_eq!(Collector::new().freeze().1, [0, 0, 0]);
    }
}
