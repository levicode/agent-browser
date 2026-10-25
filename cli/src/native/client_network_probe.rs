//! Temporary, delete after the HTTP500 investigation. No authority or payload capture.
use super::{record_capture, Capture, DiagnosticAttachment, Facts, Phase, CLEANUP_SINK};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

pub(crate) const SELECTOR_ENV: &str = "AGENT_BROWSER_NETWORK_PROBE_SHA256";
static PROBE: OnceLock<Option<Probe>> = OnceLock::new();
struct Probe {
    selector: [u8; 32],
    key: [u8; 32],
    rows: AtomicU64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    Ready,
    Receive,
    Dispatch,
    Project,
    Emit,
    Bind,
    Detach,
    Limit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Unreached,
    Invalid,
    WrongSession,
    MissingRequest,
    Stored,
    Duplicate,
    Ignored,
    Projected,
    Unsupported,
    NoSession,
    NotApplication,
    Accepted,
    Failed,
}
#[derive(Clone, Copy, Default, Serialize)]
pub(crate) struct ProbeFact {
    pub stage: Option<Stage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<u8>, // 1=request, 2=response, 3=Fetch request pause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<[u32; 4]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<[u32; 4]>, // Always includes session; Fetch uses networkId.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
}
pub(crate) fn valid_selector(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
impl Probe {
    fn new(selector: &str, key: [u8; 32]) -> Option<Self> {
        if !valid_selector(selector) {
            return None;
        }
        let mut digest = [0; 32];
        hex::decode_to_slice(selector, &mut digest).ok()?;
        Some(Self {
            selector: digest,
            key,
            rows: AtomicU64::new(0),
        })
    }
    fn tag(&self, parts: &[&str]) -> Option<[u32; 4]> {
        if parts
            .iter()
            .any(|part| part.is_empty() || part.len() > 4096)
        {
            return None;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).ok()?;
        for part in parts {
            mac.update(&(part.len() as u32).to_be_bytes());
            mac.update(part.as_bytes());
        }
        let bytes = mac.finalize().into_bytes();
        Some(std::array::from_fn(|i| {
            u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap())
        }))
    }
    fn select(
        &self,
        method: &str,
        session: Option<&str>,
        params: &serde_json::Value,
    ) -> Option<ProbeFact> {
        let (kind, pointer, id) = match method {
            "Network.requestWillBeSent" => (1, "/request/url", "requestId"),
            "Network.responseReceived" => (2, "/response/url", "requestId"),
            "Fetch.requestPaused" => (3, "/request/url", "networkId"),
            _ => return None,
        };
        let url = params.pointer(pointer)?.as_str()?;
        if url.len() > 65536 {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(url.as_bytes()).into();
        if digest != self.selector {
            return None;
        }
        let request = params.get(id).and_then(|v| v.as_str());
        Some(ProbeFact {
            kind: Some(kind),
            session: session.and_then(|s| self.tag(&[s])),
            request: session.zip(request).and_then(|(s, r)| self.tag(&[s, r])),
            status: params
                .pointer("/response/status")
                .and_then(|v| v.as_f64())
                .filter(|v| v.is_finite() && v.fract() == 0.0 && (0.0..=999.0).contains(v))
                .map(|v| v as u16),
            ..Default::default()
        })
    }
    fn record(
        &self,
        capture: &Capture,
        mut fact: ProbeFact,
        stage: Stage,
        outcome: Option<Outcome>,
        binding: Option<DiagnosticAttachment>,
    ) {
        #[allow(deprecated)]
        let Ok(row) = self
            .rows
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                (old < 64).then_some(old + 1)
            })
        else {
            return;
        };
        fact.stage = Some(stage);
        fact.outcome = outcome;
        let mut facts = Facts {
            probe: Some(fact),
            ..Default::default()
        };
        if let Some(binding) = binding {
            facts.generation = Some(binding.generation);
            facts.attachment_ordinal = Some(binding.attachment);
            facts.target_ordinal = Some(binding.target);
        }
        // Reserve the last row as a terminal unknown marker, never silently truncate.
        if row == 63 {
            facts = Facts {
                probe: Some(ProbeFact {
                    stage: Some(Stage::Limit),
                    ..Default::default()
                }),
                ..Default::default()
            };
        }
        record_capture(capture, 0, Phase::NetworkProbe, facts);
    }
}
pub(super) fn initialize(capture: &Capture) {
    let probe = PROBE.get_or_init(|| {
        let selector = std::env::var(SELECTOR_ENV).ok()?;
        if !valid_selector(&selector) {
            return None;
        }
        let mut key = [0; 32];
        getrandom::getrandom(&mut key).ok()?;
        Probe::new(&selector, key)
    });
    if let Some(probe) = probe {
        probe.record(capture, ProbeFact::default(), Stage::Ready, None, None);
    }
}
pub(crate) fn enabled() -> bool {
    PROBE.get().is_some_and(Option::is_some)
}
pub(crate) fn select(
    method: &str,
    session: Option<&str>,
    params: &serde_json::Value,
) -> Option<ProbeFact> {
    PROBE.get()?.as_ref()?.select(method, session, params)
}
pub(crate) fn emit(fact: ProbeFact, stage: Stage, outcome: Option<Outcome>) {
    if let Some(probe) = PROBE.get().and_then(Option::as_ref) {
        if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
            probe.record(capture, fact, stage, outcome, None);
        }
    }
}
pub(crate) fn binding(session: &str, binding: DiagnosticAttachment, stage: Stage) {
    if let Some(probe) = PROBE.get().and_then(Option::as_ref) {
        if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
            probe.record(
                capture,
                ProbeFact {
                    session: probe.tag(&[session]),
                    ..Default::default()
                },
                stage,
                None,
                Some(binding),
            );
        }
    }
}

// Test-only access to the same record_capture -> emit -> AppendSink path. No CDP dependency:
// the harness-free proxy fixture imports this module without native browser modules.
#[cfg(test)]
type TestRecorder<'a> = dyn Fn(&str, Option<&str>, &serde_json::Value, Stage, Option<Outcome>) + 'a;
#[cfg(test)]
pub(crate) fn test_capture(
    url: &str,
    run: impl FnOnce(&TestRecorder<'_>),
) -> Vec<serde_json::Value> {
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = super::cleanup_capture(Some(file.path())).unwrap();
    let probe = Probe::new(&hex::encode(Sha256::digest(url.as_bytes())), [7; 32]).unwrap();
    run(&|method, session, params, stage, outcome| {
        let fact = probe.select(method, session, params).unwrap();
        probe.record(&capture, fact, stage, outcome, None);
    });
    std::fs::read_to_string(file.path())
        .unwrap()
        .lines()
        .map(|line| {
            assert!(line.len() < 512);
            assert!(!line.contains(url));
            serde_json::from_str(line).unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    const URL: &str = "http://127.0.0.1:12345/bad-sw.js";
    fn probe() -> Probe {
        Probe::new(&hex::encode(Sha256::digest(URL.as_bytes())), [7; 32]).unwrap()
    }
    #[derive(Clone)]
    struct TestEvent {
        method: String,
        session_id: Option<String>,
        params: Value,
    }
    fn event(method: &str, session: &str, id: &str) -> TestEvent {
        TestEvent {
            method: method.into(),
            session_id: Some(session.into()),
            params: json!({
                "requestId": id, "networkId": id,
                "request": {"url": URL, "method": "GET", "headers": {"secret": "not-captured"}},
                "response": {"url": URL, "status": 500, "statusText": "Internal Server Error"}
            }),
        }
    }
    fn selected(probe: &Probe, event: &TestEvent) -> Option<ProbeFact> {
        probe.select(&event.method, event.session_id.as_deref(), &event.params)
    }
    fn rows(file: &tempfile::NamedTempFile) -> Vec<Value> {
        std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| {
                assert!(line.len() < 512);
                assert!(!line.contains(URL) && !line.contains("not-captured"));
                serde_json::from_str(line).unwrap()
            })
            .collect()
    }
    #[test]
    fn selector_and_request_keys_are_exact_without_new_identity_authority() {
        for invalid in ["", "abc", &"a".repeat(63), &"a".repeat(65), &"g".repeat(64)] {
            assert!(Probe::new(invalid, [0; 32]).is_none());
        }
        assert!(Probe::new(&"A".repeat(64), [0; 32]).is_some());
        let probe = probe();
        let request = event("Network.requestWillBeSent", "worker", "one");
        let one = selected(&probe, &request).unwrap();
        assert_eq!(
            one.request,
            selected(&probe, &event("Fetch.requestPaused", "worker", "one"))
                .unwrap()
                .request
        );
        assert_ne!(
            one.request,
            selected(&probe, &event("Network.responseReceived", "other", "one"))
                .unwrap()
                .request
        );
        assert_ne!(
            one.request,
            selected(&probe, &event("Network.responseReceived", "worker", "two"))
                .unwrap()
                .request
        );
        let mut missing = event("Fetch.requestPaused", "worker", "one");
        missing.params.as_object_mut().unwrap().remove("networkId");
        assert!(selected(&probe, &missing).unwrap().request.is_none());
        let mut other = request.clone();
        other.params["request"]["url"] = json!("http://127.0.0.1:12346/bad-sw.js");
        assert!(selected(&probe, &other).is_none());
    }
    #[test]
    fn capture_limit_is_terminal_unknown_and_maximum_scalar_rows_fit() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let capture = super::super::cleanup_capture(Some(file.path())).unwrap();
        let probe = probe();
        let fact = ProbeFact {
            kind: Some(2),
            session: Some([u32::MAX; 4]),
            request: Some([u32::MAX; 4]),
            status: Some(999),
            ..Default::default()
        };
        probe.record(
            &capture,
            ProbeFact {
                session: Some([u32::MAX; 4]),
                ..Default::default()
            },
            Stage::Bind,
            None,
            Some(DiagnosticAttachment {
                generation: super::super::SAFE_INTEGER,
                attachment: super::super::SAFE_INTEGER,
                target: super::super::SAFE_INTEGER,
                ..Default::default()
            }),
        );
        capture
            .counters
            .attempted
            .store(super::super::SAFE_INTEGER, Ordering::Relaxed);
        capture
            .counters
            .suppressed
            .store(super::super::SAFE_INTEGER, Ordering::Relaxed);
        for _ in 0..80 {
            probe.record(
                &capture,
                fact,
                Stage::Project,
                Some(Outcome::MissingRequest),
                None,
            );
        }
        let saved = rows(&file);
        assert_eq!(saved.len(), 64);
        assert!(saved.iter().skip(1).all(|row| row["overflow"] == true));
        assert_eq!(saved.last().unwrap()["probe"]["stage"], "limit");
        assert_eq!(probe.rows.load(Ordering::Relaxed), 64);
    }
    #[test]
    fn contested_sink_records_unknown_drop_instead_of_waiting_or_affecting_product() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let capture = super::super::cleanup_capture(Some(file.path())).unwrap();
        let probe = probe();
        let guard = capture.sink.lock().unwrap();
        probe.record(&capture, ProbeFact::default(), Stage::Ready, None, None);
        drop(guard);
        probe.record(&capture, ProbeFact::default(), Stage::Ready, None, None);
        let saved = rows(&file);
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0]["droppedBefore"], 1);
    }
}
