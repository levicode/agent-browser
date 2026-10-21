//! Bounded negotiated transport. Browser dispatch is deliberately unavailable
//! until the owned-scope executor implements and advertises its contracts.
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::client_protocol::*;
use super::client_session::{ClientSession, OperationLease};

/// Browser mechanics stay native. The reader only admits work and forwards
/// control; executors never own its lock or the output transport.
pub struct NativeOutcome {
    pub result: Result<serde_json::Value, ProtocolError>,
    pub effects: Effects,
}

pub trait ClientExecutor: Send + Sync + 'static {
    fn capabilities(&self) -> Vec<String>;
    fn set_event_sink(&self, _sink: ClientEventSink) -> Result<(), ProtocolError> {
        Ok(())
    }
    fn execute(
        &self,
        command: String,
        args: serde_json::Map<String, serde_json::Value>,
        lease: OperationLease,
    ) -> impl std::future::Future<Output = NativeOutcome> + Send;
    /// Success proves resource teardown, not merely a cancellation request.
    fn shutdown(&self) -> impl std::future::Future<Output = Result<(), ProtocolError>> + Send;
}

/// Reliable bounded event lane. Engine handles and callback policy stay out
/// of this type; overflow revokes the scope rather than losing a control event.
#[derive(Clone)]
pub struct ClientEventSink {
    sender: mpsc::Sender<ServerMessage>,
    broker: std::sync::Arc<ClientSession>,
    sequence: std::sync::Arc<std::sync::Mutex<u64>>,
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl ClientEventSink {
    pub fn emit(
        &self,
        event: String,
        payload: serde_json::Value,
        decision: Option<DecisionNotice>,
    ) -> Result<(), ProtocolError> {
        use std::sync::atomic::Ordering;
        if !self.open.load(Ordering::Acquire) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let (generation, health) = self.broker.health()?;
        if health != ScopeState::Usable {
            return Err(ProtocolError::ScopeUnavailable);
        }
        // Allocate and enqueue under one short lock so concurrent native
        // event producers cannot publish sequence n+1 before sequence n.
        let mut counter = self
            .sequence
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !self.open.load(Ordering::Acquire) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if *counter >= MAX_SAFE_SEQUENCE {
            let _ = self.broker.quarantine();
            return Err(ProtocolError::IdentifierExhausted);
        }
        *counter += 1;
        let sequence = *counter;
        let message = ServerMessage::Event {
            generation,
            sequence,
            event,
            payload,
            decision,
        };
        if serde_json::to_vec(&message)
            .map_err(|_| ProtocolError::InvalidFrame)?
            .len()
            > MAX_FRAME_BYTES
        {
            let _ = self.broker.quarantine();
            return Err(ProtocolError::CapacityExceeded);
        }
        self.sender.try_send(message).map_err(|_| {
            let _ = self.broker.quarantine();
            ProtocolError::CapacityExceeded
        })
    }
}

/// Bound allocation while reading, including an unterminated hostile frame.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut frame = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| ProtocolError::InvalidFrame)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(ProtocolError::InvalidFrame)
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let length = newline.unwrap_or(available.len());
        if frame.len() + length > MAX_FRAME_BYTES {
            return Err(ProtocolError::InvalidFrame);
        }
        frame.extend_from_slice(&available[..length]);
        reader.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

struct Outgoing {
    control: mpsc::Sender<ServerMessage>,
    results: mpsc::Sender<ServerMessage>,
}

fn enqueue(sender: &Outgoing, message: ServerMessage, broker: &ClientSession) -> bool {
    let lane = if matches!(
        &message,
        ServerMessage::Result { .. } | ServerMessage::Closed { .. }
    ) {
        &sender.results
    } else {
        &sender.control
    };
    if lane.try_send(message).is_err() {
        let _ = broker.quarantine();
        return false;
    }
    true
}

pub async fn refuse<W: AsyncWrite + Unpin>(
    writer: &mut W,
    id: Option<String>,
    code: ProtocolError,
) {
    let message = ServerMessage::Error {
        id,
        error: WireError { code },
        scope_state: ScopeState::Closed,
    };
    if let Ok(mut bytes) = serde_json::to_vec(&message) {
        bytes.push(b'\n');
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            writer.write_all(&bytes).await?;
            writer.flush().await
        })
        .await;
    }
}

pub async fn serve<R, W>(reader: R, writer: W, hello: ClientMessage) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let broker = std::sync::Arc::new(ClientSession::new());
    let executor = std::sync::Arc::new(super::client_browser::ClientBrowser::new(broker.clone()));
    serve_with_executor(reader, writer, hello, broker, executor).await
}

/// Reader/control work never takes the executor's browser lock. False means
/// cleanup is unproven and the daemon MUST retain its exclusive ownership gate.
pub async fn serve_with_executor<R, W, E>(
    mut reader: R,
    mut writer: W,
    hello: ClientMessage,
    broker: std::sync::Arc<ClientSession>,
    executor: std::sync::Arc<E>,
) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    E: ClientExecutor,
{
    let outstanding = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        bool,
    >::new()));
    let (control, mut controls) = mpsc::channel::<ServerMessage>(64);
    let (results, mut results_rx) = mpsc::channel::<ServerMessage>(64);
    let sender = Outgoing { control, results };
    let sink_open = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let event_order = std::sync::Arc::new(std::sync::Mutex::new(0));
    let sink = ClientEventSink {
        sender: sender.control.clone(),
        broker: broker.clone(),
        sequence: event_order.clone(),
        open: sink_open.clone(),
    };
    let (drain, mut drain_requested) = tokio::sync::oneshot::channel::<()>();
    let (failed, mut failure) = tokio::sync::oneshot::channel::<()>();
    let writing_ids = outstanding.clone();
    let writer_task = tokio::spawn(async move {
        let mut control_open = true;
        let mut results_open = true;
        let mut draining = false;
        while control_open || results_open {
            let message = tokio::select! {
                biased;
                _ = &mut drain_requested, if !draining => { draining = true; controls.close(); results_rx.close(); continue; },
                next = controls.recv(), if control_open => match next {
                    Some(message) => message, None => { control_open = false; continue; }
                },
                next = results_rx.recv(), if results_open => match next {
                    Some(message) => message, None => { results_open = false; continue; }
                },
            };
            let Ok(mut bytes) = serde_json::to_vec(&message) else {
                break;
            };
            if bytes.len() > MAX_FRAME_BYTES {
                break;
            }
            bytes.push(b'\n');
            if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
                break;
            }
            let id = match &message {
                ServerMessage::Ready { id, .. }
                | ServerMessage::Result { id, .. }
                | ServerMessage::ControlResult { id, .. }
                | ServerMessage::Closed { id, .. } => Some(id),
                ServerMessage::Error { id, .. } => id.as_ref(),
                ServerMessage::Event { .. } => None,
            };
            if let Some(id) = id {
                if let Ok(mut ids) = writing_ids.lock() {
                    ids.remove(id);
                }
            }
        }
        let _ = writer.shutdown().await;
        let _ = failed.send(());
    });
    let ClientMessage::Hello {
        id,
        protocol,
        required_capabilities,
    } = hello
    else {
        writer_task.abort();
        return false;
    };
    if let Ok(mut ids) = outstanding.lock() {
        ids.insert(id.clone(), false);
    }
    let capabilities = executor.capabilities();
    let supported: Vec<_> = capabilities.iter().map(String::as_str).collect();
    let validation = validate_hello(&protocol, &required_capabilities, &supported)
        .and_then(|()| executor.set_event_sink(sink.clone()));
    let valid = validation.is_ok();
    let ready = match validation {
        Ok(()) => ServerMessage::Ready {
            id,
            protocol: PROTOCOL.into(),
            session_id: broker.id.clone(),
            generation: 1,
            capabilities,
            limits: Limits {
                max_frame_bytes: MAX_FRAME_BYTES,
                max_pending_operations: 64,
                max_pending_decisions: 256,
                max_timeout_ms: MAX_TIMEOUT_MS,
            },
            scope_state: ScopeState::Usable,
        },
        Err(code) => ServerMessage::Error {
            id: Some(id),
            error: WireError { code },
            scope_state: ScopeState::Closed,
        },
    };
    let ready_queued = enqueue(&sender, ready, &broker);
    if valid && ready_queued {
        sink_open.store(true, std::sync::atomic::Ordering::Release);
    }
    let mut operations = tokio::task::JoinSet::<(u64, NativeOutcome)>::new();
    let mut pending = std::collections::HashMap::<u64, (String, u64)>::new();
    let mut closing_id = None;
    let mut timer = tokio::time::interval(std::time::Duration::from_millis(25));
    if valid && ready_queued {
        loop {
            let frame = tokio::select! {
                frame = read_frame(&mut reader) => frame,
                _ = &mut failure => break,
                _ = timer.tick() => {
                    let _ = broker.expire_decisions();
                    if !broker.health().is_ok_and(|(_, state)| state == ScopeState::Usable) { break; }
                    for version in broker.take_released_registries(16).unwrap_or_default() {
                        if sink.emit("registry-released".into(), serde_json::json!({ "registryVersion": version }), None).is_err() { break; }
                    }
                    if !broker.health().is_ok_and(|(_, state)| state == ScopeState::Usable) { break; }
                    continue;
                },
                completion = operations.join_next(), if !operations.is_empty() => {
                    let Some(Ok((sequence, outcome))) = completion else { break; };
                    let Some((id, generation)) = pending.remove(&sequence) else { break; };
                    let state = broker.settle(generation, sequence, outcome.effects).unwrap_or(ScopeState::Quarantined);
                    let unknown = outcome.effects == Effects::Unknown;
                    if !enqueue(&sender, result_message(id, generation, sequence, outcome, state), &broker) || unknown { break; }
                    continue;
                },
            };
            let message = match frame {
                Ok(Some(bytes)) => parse_frame(&bytes),
                Ok(None) => break,
                Err(error) => Err(error),
            };
            let message = match message {
                Ok(message) => message,
                Err(code) => {
                    let _ = broker.quarantine();
                    enqueue(
                        &sender,
                        ServerMessage::Error {
                            id: None,
                            error: WireError { code },
                            scope_state: ScopeState::Quarantined,
                        },
                        &broker,
                    );
                    break;
                }
            };
            let id = match &message {
                ClientMessage::Hello { id, .. }
                | ClientMessage::Request { id, .. }
                | ClientMessage::Cancel { id, .. }
                | ClientMessage::Decision { id, .. }
                | ClientMessage::Close { id, .. } => id,
            };
            let is_operation = matches!(&message, ClientMessage::Request { .. });
            let admitted = outstanding
                .lock()
                .map(|mut ids| {
                    if ids.contains_key(id)
                        || ids.values().filter(|kind| **kind == is_operation).count() >= 64
                    {
                        return false;
                    }
                    ids.insert(id.clone(), is_operation);
                    true
                })
                .unwrap_or(false);
            if !admitted {
                let _ = broker.quarantine();
                enqueue(
                    &sender,
                    ServerMessage::Error {
                        id: None,
                        error: WireError {
                            code: ProtocolError::InvalidFrame,
                        },
                        scope_state: ScopeState::Quarantined,
                    },
                    &broker,
                );
                break;
            }
            match message {
                ClientMessage::Request {
                    id,
                    generation,
                    operation_seq,
                    timeout_ms,
                    callback_token,
                    command,
                    args,
                } => {
                    match broker.admit_callback(
                        generation,
                        operation_seq,
                        timeout_ms,
                        callback_token.as_deref(),
                    ) {
                        Ok(lease) => {
                            pending.insert(operation_seq, (id, generation));
                            let executor = executor.clone();
                            let broker = broker.clone();
                            operations.spawn(async move {
                                (
                                    operation_seq,
                                    execute_bounded(executor, broker, command, args, lease).await,
                                )
                            });
                        }
                        Err(code) => {
                            let state = broker
                                .health()
                                .map(|(_, state)| state)
                                .unwrap_or(ScopeState::Quarantined);
                            if !enqueue(
                                &sender,
                                result_message(
                                    id,
                                    generation,
                                    operation_seq,
                                    NativeOutcome {
                                        result: Err(code),
                                        effects: Effects::NotDispatched,
                                    },
                                    state,
                                ),
                                &broker,
                            ) {
                                break;
                            }
                        }
                    }
                }
                ClientMessage::Close { id, generation }
                    if broker
                        .health()
                        .is_ok_and(|(current, _)| current == generation) =>
                {
                    closing_id = Some(id);
                    break;
                }
                other => {
                    let (response, close) = respond(&broker, other);
                    if !enqueue(&sender, response, &broker) || close {
                        break;
                    }
                }
            }
        }
    }
    // Seal before cancelling native work. EOF never proves resource teardown.
    {
        let _order = event_order.lock().ok();
        sink_open.store(false, std::sync::atomic::Ordering::Release);
    }
    let _ = broker.quarantine();
    operations.abort_all();
    // Aborting schedules cancellation; joining proves execution guards dropped.
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while operations.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    let teardown_proven = if drained {
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), executor.shutdown()).await,
            Ok(Ok(()))
        )
    } else {
        false
    };
    for (sequence, (id, generation)) in pending {
        let effects = if broker.has_started(sequence) {
            Effects::Unknown
        } else {
            Effects::NotDispatched
        };
        let _ = broker.settle(generation, sequence, effects);
        enqueue(
            &sender,
            result_message(
                id,
                generation,
                sequence,
                NativeOutcome {
                    result: Err(ProtocolError::Cancelled),
                    effects,
                },
                ScopeState::Quarantined,
            ),
            &broker,
        );
    }
    if teardown_proven {
        let _ = broker.mark_closed();
        if let Some(id) = closing_id {
            enqueue(
                &sender,
                ServerMessage::Closed {
                    id,
                    generation: broker
                        .health()
                        .map(|(generation, _)| generation)
                        .unwrap_or(1),
                    scope_state: ScopeState::Closed,
                },
                &broker,
            );
        }
    } else {
        enqueue(
            &sender,
            ServerMessage::Error {
                id: closing_id,
                error: WireError {
                    code: ProtocolError::CleanupFailed,
                },
                scope_state: ScopeState::Quarantined,
            },
            &broker,
        );
    }
    drop(sender);
    let _ = drain.send(());
    let mut writer_task = writer_task;
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }
    teardown_proven
}

fn result_message(
    id: String,
    generation: u64,
    operation_seq: u64,
    outcome: NativeOutcome,
    scope_state: ScopeState,
) -> ServerMessage {
    let (ok, data, error) = match outcome.result {
        Ok(data) => (true, Some(data), None),
        Err(code) => (false, None, Some(WireError { code })),
    };
    ServerMessage::Result {
        id,
        generation,
        operation_seq,
        ok,
        data,
        error,
        effects: outcome.effects,
        scope_state,
    }
}

async fn execute_bounded<E: ClientExecutor>(
    executor: std::sync::Arc<E>,
    broker: std::sync::Arc<ClientSession>,
    command: String,
    args: serde_json::Map<String, serde_json::Value>,
    lease: OperationLease,
) -> NativeOutcome {
    let sequence = lease.sequence;
    let generation = lease.generation;
    let deadline = tokio::time::Instant::from_std(lease.deadline);
    let mut cancellation = lease.cancellation.clone();
    let execution = executor.execute(command, args, lease);
    tokio::pin!(execution);
    let reason = tokio::select! {
        biased;
        outcome = &mut execution => return outcome,
        _ = cancellation.changed() => ProtocolError::Cancelled,
        _ = tokio::time::sleep_until(deadline) => ProtocolError::DeadlineExceeded,
    };
    let _ = broker.cancel(generation, sequence);
    if let Ok(outcome) =
        tokio::time::timeout(std::time::Duration::from_millis(250), &mut execution).await
    {
        return outcome;
    }
    NativeOutcome {
        result: Err(reason),
        effects: if broker.has_started(sequence) {
            Effects::Unknown
        } else {
            Effects::NotDispatched
        },
    }
}

fn respond(broker: &ClientSession, message: ClientMessage) -> (ServerMessage, bool) {
    let (generation, scope_state) = broker.health().unwrap_or((1, ScopeState::Quarantined));
    match message {
        ClientMessage::Request {
            id,
            generation: requested_generation,
            operation_seq,
            timeout_ms,
            callback_token,
            ..
        } => {
            let error = match broker.admit_callback(
                requested_generation,
                operation_seq,
                timeout_ms,
                callback_token.as_deref(),
            ) {
                Ok(_) => {
                    let _ =
                        broker.settle(requested_generation, operation_seq, Effects::NotDispatched);
                    ProtocolError::UnsupportedCommand
                }
                Err(error) => error,
            };
            (
                ServerMessage::Result {
                    id,
                    generation,
                    operation_seq,
                    ok: false,
                    data: None,
                    error: Some(WireError { code: error }),
                    effects: Effects::NotDispatched,
                    scope_state,
                },
                false,
            )
        }
        ClientMessage::Cancel {
            id,
            generation: requested_generation,
            operation_seq,
        } => {
            let result = broker.cancel(requested_generation, operation_seq);
            (
                ServerMessage::ControlResult {
                    id,
                    generation,
                    accepted: result.is_ok(),
                    error: result.err().map(|code| WireError { code }),
                    scope_state,
                },
                false,
            )
        }
        ClientMessage::Decision {
            id,
            generation: requested_generation,
            token,
            decision,
        } => {
            let result = broker.resolve(requested_generation, &token, decision);
            (
                ServerMessage::ControlResult {
                    id,
                    generation,
                    accepted: result.is_ok(),
                    error: result.err().map(|code| WireError { code }),
                    scope_state,
                },
                false,
            )
        }
        ClientMessage::Close {
            id,
            generation: requested_generation,
        } if requested_generation == generation => {
            let _ = broker.mark_closed();
            (
                ServerMessage::Closed {
                    id,
                    generation,
                    scope_state: ScopeState::Closed,
                },
                true,
            )
        }
        ClientMessage::Close { id, .. } => (
            ServerMessage::Error {
                id: Some(id),
                error: WireError {
                    code: ProtocolError::StaleGeneration,
                },
                scope_state,
            },
            false,
        ),
        ClientMessage::Hello { id, .. } => (
            ServerMessage::Error {
                id: Some(id),
                error: WireError {
                    code: ProtocolError::InvalidFrame,
                },
                scope_state,
            },
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct StalledExecutor {
        broker: std::sync::Arc<ClientSession>,
        cleanup_succeeds: bool,
    }
    impl ClientExecutor for StalledExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            self.broker.start(lease.generation, lease.sequence).unwrap();
            std::future::pending().await
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            if self.cleanup_succeeds {
                Ok(())
            } else {
                Err(ProtocolError::CleanupFailed)
            }
        }
    }

    #[test]
    fn event_sequence_is_publication_order_and_overflow_quarantines() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (sender, mut receiver) = mpsc::channel(64);
        let sink = ClientEventSink {
            sender,
            broker: broker.clone(),
            sequence: std::sync::Arc::new(std::sync::Mutex::new(0)),
            open: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let sink = sink.clone();
                std::thread::spawn(move || {
                    sink.emit("test".into(), serde_json::json!({}), None)
                        .unwrap()
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        for expected in 1..=16 {
            assert!(
                matches!(receiver.try_recv().unwrap(), ServerMessage::Event { sequence, .. } if sequence == expected)
            );
        }
        for _ in 0..64 {
            sink.emit("test".into(), serde_json::json!({}), None)
                .unwrap();
        }
        assert_eq!(
            sink.emit("test".into(), serde_json::json!({}), None),
            Err(ProtocolError::CapacityExceeded)
        );
        assert_eq!(broker.health().unwrap().1, ScopeState::Quarantined);
    }

    #[tokio::test]
    async fn stalled_executor_keeps_control_live_and_unknown_never_usable() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(StalledExecutor {
            broker: broker.clone(),
            cleanup_succeeds: true,
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let hello = ClientMessage::Hello {
            id: "h".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: vec![],
        };
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            hello,
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap();
        client.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":1000,\"command\":\"test\",\"args\":{}}\n").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        client
            .get_mut()
            .write_all(b"{\"type\":\"cancel\",\"id\":\"c\",\"generation\":1,\"operationSeq\":1}\n")
            .await
            .unwrap();
        let frame = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_frame(&mut client),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let control: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(control["type"], "control-result");
        assert_eq!(control["accepted"], true);
        let frame =
            tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut client))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        let terminal: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(terminal["effects"], "unknown");
        assert_eq!(terminal["scopeState"], "quarantined");
        assert!(task.await.unwrap());
    }

    #[tokio::test]
    async fn failed_cleanup_never_emits_closed_or_releases_ownership_proof() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(StalledExecutor {
            broker: broker.clone(),
            cleanup_succeeds: false,
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap();
        client
            .get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        let frame = read_frame(&mut client).await.unwrap().unwrap();
        let terminal: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(terminal["type"], "error");
        assert_eq!(terminal["error"]["code"], "cleanup-failed");
        assert_eq!(terminal["scopeState"], "quarantined");
        assert!(!task.await.unwrap());
    }

    #[tokio::test]
    async fn rejects_unterminated_oversize_and_invalid_utf8() {
        let bytes = vec![b'a'; MAX_FRAME_BYTES + 1];
        assert!(read_frame(&mut &bytes[..]).await.is_err());
        assert!(parse_frame(&[0xff]).is_err());
        assert!(read_frame(&mut &b"partial"[..]).await.is_err());
    }
    #[test]
    fn unavailable_browser_commands_never_claim_execution() {
        let broker = ClientSession::new();
        let message = ClientMessage::Request {
            id: "r".into(),
            generation: 1,
            operation_seq: 1,
            timeout_ms: 1000,
            command: "click".into(),
            callback_token: None,
            args: Default::default(),
        };
        let (reply, _) = respond(&broker, message);
        assert!(matches!(
            reply,
            ServerMessage::Result {
                effects: Effects::NotDispatched,
                ok: false,
                ..
            }
        ));
    }
}
