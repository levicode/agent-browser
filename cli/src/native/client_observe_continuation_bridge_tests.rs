//! Local joint wire control: actual native grant, real SDK parser and return request.
//! CDP is the existing deterministic fixture; this is not browser acceptance.
use super::*;
use crate::native::client_protocol::{ClientMessage, ProtocolError};
use crate::native::client_transport::{ClientExecutor, NativeOutcome};
use tokio::io::AsyncBufReadExt;

struct Bridge {
    state: Settled,
    wrong_owner: bool,
    calls: AtomicUsize,
    grants: AtomicUsize,
}
impl ClientExecutor for Bridge {
    fn capabilities(&self) -> Vec<String> {
        vec![
            "browser.observe/1".into(),
            "browser.observe-continuation/1".into(),
        ]
    }
    fn admission_deadline_cap_for_sequence(
        &self,
        generation: u64,
        sequence: u64,
        command: &str,
        args: &serde_json::Map<String, Value>,
    ) -> Result<Option<Instant>, ProtocolError> {
        assert_eq!(command, "browser.observe");
        self.state
            .dispatch
            .observe_deadline_cap(generation, sequence, args)
    }
    fn offer_observe_continuation(
        &self,
        proof: crate::native::client_session::ObservationSettlement,
    ) -> Option<ObserveContinuationDescriptor> {
        assert!(self.state.broker.observation_operation_settled(proof.key()));
        let grant = self.state.dispatch.offer_observe_continuation(proof);
        if grant.is_some() {
            self.grants.fetch_add(1, Ordering::SeqCst);
            if self.wrong_owner {
                self.state.targets.detach("target").unwrap();
            }
        }
        grant
    }
    fn fix_operation_result(&self, key: OperationKey) {
        self.state.retained.fix_operation_result(key);
    }
    async fn execute(
        &self,
        command: String,
        mut args: serde_json::Map<String, Value>,
        lease: OperationLease,
    ) -> NativeOutcome {
        assert_eq!(command, "browser.observe");
        assert_eq!(args.remove("identityScope"), Some(json!("scope")));
        assert!(self
            .state
            .broker
            .start(lease.generation, lease.sequence)
            .unwrap());
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request: ObserveRequest = serde_json::from_value(Value::Object(args)).unwrap();
        let journal = self
            .state
            .ledger
            .operation(
                OperationKey {
                    generation: lease.generation,
                    operation_seq: lease.sequence,
                },
                "target".into(),
                "session".into(),
            )
            .unwrap();
        journal.bind_operation(&lease).unwrap();
        let receipt = journal.clone();
        let cancel = lease.cancellation.clone();
        let dispatch = self.state.dispatch.clone();
        let context = self.state.context();
        let receive = self
            .state
            .retained
            .start_operation_prepared(
                "scope".into(),
                self.state.targets.clone(),
                self.state.broker.clone(),
                journal,
                cancel,
                move || {
                    let request = DispatchRequest::Observe(request);
                    let eligible = protected_read_receipt_eligible(&request);
                    let prepared = dispatch.prepare(context, request, lease)?;
                    Ok(async move {
                        let task = dispatch.start_prepared(prepared);
                        let output = task.result.await;
                        let cleanup = task.join.await;
                        assert!(matches!(cleanup, Ok(Ok(()))));
                        let (outcome, dirty) = settle_observation_dispatch(output, cleanup);
                        let (outcome, dirty) =
                            settle_trace_screenshot(outcome, dirty, false, &receipt);
                        settle_protected_read(outcome, dirty, eligible, &receipt)
                    })
                },
            )
            .await
            .unwrap();
        receive.await.unwrap()
    }
    async fn shutdown(&self) -> Result<(), ProtocolError> {
        self.state.retained.drain().await?;
        self.state.client.close().await;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "local joint SDK control requires private socket and separate Node harness"]
async fn continuation_joint_wire_bridge() {
    let socket = std::env::var("OBSERVE_BRIDGE_SOCKET").expect("private socket path");
    let wrong_owner = std::env::var("OBSERVE_BRIDGE_MODE").unwrap() == "wrong-owner";
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let Fixture {
        context,
        operation,
        journal,
        ledger,
        dispatch,
        samples,
        log,
        peer,
        readonly_replies,
        ..
    } = Fixture::new_mode(Race::AttachOtherContinuous, true).await;
    // Discard the fixture's unused standalone journal/lease. Every actual wire
    // request below obtains a fresh broker admission and fresh bound journal.
    drop(operation);
    drop(journal);
    let state = Settled {
        broker: Arc::new(ClientSession::new()),
        settlement: Mutex::new(None),
        dispatch,
        retained: RetainedTasks::default(),
        client: context.page.client.clone(),
        targets: context.page.targets.clone(),
        ledger,
        blobs: context.blobs.clone(),
        ui: context.ui.clone(),
        scope: context.scope.clone(),
        policy: context.policy.clone(),
        samples,
        log,
        peer,
        _readonly_replies: readonly_replies,
        deadline: Instant::now(),
    };
    drop(context);
    let bridge = Arc::new(Bridge {
        state,
        wrong_owner,
        calls: AtomicUsize::new(0),
        grants: AtomicUsize::new(0),
    });
    let (stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (read, write) = stream.into_split();
    let mut read = tokio::io::BufReader::new(read);
    let mut hello = String::new();
    read.read_line(&mut hello).await.unwrap();
    let hello: ClientMessage = serde_json::from_str(&hello).unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(30),
        crate::native::client_transport::serve_with_executor(
            read,
            write,
            hello,
            bridge.state.broker.clone(),
            bridge.clone()
        )
    )
    .await
    .unwrap());
    assert_eq!(bridge.grants.load(Ordering::SeqCst), 1);
    assert_eq!(
        bridge.calls.load(Ordering::SeqCst),
        if wrong_owner { 1 } else { 2 }
    );
    assert_eq!(
        bridge.state.samples.load(Ordering::SeqCst),
        if wrong_owner { 2 } else { 4 }
    );
    no_protected_read(&bridge.state.log.lock().unwrap());
    assert!(bridge
        .state
        .dispatch
        .refs
        .lock()
        .unwrap()
        .ref_ids()
        .is_empty());
    let bridge = Arc::try_unwrap(bridge).ok().unwrap();
    bridge.state.peer.await.unwrap();
    std::fs::remove_file(socket).unwrap();
    println!(
        "JOINT_NATIVE_BRIDGE mode={} grants=1 calls={} samples={} protected_reads=0 refs=0",
        if wrong_owner {
            "wrong-owner"
        } else {
            "continuous"
        },
        if wrong_owner { 1 } else { 2 },
        if wrong_owner { 2 } else { 4 }
    );
}
