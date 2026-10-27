//! Framed admission proof: exact retained metadata shortens the real new lease;
//! mismatches never dispatch, while ordinary commands retain normal admission.
use super::*;
use std::sync::Arc;

struct CappedExecutor {
    deadline: std::time::Instant,
    seen: std::sync::Mutex<Vec<(u64, std::time::Instant)>>,
}
impl ClientExecutor for CappedExecutor {
    fn capabilities(&self) -> Vec<String> {
        vec![]
    }
    fn admission_deadline_cap(
        &self,
        generation: u64,
        command: &str,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<std::time::Instant>, ProtocolError> {
        if command != "test.adopt" {
            return Ok(None);
        }
        if generation != 1
            || args
                .get("preparationId")
                .and_then(serde_json::Value::as_str)
                != Some("exact")
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(Some(self.deadline))
    }
    async fn execute(
        &self,
        _: String,
        _: serde_json::Map<String, serde_json::Value>,
        lease: OperationLease,
    ) -> NativeOutcome {
        self.seen
            .lock()
            .unwrap()
            .push((lease.sequence, lease.deadline));
        NativeOutcome {
            result: Ok(serde_json::json!({})),
            effects: Effects::Completed,
            retention: None,
        }
    }
    async fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[tokio::test]
async fn preparation_cap_is_applied_before_real_framed_admission() {
    use tokio::io::AsyncWriteExt;
    let broker = Arc::new(ClientSession::new());
    let executor = Arc::new(CappedExecutor {
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        seen: Default::default(),
    });
    let (peer, server) = tokio::io::duplex(8192);
    let (reader, writer) = tokio::io::split(server);
    let serving = tokio::spawn(serve_with_executor(
        tokio::io::BufReader::new(reader),
        writer,
        ClientMessage::Hello {
            id: "hello".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: vec![],
        },
        broker,
        executor.clone(),
    ));
    let mut peer = tokio::io::BufReader::new(peer);
    async fn frame(peer: &mut tokio::io::BufReader<tokio::io::DuplexStream>) -> serde_json::Value {
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(peer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    assert_eq!(frame(&mut peer).await["type"], "ready");
    for (seq, command, ticket, expected_error) in [
        (1, "test.adopt", "wrong", Some("stale-scope")),
        (1, "test.adopt", "exact", Some("sequence-reused")),
        (2, "test.adopt", "exact", None),
        (3, "ordinary", "wrong", None),
    ] {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "type":"request", "id": format!("{seq}-{ticket}"), "generation":1,
            "operationSeq":seq, "timeoutMs":60000, "command":command,
            "args":{"preparationId":ticket},
        }))
        .unwrap();
        bytes.push(b'\n');
        peer.get_mut().write_all(&bytes).await.unwrap();
        let response = frame(&mut peer).await;
        assert_eq!(response["type"], "result");
        if let Some(error) = expected_error {
            assert_eq!(response["error"]["code"], error);
        } else {
            assert_eq!(response["ok"], true);
        }
    }
    let seen = executor.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], (2, executor.deadline));
    assert_eq!(seen[1].0, 3);
    assert!(seen[1].1 > executor.deadline);
    peer.get_mut()
        .write_all(b"{\"type\":\"close\",\"id\":\"close\",\"generation\":1}\n")
        .await
        .unwrap();
    assert_eq!(frame(&mut peer).await["type"], "closed");
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap()
    );
}
