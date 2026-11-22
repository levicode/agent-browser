//! A semantic reader consumes Chromium's typed AX nodes. Decode its one
//! correlated reply directly so unused name-source trees never become a second
//! JSON DOM. Other consumers and all unusual/error envelopes keep the normal
//! CDP decoder and settlement. No browser object or action uses this route.
use super::types::{AXNode, CdpMessage, GetFullAXTreeResult};
use serde::Deserialize;
use serde_json::Value;
use std::{
    future::Future,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Option<GetFullAXTreeResult>>>);
tokio::task_local! {static CURRENT: Capture;}

impl Capture {
    pub(crate) async fn scope<F: Future>(&self, read: F) -> F::Output {
        CURRENT.scope(self.clone(), read).await
    }
    pub(super) fn for_command(method: &str) -> Option<Self> {
        (method == "Accessibility.getFullAXTree")
            .then(|| CURRENT.try_with(Clone::clone).ok())
            .flatten()
    }
    pub(crate) fn finish(self, value: Value) -> Result<GetFullAXTreeResult, serde_json::Error> {
        match self.0.lock().unwrap_or_else(|e| e.into_inner()).take() {
            Some(tree) => Ok(tree),
            None => serde_json::from_value(value),
        }
    }
    pub(super) fn decode(&self, message: &str, id: u64, session: &str) -> Option<CdpMessage> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Reply {
            id: u64,
            session_id: String,
            result: Rows,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Rows {
            nodes: Vec<AXNode>,
        }
        let reply: Reply = serde_json::from_str(message).ok()?;
        if reply.id != id || reply.session_id != session {
            return None;
        }
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return None;
        }
        *slot = Some(GetFullAXTreeResult {
            nodes: reply.result.nodes,
        });
        Some(CdpMessage {
            id: Some(id),
            session_id: Some(reply.session_id),
            result: Some(serde_json::json!({"nodes":[]})),
            error: None,
            method: None,
            params: None,
        })
    }
}

/// Only Chromium's ordinary leading id gets the optional fast decode.
/// The actual envelope is parsed and correlated again in full, including its
/// session and any unknown fields. This prefix is never settlement evidence.
pub(super) fn leading_id(message: &str) -> Option<u64> {
    let tail = message.strip_prefix("{\"id\":")?;
    let end = tail.bytes().take(21).position(|b| b == b',')?;
    let id = tail.get(..end)?.parse::<u64>().ok()?;
    (id > 0).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_requested_scoped_ordinary_ax_envelope_is_projected() {
        let capture = Capture::default();
        for bad in [
            r#"{"id":2,"sessionId":"s","result":{"nodes":[]}}"#,
            r#"{"id":1,"sessionId":"other","result":{"nodes":[]}}"#,
            r#"{"id":1,"sessionId":"s","result":{"nodes":[],"object":{"objectId":"x"}}}"#,
            r#"{"id":1,"sessionId":"s","error":{"code":-1,"message":"x"}}"#,
            r#"{"id":1,"sessionId":"s","result":{"nodes":[{"role":"invalid"}]}}"#,
        ] {
            assert!(capture.decode(bad, 1, "s").is_none());
        }
        let wire = r#"{"id":1,"result":{"nodes":[{"nodeId":"8","backendDOMNodeId":11,"role":{"type":"role","value":"button"},"name":{"type":"computedString","value":"name","sources":[{"type":"contents"}]}}]},"sessionId":"s"}"#;
        assert_eq!(leading_id(wire), Some(1));
        let envelope = capture.decode(wire, 1, "s").unwrap();
        let node = capture
            .finish(envelope.result.unwrap())
            .unwrap()
            .nodes
            .pop()
            .unwrap();
        assert_eq!(node.backend_d_o_m_node_id, Some(11));
        assert_eq!(node.name.unwrap().value.unwrap(), "name");
        assert!(leading_id(r#"{"method":"DOM.documentUpdated"}"#).is_none());
    }
}
