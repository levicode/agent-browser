//! Native request ownership and token dispatch. ECMAScript route matching and
//! callbacks stay in e2e; no JavaScript function or matcher is interpreted here.
use super::cdp::client::CdpClient;
use super::client_protocol::{Decision, DecisionNotice, ProtocolError, RequestOverrides};
use super::client_session::{ClientSession, DecisionKind, DecisionOutcome, DecisionOwner};
use super::client_transport::ClientEventSink;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub struct ClientNetwork {
    pub client: Arc<CdpClient>,
    broker: Arc<ClientSession>,
    sink: ClientEventSink,
    registry: Mutex<Option<u64>>,
}

impl ClientNetwork {
    pub fn new(client: Arc<CdpClient>, broker: Arc<ClientSession>, sink: ClientEventSink) -> Self {
        Self {
            client,
            broker,
            sink,
            registry: Mutex::new(None),
        }
    }

    /// Replacement affects future captures only. Broker retains retired
    /// snapshots until every paused request/fallback chain releases them.
    pub fn replace_routes(
        &self,
        version: u64,
        registrations: Vec<String>,
    ) -> Result<(), ProtocolError> {
        let mut current = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let (generation, _) = self.broker.health()?;
        self.broker
            .register_routes(generation, version, registrations)?;
        if let Some(old) = *current {
            self.broker.retire_registry(generation, old)?;
        }
        *current = Some(version);
        Ok(())
    }

    /// Caller verifies that session belongs to the owned context before calling
    /// this method. The event does not reveal native request/session handles.
    pub async fn paused_request(
        &self,
        session: &str,
        params: Value,
        owner: DecisionOwner,
        timeout_ms: u64,
    ) -> Result<(), ProtocolError> {
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?
            .to_owned();
        let source = params
            .get("request")
            .ok_or(ProtocolError::InvalidArguments)?;
        let url = source
            .get("url")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?;
        let method = source
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?;
        let headers = source
            .get("headers")
            .filter(|value| value.is_object())
            .ok_or(ProtocolError::InvalidArguments)?;
        let mut request = json!({"url": url, "method": method, "headers": headers});
        if let Some(body) = source.get("postData").and_then(Value::as_str) {
            request["postData"] = json!(body);
        }
        let (generation, _) = self.broker.health()?;
        let mut lease = {
            let current = self
                .registry
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            self.broker.decision(
                generation,
                owner,
                DecisionKind::Request,
                timeout_ms,
                *current,
            )?
        };
        let mut overrides = RequestOverrides::default();
        let mut fallback_of: Option<String> = None;
        loop {
            let remaining = lease
                .deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(u64::MAX as u128) as u64;
            if remaining == 0 {
                return self.abort_request(session, &request_id).await;
            }
            let token = lease.token.clone();
            let mut payload = json!({"version": lease.registry_version.unwrap_or(0),
                "registrationIds": lease.registrations.as_ref(), "request": request});
            if let Some(previous) = &fallback_of {
                payload["fallbackOf"] = json!(previous);
            }
            self.sink.emit(
                "network.request".into(),
                payload,
                Some(DecisionNotice {
                    token: token.clone(),
                    timeout_ms: remaining,
                }),
            )?;
            match lease
                .outcome
                .await
                .map_err(|_| ProtocolError::ScopeUnavailable)?
            {
                DecisionOutcome::Fallback {
                    overrides: next_overrides,
                    next,
                } => {
                    merge_overrides(&mut overrides, next_overrides);
                    update_request(&mut request, &overrides);
                    fallback_of = Some(token);
                    lease = *next;
                }
                DecisionOutcome::Selected(Decision::Continue {
                    overrides: final_overrides,
                }) => {
                    merge_overrides(&mut overrides, final_overrides);
                    let mut command = json!({"requestId": request_id});
                    if let Some(url) = overrides.url {
                        command["url"] = json!(url);
                    }
                    if let Some(method) = overrides.method {
                        command["method"] = json!(method);
                    }
                    if let Some(headers) = overrides.headers {
                        command["headers"] = json!(headers);
                    }
                    if let Some(body) = overrides.body_base64 {
                        command["postData"] = json!(body);
                    }
                    return self
                        .client
                        .send_command("Fetch.continueRequest", Some(command), Some(session))
                        .await
                        .map(|_| ())
                        .map_err(|_| ProtocolError::BrowserFailure);
                }
                DecisionOutcome::Selected(Decision::Fulfill {
                    status,
                    headers,
                    body_base64,
                }) => {
                    return self
                        .client
                        .send_command(
                            "Fetch.fulfillRequest",
                            Some(json!({"requestId": request_id,
                        "responseCode": status, "responseHeaders": headers, "body": body_base64})),
                            Some(session),
                        )
                        .await
                        .map(|_| ())
                        .map_err(|_| ProtocolError::BrowserFailure);
                }
                DecisionOutcome::Selected(Decision::Abort {})
                | DecisionOutcome::Expired
                | DecisionOutcome::Cancelled
                | DecisionOutcome::SessionClosed => {
                    return self.abort_request(session, &request_id).await
                }
                _ => return Err(ProtocolError::DecisionKindMismatch),
            }
        }
    }

    async fn abort_request(&self, session: &str, request_id: &str) -> Result<(), ProtocolError> {
        self.client
            .send_command(
                "Fetch.failRequest",
                Some(json!({"requestId": request_id, "errorReason": "Aborted"})),
                Some(session),
            )
            .await
            .map(|_| ())
            .map_err(|_| ProtocolError::BrowserFailure)
    }
}

fn merge_overrides(current: &mut RequestOverrides, next: RequestOverrides) {
    if next.url.is_some() {
        current.url = next.url;
    }
    if next.method.is_some() {
        current.method = next.method;
    }
    if next.headers.is_some() {
        current.headers = next.headers;
    }
    if next.body_base64.is_some() {
        current.body_base64 = next.body_base64;
    }
}
fn update_request(request: &mut Value, overrides: &RequestOverrides) {
    if let Some(url) = &overrides.url {
        request["url"] = json!(url);
    }
    if let Some(method) = &overrides.method {
        request["method"] = json!(method);
    }
    if let Some(headers) = &overrides.headers {
        let mut values = serde_json::Map::new();
        for header in headers {
            values.insert(header.name.clone(), json!(header.value));
        }
        request["headers"] = Value::Object(values);
    }
    if let Some(body) = &overrides.body_base64 {
        request["postDataBase64"] = json!(body);
        request
            .as_object_mut()
            .map(|object| object.remove("postData"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_overrides_accumulate_without_erasing_previous_fields() {
        let mut current = RequestOverrides {
            url: Some("https://example.test/changed".into()),
            ..Default::default()
        };
        merge_overrides(
            &mut current,
            RequestOverrides {
                method: Some("POST".into()),
                ..Default::default()
            },
        );
        assert_eq!(current.url.as_deref(), Some("https://example.test/changed"));
        assert_eq!(current.method.as_deref(), Some("POST"));
    }
}
