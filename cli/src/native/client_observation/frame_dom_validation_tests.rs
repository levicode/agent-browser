//! Exact managed-CDP command scripts for adjacent fresh frame-tree coalescing.
//! These controls exercise production command/lease/cleanup paths, not a second
//! implementation of the frame traversal or DOM acquisition algorithm.
use super::*;
use crate::native::client_debt::{AdmissionClass, OperationKey, OwnerDebtLedger};
use futures_util::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy)]
enum Read {
    Validated,
    Legacy,
    Fields,
}
struct Step {
    method: &'static str,
    params: Option<Value>,
    result: Value,
    stop: Option<CancelSignal>,
    error: Option<Value>,
    reply_session: Option<&'static str>,
}
fn step(method: &'static str, params: Value, result: Value) -> Step {
    Step {
        method,
        params: Some(params),
        result,
        stop: None,
        error: None,
        reply_session: None,
    }
}
fn frame(child: bool) -> ObservationFrame {
    ObservationFrame {
        parent_frame_id: child.then(|| "main".into()),
        owner_backend_id: child.then_some(7),
        url: "https://fixture.invalid/document".into(),
        binding: ExactBinding {
            page_session: "renderer".into(),
            session: "renderer".into(),
            frame: if child { "child" } else { "main" }.into(),
            loader: "doc".into(),
            actionable: false,
        },
        offset_x: 0.0,
        offset_y: 0.0,
        frame_path: vec![],
    }
}
fn tree(child: bool, loader: &str) -> Value {
    if child {
        json!({"frameTree":{"frame":{"id":"main","loaderId":"parent-doc"},"childFrames":[{"frame":{"id":"child","loaderId":loader}}]}})
    } else {
        json!({"frameTree":{"frame":{"id":"main","loaderId":loader}}})
    }
}
fn dom(backend: i64) -> Value {
    json!({"root":{"nodeType":9,"backendNodeId":backend,"children":[]}})
}
fn inventory(child: bool, backend: i64) -> Vec<Step> {
    let mut steps = vec![step("Page.getFrameTree", json!({}), tree(child, "doc"))];
    if child {
        steps.extend([
            step(
                "DOM.getFrameOwner",
                json!({"frameId":"child"}),
                json!({"backendNodeId":7}),
            ),
            step(
                "DOM.describeNode",
                json!({"backendNodeId":7,"depth":1,"pierce":true}),
                json!({"node":{"contentDocument":{"backendNodeId":backend}}}),
            ),
            step(
                "DOM.describeNode",
                json!({"backendNodeId":backend,"depth":-1,"pierce":true}),
                json!({"node":dom(backend)["root"]}),
            ),
        ]);
    } else {
        steps.extend([
            step(
                "DOM.getDocument",
                json!({"depth":0,"pierce":true}),
                json!({"root":{"nodeType":9,"backendNodeId":backend}}),
            ),
            step(
                "DOM.describeNode",
                json!({"backendNodeId":backend,"depth":-1,"pierce":true}),
                json!({"node":dom(backend)["root"]}),
            ),
        ]);
    }
    steps
}
fn fields_prefix(child: bool) -> Vec<Step> {
    let mut steps = inventory(child, 99);
    steps.push(step(
        "Page.createIsolatedWorld",
        json!({"frameId":if child { "child" } else { "main" },"worldName":"agent-browser-native-observation"}),
        json!({"executionContextId":1}),
    ));
    steps.extend([
        Step {
            method: "DOM.resolveNode",
            params: None,
            stop: None,
            error: None,
            reply_session: None,
            result: json!({"object":{"objectId":"root-object","subtype":"node"}}),
        },
        Step {
            method: "Runtime.callFunctionOn",
            params: None,
            stop: None,
            error: None,
            reply_session: None,
            result: json!({"result":{"value":{"values":[]}}}),
        },
        Step {
            method: "Runtime.releaseObjectGroup",
            params: None,
            stop: None,
            error: None,
            reply_session: None,
            result: json!({}),
        },
    ]);
    steps
}

async fn run_case(
    read: Read,
    selected: ObservationFrame,
    steps: Vec<Step>,
) -> (Result<Value, ObservationError>, Vec<Value>) {
    run_case_with_integrity(read, selected, steps, false).await
}
async fn run_case_with_integrity(
    read: Read,
    selected: ObservationFrame,
    steps: Vec<Step>,
    expect_integrity_loss: bool,
) -> (Result<Value, ObservationError>, Vec<Value>) {
    let expected_count = steps.len();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (cancellation, receiver) = tokio::sync::watch::channel(CancelSignal::None);
    let peer_cancellation = cancellation.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut steps: VecDeque<_> = steps.into();
        let mut pending_cleanup = None;
        let mut requests = Vec::new();
        while let Some(message) = socket.next().await {
            let text = match message.unwrap() {
                Message::Text(text) => text,
                Message::Close(_) => break,
                Message::Ping(payload) => {
                    socket.send(Message::Pong(payload)).await.unwrap();
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Binary(_) | Message::Frame(_) => panic!("unexpected CDP frame"),
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            // Managed readonly cleanup transfers custody without waiting for
            // its ACK. Keep exact application order/counts, but do not invent
            // wire ordering between this one release and the final inventory.
            if steps
                .front()
                .is_some_and(|step| step.method == "Runtime.releaseObjectGroup")
            {
                assert!(pending_cleanup.is_none());
                pending_cleanup = steps.pop_front();
            }
            let expected = if request["method"] == "Runtime.releaseObjectGroup" {
                pending_cleanup.take().expect("unexpected cleanup command")
            } else {
                steps.pop_front().expect("unexpected extra CDP command")
            };
            assert_eq!(request["sessionId"], "renderer");
            assert_eq!(request["method"], expected.method);
            if let Some(params) = expected.params {
                assert_eq!(request["params"], params);
            }
            if let Some(stop) = expected.stop {
                peer_cancellation.send_replace(stop);
            }
            let session = expected.reply_session.unwrap_or("renderer");
            let response = match expected.error {
                Some(error) => json!({"id":request["id"],"sessionId":session,"error":error}),
                None => json!({"id":request["id"],"sessionId":session,"result":expected.result}),
            };
            socket
                .send(Message::Text(response.to_string()))
                .await
                .unwrap();
            requests.push(request);
        }
        assert!(
            steps.is_empty(),
            "production skipped an expected CDP command"
        );
        assert!(
            pending_cleanup.is_none(),
            "production skipped exact cleanup"
        );
        requests
    });
    let transport = tokio::time::timeout(Duration::from_secs(1), CdpClient::connect(&endpoint))
        .await
        .expect("mock CDP connection timed out")
        .unwrap();
    let ledger = OwnerDebtLedger::new(1, "frame-dom-owner".into());
    transport.install_debt_ledger(ledger.clone()).unwrap();
    let client = transport.owner_view(ledger.clone()).unwrap();
    let lease = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline: std::time::Instant::now() + Duration::from_secs(5),
        cancellation: receiver,
    };
    let journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            "target".into(),
            "renderer".into(),
        )
        .unwrap();
    journal.bind_operation(&lease).unwrap();
    ledger.check_admission(AdmissionClass::Reference).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        journal.scope(async {
            match read {
                Read::Validated => validated_frame_dom(&client, &selected, &lease).await,
                Read::Legacy => frame_dom(&client, &selected, &lease).await,
                Read::Fields => {
                    let expression: LocatorExpression = serde_json::from_value(json!({"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"city","exact":true}}})).unwrap();
                    fresh_query::fields(
                        &client,
                        &selected,
                        &expression,
                        &QueryOptions {
                            expression: expression.clone(),
                            test_id_attribute: default_test_id(),
                            secure_field_selector: default_secure_selector(),
                        },
                        &[ReadField::Value],
                        &lease,
                        &query_diagnostic::QueryReadWitness::disabled(&lease),
                    )
                    .await
                    .map(|rows| serde_json::to_value(rows).unwrap())
                }
            }
        }),
    )
    .await
    .expect("bounded field/frame read did not finish");
    if expect_integrity_loss {
        // A foreign-session ACK is not settlement. Observe exact retained debt;
        // do not route this adversarial case through the clean-debt success wait.
        let snapshot = ledger.snapshot();
        assert!(snapshot.integrity_lost, "foreign ACK must poison authority");
        assert_eq!(
            snapshot.outstanding_commands, 1,
            "foreign ACK must not settle the read"
        );
        assert_eq!(
            snapshot.object_debt, 0,
            "inventory cannot create object handles"
        );
        assert_eq!(snapshot.input_debt, 0);
        for class in [AdmissionClass::Reference, AdmissionClass::FixedRead] {
            assert_eq!(
                ledger.check_admission(class),
                Err(crate::native::client_protocol::ProtocolError::ScopeUnavailable)
            );
        }
    } else {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = ledger.snapshot();
                assert!(
                    !snapshot.integrity_lost,
                    "cleanup accounting lost integrity"
                );
                if snapshot.outstanding_commands == 0 && snapshot.object_debt == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accounted release did not settle exact command and object debt");
        assert_eq!(ledger.snapshot().object_debt, 0);
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(!ledger.snapshot().integrity_lost);
    }
    assert!(!journal.snapshot().mutation_dispatched);
    tokio::time::timeout(Duration::from_secs(1), transport.close())
        .await
        .expect("mock transport close timed out");
    let requests = tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("mock CDP peer did not stop")
        .expect("mock CDP peer failed its exact command assertions");
    assert_eq!(requests.len(), expected_count);
    if matches!(read, Read::Fields) {
        let resolve = requests
            .iter()
            .find(|request| request["method"] == "DOM.resolveNode")
            .unwrap();
        let group = resolve["params"]["objectGroup"].as_str().unwrap();
        let releases: Vec<_> = requests
            .iter()
            .enumerate()
            .filter(|(_, request)| request["method"] == "Runtime.releaseObjectGroup")
            .collect();
        assert_eq!(releases.len(), 1, "actual exact cleanup must be observed");
        assert_eq!(releases[0].1["params"], json!({"objectGroup":group}));
        let sample_index = requests
            .iter()
            .position(|request| request["method"] == "Runtime.callFunctionOn")
            .unwrap();
        assert!(releases[0].0 > sample_index);
    }
    (result, requests)
}

#[test]
fn pure_frame_validation_requires_exact_id_and_loader_without_new_shape_rules() {
    for child in [false, true] {
        let selected = frame(child);
        assert_eq!(
            validate_frame_tree(&tree(child, "doc"), &selected, false),
            Ok(())
        );
        assert_eq!(
            validate_frame_tree(&tree(child, "other-doc"), &selected, false),
            Err(ObservationError::StaleReference)
        );
        assert_eq!(
            validate_frame_tree(&json!({}), &selected, false),
            Err(ObservationError::StaleReference)
        );
    }
    let mut response = tree(false, "doc");
    response["frameTree"]["frame"]["loaderId"] = Value::Null;
    assert_eq!(
        validate_frame_tree(&response, &frame(false), false),
        Err(ObservationError::StaleReference)
    );
    response = tree(false, "doc");
    // Loader-only explicit validation deliberately does not invent a URL rule.
    assert_eq!(validate_frame_tree(&response, &frame(false), false), Ok(()));
    assert_eq!(
        validate_frame_tree(&response, &frame(false), true),
        Err(ObservationError::BackendFailure)
    );
    response["frameTree"]["frame"]["url"] = json!("https://fixture.invalid/other");
    assert_eq!(
        validate_frame_tree(&response, &frame(false), true),
        Err(ObservationError::StaleReference)
    );
    response["frameTree"]["frame"]["url"] = json!(frame(false).url);
    assert_eq!(validate_frame_tree(&response, &frame(false), true), Ok(()));
}

#[tokio::test]
async fn root_and_child_dom_keep_exact_branches_with_one_fresh_tree_each() {
    for child in [false, true] {
        let (result, requests) =
            run_case(Read::Validated, frame(child), inventory(child, 99)).await;
        assert_eq!(result, Ok(dom(99)));
        assert_eq!(requests.len(), if child { 4 } else { 3 });
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == "Page.getFrameTree")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn selected_child_that_is_its_session_root_uses_get_document() {
    let selected = frame(true);
    let mut steps = inventory(false, 99);
    steps[0].result = json!({"frameTree":{"frame":{"id":"child","loaderId":"doc"}}});
    let (result, requests) = run_case(Read::Validated, selected, steps).await;
    assert_eq!(result, Ok(dom(99)));
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1]["method"], "DOM.getDocument");
}

#[tokio::test]
async fn missing_frame_and_wrong_loader_stop_before_any_dom_command() {
    for child in [false, true] {
        let missing = if child {
            tree(false, "doc")
        } else {
            json!({"frameTree":{"frame":{"id":"other","loaderId":"doc"}}})
        };
        let mut missing_loader = tree(child, "doc");
        if child {
            missing_loader["frameTree"]["childFrames"][0]["frame"]["loaderId"] = Value::Null;
        } else {
            missing_loader["frameTree"]["frame"]["loaderId"] = Value::Null;
        }
        for response in [missing, tree(child, "other-doc"), missing_loader, json!({})] {
            let (result, requests) = run_case(
                Read::Validated,
                frame(child),
                vec![step("Page.getFrameTree", json!({}), response)],
            )
            .await;
            assert_eq!(result, Err(ObservationError::StaleReference));
            assert_eq!(requests.len(), 1);
        }
    }
}

#[tokio::test]
async fn child_without_content_document_keeps_existing_backend_failure() {
    let mut steps = inventory(true, 99);
    steps.truncate(3);
    steps[2].result = json!({"node":{"backendNodeId":7}});
    let (result, requests) = run_case(Read::Validated, frame(true), steps).await;
    assert_eq!(result, Err(ObservationError::BackendFailure));
    assert_eq!(requests.len(), 3);
}

#[tokio::test]
async fn legacy_frame_dom_keeps_loader_agnostic_root_and_child_behavior() {
    for child in [false, true] {
        let mut steps = if child {
            inventory(true, 99)
        } else {
            vec![
                step("Page.getFrameTree", json!({}), tree(false, "doc")),
                step(
                    "DOM.getDocument",
                    json!({"depth":-1,"pierce":true}),
                    dom(99),
                ),
            ]
        };
        steps[0].result = tree(child, "other-doc");
        let (result, _) = run_case(Read::Legacy, frame(child), steps).await;
        assert_eq!(result, Ok(dom(99)));
    }
}

#[tokio::test]
async fn fresh_fields_reacquire_final_inventory_with_exact_cdp_counts() {
    for child in [false, true] {
        let mut steps = fields_prefix(child);
        steps.extend(inventory(child, 99));
        let (result, requests) = run_case(Read::Fields, frame(child), steps).await;
        assert_eq!(result, Ok(json!([])));
        assert_eq!(requests.len(), if child { 12 } else { 10 });
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == "Page.getFrameTree")
                .count(),
            2
        );
        let resolve = requests
            .iter()
            .find(|r| r["method"] == "DOM.resolveNode")
            .unwrap();
        let group = resolve["params"]["objectGroup"].as_str().unwrap();
        assert_eq!(
            resolve["params"],
            json!({"backendNodeId":99,"executionContextId":1,"objectGroup":group})
        );
        let sample = requests
            .iter()
            .find(|r| r["method"] == "Runtime.callFunctionOn")
            .unwrap();
        assert_eq!(sample["params"]["objectGroup"], group);
        assert_eq!(sample["params"]["objectId"], "root-object");
        assert_eq!(sample["params"]["returnByValue"], true);
        let release = requests
            .iter()
            .find(|r| r["method"] == "Runtime.releaseObjectGroup")
            .unwrap();
        assert_eq!(release["params"], json!({"objectGroup":group}));
        let release_index = requests
            .iter()
            .position(|r| r["method"] == "Runtime.releaseObjectGroup")
            .unwrap();
        let sample_index = requests
            .iter()
            .position(|r| r["method"] == "Runtime.callFunctionOn")
            .unwrap();
        assert!(release_index > sample_index);
        let final_tree_index = requests
            .iter()
            .rposition(|r| r["method"] == "Page.getFrameTree")
            .unwrap();
        assert!(final_tree_index > sample_index);
    }
}

#[tokio::test]
async fn fresh_fields_final_loader_and_root_changes_still_reject_publication() {
    for child in [false, true] {
        for final_tree in [tree(child, "new-doc"), json!({"frameTree":{}})] {
            let mut steps = fields_prefix(child);
            steps.push(step("Page.getFrameTree", json!({}), final_tree));
            let (result, _) = run_case(Read::Fields, frame(child), steps).await;
            assert_eq!(result, Err(ObservationError::StaleReference));
        }

        let mut steps = fields_prefix(child);
        steps.extend(inventory(child, 100));
        let (result, _) = run_case(Read::Fields, frame(child), steps).await;
        assert_eq!(result, Err(ObservationError::StaleReference));
    }
}

#[tokio::test]
async fn stateless_root_rejects_malformed_seed_and_deep_document_identity() {
    for root in [
        Value::Null,
        json!({"nodeType":1,"backendNodeId":99}),
        json!({"nodeType":9}),
        json!({"nodeType":9,"backendNodeId":0}),
        json!({"nodeType":9,"backendNodeId":-1}),
        json!({"nodeType":9,"backendNodeId":1.5}),
        json!({"nodeType":9,"backendNodeId":"99"}),
    ] {
        let mut steps = inventory(false, 99);
        steps.truncate(2);
        steps[1].result = json!({"root":root});
        let (result, requests) = run_case(Read::Validated, frame(false), steps).await;
        assert_eq!(result, Err(ObservationError::BackendFailure));
        assert_eq!(
            requests.len(),
            2,
            "malformed seed must not reach describeNode"
        );
    }
    for (node, error) in [
        (Value::Null, ObservationError::BackendFailure),
        (
            json!({"nodeType":1,"backendNodeId":99,"children":[]}),
            ObservationError::BackendFailure,
        ),
        (
            json!({"nodeType":9,"backendNodeId":0,"children":[]}),
            ObservationError::BackendFailure,
        ),
        (
            json!({"nodeType":9,"backendNodeId":99}),
            ObservationError::BackendFailure,
        ),
        (
            json!({"nodeType":9,"backendNodeId":99,"children":{}}),
            ObservationError::BackendFailure,
        ),
        (
            json!({"nodeType":9,"backendNodeId":100,"children":[]}),
            ObservationError::StaleReference,
        ),
    ] {
        let mut steps = inventory(false, 99);
        steps[2].result = json!({"node":node});
        let (result, requests) = run_case(Read::Validated, frame(false), steps).await;
        assert_eq!(result, Err(error));
        assert_eq!(requests.len(), 3);
    }
}

#[tokio::test]
async fn stateless_root_keeps_zero_frontend_ids_and_full_shadow_security_inventory() {
    for ua_password in [false, true] {
        let deep = json!({"nodeId":0,"nodeType":9,"backendNodeId":99,"children":[
            {"nodeId":0,"parentId":0,"nodeType":1,"nodeName":"DIV","backendNodeId":40,"children":[],
             "shadowRoots":[{"nodeId":0,"nodeType":11,"backendNodeId":41,"shadowRootType":"closed","children":[]}]},
            {"nodeId":0,"parentId":0,"nodeType":1,"nodeName":"DIV","backendNodeId":60,"children":[],
             "shadowRoots":[{"nodeId":0,"nodeType":11,"backendNodeId":61,"shadowRootType":"open","children":[]}]},
            {"nodeId":0,"parentId":0,"nodeType":1,"nodeName":"INPUT","backendNodeId":50,"children":[],
             "shadowRoots":[{"nodeId":0,"nodeType":11,"backendNodeId":51,"shadowRootType":"user-agent","children":[
                 {"nodeId":0,"nodeType":1,"nodeName":if ua_password {"INPUT"} else {"DIV"},"backendNodeId":52,
                  "attributes":if ua_password {json!(["type","password"])} else {json!([])},"children":[]}
             ]}]}
        ]});
        let mut steps = inventory(false, 99);
        steps[2].result = json!({"node":deep});
        let (result, requests) = run_case(Read::Validated, frame(false), steps).await;
        assert_eq!(
            result,
            Ok(json!({"root":deep})),
            "full native tree must be preserved"
        );
        assert_eq!(requests[1]["params"], json!({"depth":0,"pierce":true}));
        assert_eq!(
            requests[2]["params"],
            json!({"backendNodeId":99,"depth":-1,"pierce":true})
        );
        assert_eq!(
            fresh_query::roots(&deep).unwrap(),
            if ua_password {
                None
            } else {
                Some((vec![99, 41, 61], vec![true, true, true], vec![0, 1]))
            }
        );
        // Frontend mirror numbers are neither root authority nor policy input.
        fn front_ids(node: &mut Value) {
            node["nodeId"] = json!(700);
            node["parentId"] = json!(701);
            for key in ["children", "shadowRoots"] {
                if let Some(children) = node[key].as_array_mut() {
                    for child in children {
                        front_ids(child);
                    }
                }
            }
        }
        let mut tracked = deep.clone();
        front_ids(&mut tracked);
        assert_eq!(fresh_query::roots(&deep), fresh_query::roots(&tracked));
    }
}

#[tokio::test]
async fn stateless_root_boundary_keeps_original_cancel_and_deadline_without_group_debt() {
    for signal in [CancelSignal::Requested, CancelSignal::DeadlineExceeded] {
        for boundary in [1usize, 2] {
            let mut steps = inventory(false, 99);
            steps.truncate(boundary + 1);
            steps[boundary].stop = Some(signal);
            let (result, requests) = run_case(Read::Validated, frame(false), steps).await;
            assert_eq!(
                result,
                Err(if signal == CancelSignal::Requested {
                    ObservationError::Cancelled
                } else {
                    ObservationError::DeadlineExceeded
                })
            );
            assert_eq!(requests.len(), boundary + 1);
            assert!(!requests
                .iter()
                .any(|request| request["method"] == "DOM.resolveNode"
                    || request["method"] == "Runtime.releaseObjectGroup"));
        }
    }
}

#[tokio::test]
async fn fresh_fields_stateless_final_description_navigation_and_closed_root_changes_reject() {
    for changed_document in [false, true] {
        let mut steps = fields_prefix(false);
        let mut final_inventory = inventory(false, 99);
        final_inventory[2].result = if changed_document {
            // The second RPC may never substitute another Document for its seed.
            json!({"node":{"nodeType":9,"backendNodeId":100,"children":[]}})
        } else {
            json!({"node":{"nodeId":0,"nodeType":9,"backendNodeId":99,"children":[
                {"nodeId":0,"nodeType":1,"backendNodeId":40,"shadowRoots":[
                    {"nodeId":0,"nodeType":11,"backendNodeId":41,"shadowRootType":"closed","children":[]}
                ]}
            ]}})
        };
        steps.extend(final_inventory);
        let (result, requests) = run_case(Read::Fields, frame(false), steps).await;
        assert_eq!(result, Err(ObservationError::StaleReference));
        assert_eq!(requests.len(), 10);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "DOM.getDocument")
                .count(),
            2
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "DOM.describeNode")
                .count(),
            2
        );
    }
}

#[tokio::test]
async fn stateless_root_describe_errors_stay_opaque_and_foreign_ack_keeps_debt() {
    for foreign_session in [false, true] {
        let mut steps = inventory(false, 99);
        if foreign_session {
            steps[2].reply_session = Some("foreign-renderer");
        } else {
            // Opaque browser wording is not evidence of this operation's stop.
            steps[2].error =
                Some(json!({"code":-32000,"message":"deadline exceeded in another operation"}));
        }
        let (result, requests) =
            run_case_with_integrity(Read::Validated, frame(false), steps, foreign_session).await;
        if foreign_session {
            // Legacy LocalFailure delivery preserves the provisional payload.
            // run_case_with_integrity has already required poisoned authority,
            // exactly one unsettled command, and no object/input debt. This is
            // NOT public success: the paired framed ReadFields controls reject
            // both inventory descriptions and the last dispatcher frame ACK.
            assert_eq!(result, Ok(dom(99)));
        } else {
            assert_eq!(result, Err(ObservationError::BackendFailure));
        }
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2]["method"], "DOM.describeNode");
        assert_eq!(requests[2]["sessionId"], "renderer");
    }
}
