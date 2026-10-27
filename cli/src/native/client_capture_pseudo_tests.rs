//! Native snapshot provenance and real generated-paint capture regressions.
use super::*;
#[test]
fn capture_pseudo_origins_are_native_bound_and_not_element_receivers() {
    let strings = vec![
        json!("before"),
        json!("marker"),
        json!("closed"),
        json!("after"),
    ];
    // A nested ::before::marker plus a closed author root's ::after.
    let doc = json!({"nodes":{
        "nodeType":[9,1,1,1,11,1,1],"backendNodeId":[1,2,3,4,5,6,7],
        "parentIndex":[-1,0,1,2,1,4,5],
        "pseudoType":{"index":[2,3,6],"value":[0,1,3]},
        "shadowRootType":{"index":[4,5,6],"value":[2,2,2]}
    }});
    let proof = capture_pseudo_nodes(&doc, &strings).unwrap();
    assert_eq!(proof.indices, HashSet::from([2, 3, 6]));
    assert_eq!(proof.origins, vec![2, 6]);
    assert_eq!(
        source_mask_backend_ids(&doc, &strings).unwrap(),
        vec![1, 2, 5, 6]
    );
    // No pseudo metadata does not require parent links or change old roots.
    let plain = json!({"nodes":{"nodeType":[9,1,11,1],"backendNodeId":[1,2,3,4]}});
    assert_eq!(
        capture_pseudo_nodes(&plain, &[]),
        Ok(CapturePseudoNodes::default())
    );
    assert_eq!(
        source_mask_backend_ids(&plain, &[]).unwrap(),
        vec![1, 2, 3, 4]
    );
}
#[test]
fn capture_pseudo_metadata_and_parent_ambiguity_fail_closed() {
    let strings = vec![json!("before"), json!("view-transition"), json!("unknown")];
    let base = json!({"nodes":{"nodeType":[9,1,1],"backendNodeId":[1,2,3],"parentIndex":[-1,0,1],"pseudoType":{"index":[2],"value":[0]}}});
    for (pointer, replacement) in [
        ("/nodes/pseudoType/index", json!([2, 2])),
        ("/nodes/pseudoType", json!({"index":[2,2],"value":[0,0]})),
        ("/nodes/pseudoType/index/0", json!(3)),
        ("/nodes/pseudoType/index/0", json!(-1)),
        ("/nodes/pseudoType/value/0", json!(9)),
        ("/nodes/pseudoType/value/0", json!(1)),
        ("/nodes/pseudoType/value/0", json!(2)),
        ("/nodes/nodeType/2", json!(3)),
        ("/nodes/backendNodeId/2", json!(0)),
        ("/nodes/backendNodeId/1", json!(0)),
        ("/nodes/parentIndex", json!(null)),
        ("/nodes/parentIndex", json!([-1, 0])),
        ("/nodes/parentIndex/2", json!(2)),
        ("/nodes/parentIndex/2", json!(3)),
        ("/nodes/parentIndex/2", json!(-1)),
        ("/nodes/parentIndex/2", json!(0)),
    ] {
        let mut doc = base.clone();
        *doc.pointer_mut(pointer).unwrap() = replacement;
        assert_eq!(
            capture_pseudo_nodes(&doc, &strings),
            Err(CaptureReason::MaskingUnproven),
            "{pointer}"
        );
        assert_eq!(
            source_mask_backend_ids(&doc, &strings),
            Err(CaptureReason::MaskingUnproven),
            "source {pointer}"
        );
    }
}
#[test]
fn capture_pseudo_chain_and_node_budget_are_bounded() {
    let nodes = 258usize;
    let doc = json!({"nodes":{
        "nodeType":vec![1;nodes],"backendNodeId":(1..=nodes).collect::<Vec<_>>(),
        "parentIndex":(-1..nodes as i64-1).collect::<Vec<_>>(),
        "pseudoType":{"index":(1..nodes).collect::<Vec<_>>(),"value":vec![0;nodes-1]}
    }});
    assert_eq!(
        capture_pseudo_nodes(&doc, &[json!("marker")]),
        Err(CaptureReason::BoundsExceeded)
    );
    let huge = json!({"nodes":{"nodeType":vec![1;MAX_DOM_NODES+1],"backendNodeId":vec![1;MAX_DOM_NODES+1]}});
    assert_eq!(
        capture_pseudo_nodes(&huge, &[]),
        Err(CaptureReason::BoundsExceeded)
    );
}

// Test-only closed diagnostics. No CDP message, JS exception, page value,
// identifier, URL or pixel data can be carried by these output types.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PseudoStage {
    Launch,
    Lease,
    Viewport,
    Setup,
    Snapshot,
    Provenance,
    AnimationEnable,
    AnimationSetRate,
    FrameEnumeration,
    Enrollment,
    JournalBinding,
    Capture,
    PixelChecks,
    SourceRestoration,
    AnimationRestoration,
    OwnerCleanup,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PseudoCdpFailure {
    OwnerViewRequired,
    OwnerChanged,
    AdmissionRefused,
    AdmissionRevoked,
    ChannelClosed,
    TransportClosed,
    ResponseDeadline,
    ErrorAck,
    SendFailed,
    Other,
}
fn pseudo_cdp_failure(error: &str) -> PseudoCdpFailure {
    match error {
        "Native CDP requires an owner-bound view" => PseudoCdpFailure::OwnerViewRequired,
        "Native CDP owner changed"
        | "Native CDP reservation owner changed"
        | "Native cleanup owner changed" => PseudoCdpFailure::OwnerChanged,
        "Native CDP command admission refused" => PseudoCdpFailure::AdmissionRefused,
        "Native CDP command admission revoked" => PseudoCdpFailure::AdmissionRevoked,
        "CDP response channel closed" => PseudoCdpFailure::ChannelClosed,
        "CDP connection closed" => PseudoCdpFailure::TransportClosed,
        value if value.starts_with("CDP command timed out:") => PseudoCdpFailure::ResponseDeadline,
        value if value.starts_with("CDP error (") => PseudoCdpFailure::ErrorAck,
        value if value.starts_with("Failed to send CDP command:") => PseudoCdpFailure::SendFailed,
        _ => PseudoCdpFailure::Other,
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PseudoCheckFailure {
    Setup,
    SnapshotStrings,
    NoOrigin,
    PseudoTypes,
    MissingRequestedKind,
    FrameInventory,
    SecurePaintAccepted,
    PasswordMaskMissing,
    PngInvalid,
    PasswordPixel,
    PublicPaintPixel,
    SourceRestoration,
    AnimationRestoration,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PseudoFailure {
    Cdp(PseudoCdpFailure),
    Check(PseudoCheckFailure),
    Protocol(super::super::client_protocol::ProtocolError),
    Provenance(CaptureReason),
    Enumeration,
    ScriptException,
    Join {
        cancelled: bool,
        panicked: bool,
    },
    Capture {
        reason: CaptureReason,
        cleanup_integrity_lost: bool,
    },
}
impl From<String> for PseudoFailure {
    fn from(error: String) -> Self {
        Self::Cdp(pseudo_cdp_failure(&error))
    }
}
fn pseudo_diagnostic(
    kind: &str,
    closed: bool,
    secure: bool,
    stage: PseudoStage,
    outcome: &str,
    failure: Option<&PseudoFailure>,
) {
    // The only string inputs are local closed call-site literals; reject rather
    // than project an unexpected string if a future test changes the schema.
    assert!(matches!(kind, "before" | "after"));
    assert!(matches!(outcome, "entered" | "passed" | "failed"));
    eprintln!(
        "PSEUDO_CAPTURE_DIAGNOSTIC {}",
        json!({"kind":kind,"closed":closed,"secure":secure,"stage":stage,"outcome":outcome,"failure":failure})
    );
}
#[test]
fn pseudo_diagnostics_never_retain_untrusted_cdp_text() {
    let secret = "synthetic-private-value https://invalid.example/private";
    for (error, expected) in [
        (secret.to_owned(), PseudoCdpFailure::Other),
        (
            format!("CDP error (Runtime.evaluate): {secret}"),
            PseudoCdpFailure::ErrorAck,
        ),
        (
            format!("Failed to send CDP command: {secret}"),
            PseudoCdpFailure::SendFailed,
        ),
        (
            "Native CDP requires an owner-bound view".into(),
            PseudoCdpFailure::OwnerViewRequired,
        ),
    ] {
        assert_eq!(pseudo_cdp_failure(&error), expected);
        let serialized = serde_json::to_string(&PseudoFailure::from(error)).unwrap();
        assert!(!serialized.contains(secret));
        assert!(serialized.len() < 96);
    }
}

#[tokio::test]
#[ignore = "requires real Chromium: pseudo receivers, generated-secret refusal and restoration"]
async fn chromium_pseudo_capture_preserves_public_pixels_and_refuses_secure_generated_paint() {
    use super::super::client_browser::{ExecutionGate, OwnedBrowser};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    for (kind, closed, secure) in [
        ("before", false, false),
        ("before", true, false),
        ("before", false, true),
        ("after", false, true),
        ("before", true, true),
        ("after", true, true),
    ] {
        let stage = std::cell::Cell::new(PseudoStage::Launch);
        let mark = |next| {
            stage.set(next);
            pseudo_diagnostic(kind, closed, secure, next, "entered", None);
        };
        mark(PseudoStage::Launch);
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap_or_else(|error| {
                pseudo_diagnostic(
                    kind,
                    closed,
                    secure,
                    stage.get(),
                    "failed",
                    Some(&PseudoFailure::Protocol(error)),
                );
                panic!("Pseudo fixture launch failed");
            });
        mark(PseudoStage::Lease);
        let gate = Arc::new(ExecutionGate::default());
        let mut page = owner
            .lease(gate.enter(false).unwrap())
            .unwrap_or_else(|error| {
                pseudo_diagnostic(
                    kind,
                    closed,
                    secure,
                    stage.get(),
                    "failed",
                    Some(&PseudoFailure::Protocol(error)),
                );
                panic!("Pseudo fixture lease failed");
            });
        let client = page.client.clone();
        let session = page.page_session_id.clone();
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let result: Result<(), PseudoFailure> = async {
            mark(PseudoStage::Viewport);
            client.send_command("Emulation.setDeviceMetricsOverride",Some(json!({"width":400,"height":300,"deviceScaleFactor":1,"mobile":false})),Some(&session)).await?;
            let setup = format!(r#"(()=>{{
              document.body.style.cssText='margin:0;background:rgb(25,75,125)';
              const host=document.createElement('div');document.body.appendChild(host);
              const root={closed}?host.attachShadow({{mode:'closed'}}):host;
              const input=document.createElement('input');input.type='password';input.value='synthetic-password';
              input.style.cssText='position:absolute;left:20px;top:20px;width:100px;height:30px;border:0;padding:0;background:red;text-shadow:none';root.appendChild(input);
              const generated=document.createElement({secure}&&!{closed}?'input':'span');
              if({secure}&&!{closed}){{generated.type='checkbox';generated.setAttribute('data-protected','');generated.style.cssText='appearance:none;position:absolute;left:20px;top:100px;width:20px;height:20px';}}
              if({secure}&&{closed})host.setAttribute('data-protected','');
              generated.className='generated';generated.setAttribute('value','synthetic-generated-secret');root.appendChild(generated);
              const style=document.createElement('style');style.textContent='.generated::{kind}{{content:attr(value);position:fixed;left:220px;top:20px;width:60px;height:40px;display:block;background:lime;color:lime;overflow:visible}}';root.appendChild(style);
              const list=document.createElement('ul');list.innerHTML='<li>Public item</li>';list.style.cssText='position:absolute;left:180px;top:100px';root.appendChild(list);
              const details=document.createElement('details');details.innerHTML='<summary>Public summary</summary>';root.appendChild(details);
              window.__pseudoFixture={{root,input,generated,style,inline:input.getAttribute('style')}};
              return true;
            }})()"#);
            mark(PseudoStage::Setup);
            let ready=client.send_command("Runtime.evaluate",Some(json!({"expression":setup,"returnByValue":true})),Some(&session)).await?;
            if ready.get("exceptionDetails").is_some(){return Err(PseudoFailure::ScriptException);}
            if ready["result"]["value"]!=true{return Err(PseudoFailure::Check(PseudoCheckFailure::Setup));}
            // Prove this is a real generated-node fixture, not a browser that
            // ignored the CSS. Native snapshot must contain this exact kind.
            mark(PseudoStage::Snapshot);
            let snapshot=client.send_command("DOMSnapshot.captureSnapshot",Some(json!({"computedStyles":[]})),Some(&session)).await?;
            mark(PseudoStage::Provenance);
            let strings=snapshot["strings"].as_array().ok_or(PseudoFailure::Check(PseudoCheckFailure::SnapshotStrings))?;
            let document=&snapshot["documents"][0];
            let proof=capture_pseudo_nodes(document,strings).map_err(PseudoFailure::Provenance)?;
            if proof.origins.is_empty(){return Err(PseudoFailure::Check(PseudoCheckFailure::NoOrigin));}
            let values=document["nodes"]["pseudoType"]["value"].as_array().ok_or(PseudoFailure::Check(PseudoCheckFailure::PseudoTypes))?;
            if !values.iter().any(|v|v.as_u64().and_then(|i|strings.get(i as usize)).and_then(Value::as_str)==Some(kind)) {
                return Err(PseudoFailure::Check(PseudoCheckFailure::MissingRequestedKind));
            }
            mark(PseudoStage::AnimationEnable);
            client.send_command("Animation.enable",Some(json!({})),Some(&session)).await?;
            mark(PseudoStage::AnimationSetRate);
            client.send_command("Animation.setPlaybackRate",Some(json!({"playbackRate":0.75})),Some(&session)).await?;
            mark(PseudoStage::FrameEnumeration);
            let frames=super::super::client_observation::enumerate_frames(&client,&session,&HashMap::new(),&operation).await.map_err(|_|PseudoFailure::Enumeration)?;
            if frames.len()!=1{return Err(PseudoFailure::Check(PseudoCheckFailure::FrameInventory));}
            // This isolated synthetic fixture is a known one-renderer owner.
            mark(PseudoStage::Enrollment);
            page.targets.acknowledge_enrollment().map_err(PseudoFailure::Protocol)?;
            mark(PseudoStage::JournalBinding);
            let journal=super::tests::owned_capture_journal(&mut owner,&mut page,&operation);
            // Installation replaces the ambient transport handle with its exact
            // owner-bound view. Post-capture checks must use that view too.
            let client=page.client.clone();
            mark(PseudoStage::Capture);
            let captured=journal.scope(async {
                start_capture(CaptureContext{page,frames,inventory_complete:true},CaptureRequest{secure_field_selector:"[data-protected]".into()},operation).await
            }).await.map_err(|error|PseudoFailure::Join{cancelled:error.is_cancelled(),panicked:error.is_panic()})?;
            if secure {
                match captured {
                    Err(error) if error.reason==CaptureReason::UnsafeGeometry && !error.cleanup_integrity_lost => {},
                    Err(error) => return Err(PseudoFailure::Capture{reason:error.reason,cleanup_integrity_lost:error.cleanup_integrity_lost}),
                    Ok(_) => return Err(PseudoFailure::Check(PseudoCheckFailure::SecurePaintAccepted)),
                }
            } else {
                let captured=captured.map_err(|error|PseudoFailure::Capture{reason:error.reason,cleanup_integrity_lost:error.cleanup_integrity_lost})?;
                mark(PseudoStage::PixelChecks);
                if captured.masked_region_count<1{return Err(PseudoFailure::Check(PseudoCheckFailure::PasswordMaskMissing));}
                let pixels=image::load_from_memory(&captured.png).map_err(|_|PseudoFailure::Check(PseudoCheckFailure::PngInvalid))?.to_rgba8();
                if pixels.dimensions()!=(400,300)||pixels.get_pixel(25,25).0!=[0,0,0,255] {
                    return Err(PseudoFailure::Check(PseudoCheckFailure::PasswordPixel));
                }
                if pixels.get_pixel(240,30).0!=[0,255,0,255]||pixels.get_pixel(300,200).0!=[25,75,125,255] {
                    return Err(PseudoFailure::Check(PseudoCheckFailure::PublicPaintPixel));
                }
            }
            mark(PseudoStage::SourceRestoration);
            let restored=client.send_command("Runtime.evaluate",Some(json!({"expression":"(()=>{const f=window.__pseudoFixture;return f.input.value==='synthetic-password'&&f.input.getAttribute('style')===f.inline&&f.generated.getAttribute('value')==='synthetic-generated-secret'&&f.root.querySelectorAll('style').length===1&&f.style.isConnected&&getComputedStyle(f.input).opacity==='1'})()","returnByValue":true})),Some(&session)).await?;
            if restored.get("exceptionDetails").is_some(){return Err(PseudoFailure::ScriptException);}
            if restored["result"]["value"]!=true{return Err(PseudoFailure::Check(PseudoCheckFailure::SourceRestoration));}
            mark(PseudoStage::AnimationRestoration);
            let rate=client.send_command("Animation.getPlaybackRate",Some(json!({})),Some(&session)).await?;
            if rate["playbackRate"].as_f64()!=Some(0.75){return Err(PseudoFailure::Check(PseudoCheckFailure::AnimationRestoration));}
            Ok(())
        }.await;
        pseudo_diagnostic(
            kind,
            closed,
            secure,
            stage.get(),
            if result.is_ok() { "passed" } else { "failed" },
            result.as_ref().err(),
        );
        mark(PseudoStage::OwnerCleanup);
        let cleanup = owner.close().await.map_err(PseudoFailure::Protocol);
        pseudo_diagnostic(
            kind,
            closed,
            secure,
            stage.get(),
            if cleanup.is_ok() { "passed" } else { "failed" },
            cleanup.as_ref().err(),
        );
        assert!(cleanup.is_ok(), "Pseudo fixture owner cleanup failed");
        assert!(
            result.is_ok(),
            "Pseudo fixture contract failed; see closed diagnostic"
        );
    }
}
