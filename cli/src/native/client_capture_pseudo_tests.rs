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
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let mut page = owner.lease(gate.enter(false).unwrap()).unwrap();
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
        let result: Result<(), String> = async {
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
            let ready=client.send_command("Runtime.evaluate",Some(json!({"expression":setup,"returnByValue":true})),Some(&session)).await?;
            if ready["result"]["value"]!=true{return Err("Pseudo fixture setup failed".into());}
            // Prove this is a real generated-node fixture, not a browser that
            // ignored the CSS. Native snapshot must contain this exact kind.
            let snapshot=client.send_command("DOMSnapshot.captureSnapshot",Some(json!({"computedStyles":[]})),Some(&session)).await?;
            let strings=snapshot["strings"].as_array().ok_or("Missing snapshot strings")?;
            let document=&snapshot["documents"][0];
            let proof=capture_pseudo_nodes(document,strings).map_err(|_|"Pseudo fixture provenance failed")?;
            if proof.origins.is_empty(){return Err("Pseudo fixture has no native origin".into());}
            let values=document["nodes"]["pseudoType"]["value"].as_array().ok_or("Missing pseudo types")?;
            if !values.iter().any(|v|v.as_u64().and_then(|i|strings.get(i as usize)).and_then(Value::as_str)==Some(kind)) {
                return Err("Browser did not generate the requested pseudo kind".into());
            }
            client.send_command("Animation.enable",Some(json!({})),Some(&session)).await?;
            client.send_command("Animation.setPlaybackRate",Some(json!({"playbackRate":0.75})),Some(&session)).await?;
            let frames=super::super::client_observation::enumerate_frames(&client,&session,&HashMap::new(),&operation).await.map_err(|_|"Pseudo frame enumeration failed")?;
            if frames.len()!=1{return Err("Unexpected pseudo frame inventory".into());}
            // This isolated synthetic fixture is a known one-renderer owner.
            page.targets.acknowledge_enrollment().map_err(|_|"Pseudo enrollment failed")?;
            let journal=super::tests::owned_capture_journal(&mut owner,&mut page,&operation);
            let captured=journal.scope(async {
                start_capture(CaptureContext{page,frames,inventory_complete:true},CaptureRequest{secure_field_selector:"[data-protected]".into()},operation).await
            }).await.map_err(|_|"Pseudo capture task failed")?;
            if secure {
                match captured {
                    Err(error) if error.reason==CaptureReason::UnsafeGeometry && !error.cleanup_integrity_lost => {},
                    _ => return Err("Generated protected paint did not fail closed".into()),
                }
            } else {
                let captured=captured.map_err(|error|format!("Public pseudo protected capture failed: {:?}",error.reason))?;
                if captured.masked_region_count<1{return Err("Password mask missing with public pseudos".into());}
                let pixels=image::load_from_memory(&captured.png).map_err(|_|"Pseudo PNG invalid")?.to_rgba8();
                if pixels.dimensions()!=(400,300)||pixels.get_pixel(25,25).0!=[0,0,0,255] {
                    return Err("Public pseudo fixture password was not masked".into());
                }
                if pixels.get_pixel(240,30).0!=[0,255,0,255]||pixels.get_pixel(300,200).0!=[25,75,125,255] {
                    return Err("Capture removed public generated paint or background".into());
                }
            }
            let restored=client.send_command("Runtime.evaluate",Some(json!({"expression":"(()=>{const f=window.__pseudoFixture;return f.input.value==='synthetic-password'&&f.input.getAttribute('style')===f.inline&&f.generated.getAttribute('value')==='synthetic-generated-secret'&&f.root.querySelectorAll('style').length===1&&f.style.isConnected&&getComputedStyle(f.input).opacity==='1'})()","returnByValue":true})),Some(&session)).await?;
            if restored["result"]["value"]!=true{return Err("Pseudo capture changed source state or left masks".into());}
            let rate=client.send_command("Animation.getPlaybackRate",Some(json!({})),Some(&session)).await?;
            if rate["playbackRate"].as_f64()!=Some(0.75){return Err("Pseudo capture did not restore animation playback".into());}
            Ok(())
        }.await;
        let cleanup = owner.close().await;
        assert!(cleanup.is_ok(), "Pseudo fixture owner cleanup failed");
        assert!(
            result.is_ok(),
            "Pseudo fixture {kind}/{closed}/{secure}: {result:?}"
        );
    }
}
