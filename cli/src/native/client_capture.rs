//! Native-only protected pixel transaction. Raw pixels stay inside this module;
//! cleanup integrity is part of the outcome, even for optional screenshots.
use super::client_browser::BrowserExecutionLease;
use super::client_observation::ObservationFrame;
use super::client_protected_read::{ProtectedReadJournal, ProtectedReadReason};
use super::client_session::{CancelSignal, OperationLease};
use base64::Engine;
use futures_util::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;

const MAX_PIXELS: u64 = 16_777_216;
const MAX_PNG_BYTES: usize = 32 * 1024 * 1024;
const MAX_DOM_NODES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureReason {
    Cancelled,
    Deadline,
    StaleScope,
    IncompleteFrames,
    UnsafeGeometry,
    UninspectableContent,
    MaskingUnproven,
    BrowserFailure,
    BoundsExceeded,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFailure {
    pub reason: CaptureReason,
    pub identity_scope: String,
    /// True means the captured OLD scope needs quarantine, never whichever
    /// scope happens to be current when this asynchronous result arrives.
    pub cleanup_integrity_lost: bool,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureRequest {
    pub secure_field_selector: String,
}
/// Built by the native owner after a complete frame inventory. The caller must
/// retain the returned task until cleanup, including when its RPC is cancelled.
pub struct CaptureContext {
    pub page: BrowserExecutionLease,
    pub frames: Vec<ObservationFrame>,
    pub inventory_complete: bool,
    pub lifecycle_known_active: bool,
}
pub struct MaskedCapture {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub scale: f64,
    pub masked_region_count: usize,
    pub identity_scope: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
struct MaskRect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameMasks {
    count: usize,
    masks: Vec<MaskRect>,
    opaque: bool,
    unsafe_geometry: bool,
}
#[derive(Clone, PartialEq)]
struct MaskProof {
    count: usize,
    masks: Vec<MaskRect>,
}

fn check(context: &CaptureContext, operation: &OperationLease) -> Result<(), CaptureReason> {
    context
        .page
        .permit
        .check()
        .map_err(|_| CaptureReason::StaleScope)?;
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(CaptureReason::Cancelled);
    }
    if std::time::Instant::now() >= operation.deadline {
        return Err(CaptureReason::Deadline);
    }
    Ok(())
}
async fn command(
    context: &CaptureContext,
    operation: &OperationLease,
    session: &str,
    method: &str,
    args: Value,
) -> Result<Value, CaptureReason> {
    check(context, operation)?;
    let mut cancellation = operation.cancellation.clone();
    tokio::select! {
        result = context.page.client.send_command(method, Some(args), Some(session)) => { check(context, operation)?; result.map_err(|_| CaptureReason::BrowserFailure) },
        _ = cancellation.changed() => Err(CaptureReason::Cancelled),
        _ = tokio::time::sleep_until(operation.deadline.into()) => Err(CaptureReason::Deadline),
    }
}
/// Spawn supervision before the first page mutation. Dropping the RPC receiver
/// does not drop this task; the owner joins it before releasing its scope.
pub fn start_capture(
    context: CaptureContext,
    request: CaptureRequest,
    operation: OperationLease,
) -> tokio::task::JoinHandle<Result<MaskedCapture, CaptureFailure>> {
    tokio::spawn(async move { capture_transaction(context, request, operation).await })
}

async fn capture_transaction(
    context: CaptureContext,
    request: CaptureRequest,
    operation: OperationLease,
) -> Result<MaskedCapture, CaptureFailure> {
    let mut journal =
        ProtectedReadJournal::begin(&context.page, &operation, context.lifecycle_known_active)
            .map_err(|failure| CaptureFailure {
                reason: protected_reason(failure.reason),
                identity_scope: failure.identity_scope,
                cleanup_integrity_lost: failure.cleanup_integrity_lost,
            })?;
    let result = async {
        if !context.inventory_complete || !context.lifecycle_known_active || context.frames.is_empty() { return Err(CaptureReason::IncompleteFrames); }
        if request.secure_field_selector.is_empty() || request.secure_field_selector.len() > 8192 { return Err(CaptureReason::MaskingUnproven); }
        for frame in &context.frames {
            if frame.binding.page_session != context.page.page_session_id || !journal.contains_session(&frame.binding.session) {return Err(CaptureReason::IncompleteFrames);}
        }
        journal.freeze().await.map_err(protected_reason)?;
        validate_frames(&context, &operation).await?;
        let viewport_size = viewport(&context, &operation).await?;
        let before = masks(&context, &request, &operation).await?;
        // Reuse canonical native screenshot capture, without annotations or IO.
        let options = super::screenshot::ScreenshotOptions::default();
        let refs = super::element::RefMap::new();
        let iframe_sessions = HashMap::new();
        let capture = super::screenshot::take_screenshot(&context.page.client, &context.page.page_session_id, &refs, &options, &iframe_sessions);
        let mut cancellation = operation.cancellation.clone();
        let raw = tokio::select! {
            result = capture => result.map_err(|_| CaptureReason::BrowserFailure)?,
            _ = cancellation.changed() => return Err(CaptureReason::Cancelled),
            _ = tokio::time::sleep_until(operation.deadline.into()) => return Err(CaptureReason::Deadline),
        };
        if raw.base64.len() > MAX_PNG_BYTES * 4 / 3 + 4 { return Err(CaptureReason::BoundsExceeded); }
        let bytes = base64::engine::general_purpose::STANDARD.decode(raw.base64).map_err(|_| CaptureReason::BrowserFailure)?;
        validate_frames(&context, &operation).await?;
        if viewport(&context, &operation).await? != viewport_size || masks(&context, &request, &operation).await? != before { return Err(CaptureReason::MaskingUnproven); }
        check(&context, &operation)?;
        raster_mask(&bytes, viewport_size, &before, &context.page.identity_scope)
    }.await;
    let integrity = journal.check().map_err(protected_reason);
    if let Err(failure) = journal.restore().await {
        return Err(CaptureFailure {
            reason: result
                .as_ref()
                .err()
                .copied()
                .unwrap_or_else(|| protected_reason(failure.reason)),
            identity_scope: failure.identity_scope,
            cleanup_integrity_lost: failure.cleanup_integrity_lost,
        });
    }
    integrity
        .and_then(|_| journal.check().map_err(protected_reason))
        .and(result)
        .map_err(|reason| CaptureFailure {
            reason,
            identity_scope: context.page.identity_scope.clone(),
            cleanup_integrity_lost: false,
        })
}
fn protected_reason(reason: ProtectedReadReason) -> CaptureReason {
    match reason {
        ProtectedReadReason::Cancelled => CaptureReason::Cancelled,
        ProtectedReadReason::Deadline => CaptureReason::Deadline,
        ProtectedReadReason::StaleScope => CaptureReason::StaleScope,
        ProtectedReadReason::IncompleteInventory => CaptureReason::IncompleteFrames,
        ProtectedReadReason::BrowserFailure => CaptureReason::BrowserFailure,
    }
}

async fn viewport(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<(f64, f64), CaptureReason> {
    let value = command(
        context,
        operation,
        &context.page.page_session_id,
        "Page.getLayoutMetrics",
        json!({}),
    )
    .await?;
    let viewport = value
        .get("cssVisualViewport")
        .ok_or(CaptureReason::UnsafeGeometry)?;
    let width = viewport["clientWidth"]
        .as_f64()
        .ok_or(CaptureReason::UnsafeGeometry)?;
    let height = viewport["clientHeight"]
        .as_f64()
        .ok_or(CaptureReason::UnsafeGeometry)?;
    if !width.is_finite()
        || !height.is_finite()
        || width <= 0.0
        || height <= 0.0
        || viewport["scale"].as_f64() != Some(1.0)
        || viewport["offsetX"].as_f64() != Some(0.0)
        || viewport["offsetY"].as_f64() != Some(0.0)
    {
        return Err(CaptureReason::UnsafeGeometry);
    }
    Ok((width, height))
}
async fn validate_frames(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<(), CaptureReason> {
    for frame in &context.frames {
        let tree = command(
            context,
            operation,
            &frame.binding.session,
            "Page.getFrameTree",
            json!({}),
        )
        .await?;
        fn find<'a>(tree: &'a Value, id: &str) -> Option<&'a str> {
            if tree["frame"]["id"].as_str() == Some(id) {
                return tree["frame"]["loaderId"].as_str();
            }
            tree["childFrames"]
                .as_array()?
                .iter()
                .find_map(|child| find(child, id))
        }
        if find(&tree["frameTree"], &frame.binding.frame) != Some(frame.binding.loader.as_str()) {
            return Err(CaptureReason::StaleScope);
        }
    }
    Ok(())
}

// Snapshot enumerates closed shadow trees as well as ordinary DOM. Discovery
// publishes no form values, text content, or serialized HTML. Snapshot payloads
// stay native and are never included in diagnostics or returned to the adapter.
async fn masks(
    context: &CaptureContext,
    request: &CaptureRequest,
    operation: &OperationLease,
) -> Result<MaskProof, CaptureReason> {
    let mut proof = MaskProof {
        count: 0,
        masks: Vec::new(),
    };
    let mut sessions = HashSet::new();
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for frame in &context.frames {
        if !sessions.insert(frame.binding.session.clone()) {
            continue;
        }
        let snapshot = command(
            context,
            operation,
            &frame.binding.session,
            "DOMSnapshot.captureSnapshot",
            json!({"computedStyles":[]}),
        )
        .await?;
        let strings = snapshot["strings"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?;
        for document in snapshot["documents"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?
        {
            let index = document["frameId"]
                .as_u64()
                .ok_or(CaptureReason::IncompleteFrames)? as usize;
            let id = strings
                .get(index)
                .and_then(Value::as_str)
                .ok_or(CaptureReason::IncompleteFrames)?;
            let owned = context
                .frames
                .iter()
                .find(|f| f.binding.frame == id && f.binding.session == frame.binding.session)
                .ok_or(CaptureReason::IncompleteFrames)?;
            if !seen.insert(id.to_owned()) {
                return Err(CaptureReason::IncompleteFrames);
            }
            // Additive offsets cannot prove transformed frame geometry. Mask
            // the entire viewport when a child frame contains a secure field;
            // this is conservative, not a fabricated exact coordinate mapping.
            let world = command(
                context,
                operation,
                &owned.binding.session,
                "Page.createIsolatedWorld",
                json!({"frameId":id,"worldName":"agent-browser-protected-capture"}),
            )
            .await?;
            let realm = world["executionContextId"]
                .as_i64()
                .ok_or(CaptureReason::MaskingUnproven)?;
            let types = document["nodes"]["nodeType"]
                .as_array()
                .ok_or(CaptureReason::MaskingUnproven)?;
            let backends = document["nodes"]["backendNodeId"]
                .as_array()
                .ok_or(CaptureReason::MaskingUnproven)?;
            if types.len() != backends.len() {
                return Err(CaptureReason::MaskingUnproven);
            }
            total = total
                .checked_add(types.len())
                .ok_or(CaptureReason::BoundsExceeded)?;
            if total > MAX_DOM_NODES {
                return Err(CaptureReason::BoundsExceeded);
            }
            let group = format!("capture-{}-{}", operation.sequence, id);
            let gathered = async {
                let ids: Vec<_> = types.iter().zip(backends).filter(|(kind,_)| kind.as_u64()==Some(1)).map(|(_,id)|id.as_i64().ok_or(CaptureReason::MaskingUnproven)).collect::<Result<Vec<i64>,_>>()?;
                for batch in ids.chunks(64) {
                    let mut args = vec![json!({"value":request.secure_field_selector})];
                    let handles: Vec<Value> = futures_util::stream::iter(batch.iter().copied().map(|backend: i64| { let group = &group; async move {
                        let resolved = command(context, operation, &owned.binding.session, "DOM.resolveNode", json!({"backendNodeId":backend,"executionContextId":realm,"objectGroup":group})).await?;
                        let object = resolved["object"]["objectId"].as_str().ok_or(CaptureReason::MaskingUnproven)?;
                        Ok::<Value, CaptureReason>(json!({"objectId":object}))
                    }})).buffered(16).try_collect().await?;
                    args.extend(handles);
                    let response = command(context, operation, &owned.binding.session, "Runtime.callFunctionOn", json!({"executionContextId":realm,"functionDeclaration":MASK_READER,"arguments":args,"returnByValue":true,"objectGroup":group})).await?;
                    if response.get("exceptionDetails").is_some() { return Err(CaptureReason::MaskingUnproven); }
                    let result: FrameMasks = serde_json::from_value(response["result"]["value"].clone()).map_err(|_|CaptureReason::MaskingUnproven)?;
                    if result.opaque { return Err(CaptureReason::UninspectableContent); }
                    if result.unsafe_geometry { return Err(CaptureReason::UnsafeGeometry); }
                    proof.count += result.count;
                    if owned.parent_frame_id.is_some() && !result.masks.is_empty() {
                        // No all-black success: renderer/frame projection needs
                        // its own verified geometry before pixels are usable.
                        return Err(CaptureReason::UnsafeGeometry);
                    }
                    proof.masks.extend(result.masks);
                }
                Ok(())
            }.await;
            // Object handles are private and best-effort released; cancelled
            // remote resolution can finish late, so scope disposal is final GC.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                context.page.client.send_command(
                    "Runtime.releaseObjectGroup",
                    Some(json!({"objectGroup":group})),
                    Some(&owned.binding.session),
                ),
            )
            .await;
            gathered?;
        }
    }
    if seen.len() != context.frames.len() {
        return Err(CaptureReason::IncompleteFrames);
    }
    Ok(proof)
}
const MASK_READER: &str = r#"function(selector,...nodes){
 const connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
 const owner=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get;
 let count=0,masks=[],opaque=false,unsafeGeometry=false;
 for(const node of nodes){
  if(!connected.call(node)||owner.call(node)!==document)throw Error('stale');
  const rect=node.getBoundingClientRect(),style=getComputedStyle(node);
  const visible=rect.width>0&&rect.height>0&&style.visibility!=='hidden'&&style.display!=='none'&&Number(style.opacity)!==0;
  if(visible&&(node.localName==='object'||node.localName==='embed'))opaque=true;
  let secure=false;for(let p=node;p;){if(p.matches('input[type="password" i]')||p.matches(selector)){secure=true;break;}p=p.parentElement||(p.getRootNode().host||null);}
  if(!secure)continue;
  count++;
  if(!visible){if(style.display==='contents')unsafeGeometry=true;continue;}
  if(![rect.x,rect.y,rect.width,rect.height].every(Number.isFinite))throw Error('geometry');
  // A clean refusal is not an all-black success. Required password-input
  // geometry is distinct from optional arbitrary secure-container policies.
  // Decorative box shadows do not carry the input's protected glyph pixels.
  let bleed=!(node.localName==='input'||node.localName==='textarea')||style.textShadow!=='none';
  for(let p=node;p;){const s=getComputedStyle(p);if(s.filter!=='none')bleed=true;p=p.parentElement||(p.getRootNode().host||null);}
  if(bleed){unsafeGeometry=true;continue;}
  masks.push({x:rect.x,y:rect.y,width:rect.width,height:rect.height});
 }
 return {count,masks,opaque,unsafeGeometry};
}"#;

fn raster_mask(
    bytes: &[u8],
    viewport: (f64, f64),
    proof: &MaskProof,
    scope: &str,
) -> Result<MaskedCapture, CaptureReason> {
    // Validate PNG IHDR before allocating a decoded pixel buffer.
    if bytes.len() < 24
        || bytes.len() > MAX_PNG_BYTES
        || &bytes[..8] != b"\x89PNG\r\n\x1a\n"
        || &bytes[12..16] != b"IHDR"
    {
        return Err(CaptureReason::BoundsExceeded);
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(CaptureReason::BoundsExceeded);
    }
    if !viewport.0.is_finite() || !viewport.1.is_finite() || viewport.0 <= 0.0 || viewport.1 <= 0.0
    {
        return Err(CaptureReason::UnsafeGeometry);
    }
    let sx = f64::from(width) / viewport.0;
    let sy = f64::from(height) / viewport.1;
    if (sx - sy).abs() > 1.0 / viewport.0.min(viewport.1) {
        return Err(CaptureReason::UnsafeGeometry);
    }
    let mut image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .map_err(|_| CaptureReason::BrowserFailure)?
        .to_rgba8();
    if image.dimensions() != (width, height) {
        return Err(CaptureReason::BoundsExceeded);
    }
    for rect in &proof.masks {
        if ![rect.x, rect.y, rect.width, rect.height]
            .iter()
            .all(|n| n.is_finite())
            || rect.width < 0.0
            || rect.height < 0.0
        {
            return Err(CaptureReason::UnsafeGeometry);
        }
        let left = (rect.x * sx).floor().clamp(0.0, f64::from(width)) as u32;
        let top = (rect.y * sy).floor().clamp(0.0, f64::from(height)) as u32;
        let right = ((rect.x + rect.width) * sx)
            .ceil()
            .clamp(0.0, f64::from(width)) as u32;
        let bottom = ((rect.y + rect.height) * sy)
            .ceil()
            .clamp(0.0, f64::from(height)) as u32;
        for y in top..bottom {
            for x in left..right {
                image.put_pixel(x, y, image::Rgba([0, 0, 0, 255]));
            }
        }
    }
    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut output, image::ImageFormat::Png)
        .map_err(|_| CaptureReason::BrowserFailure)?;
    let png = output.into_inner();
    if png.len() > MAX_PNG_BYTES {
        return Err(CaptureReason::BoundsExceeded);
    }
    Ok(MaskedCapture {
        png,
        width,
        height,
        scale: sx,
        masked_region_count: proof.count,
        identity_scope: scope.to_owned(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fractional_masks_round_outward() {
        let image = image::RgbaImage::from_pixel(8, 8, image::Rgba([255, 120, 80, 255]));
        let mut bytes = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let result = raster_mask(
            bytes.get_ref(),
            (4.0, 4.0),
            &MaskProof {
                count: 1,
                masks: vec![MaskRect {
                    x: 0.75,
                    y: 0.75,
                    width: 0.5,
                    height: 0.5,
                }],
            },
            "scope",
        )
        .unwrap();
        let pixels = image::load_from_memory(&result.png).unwrap().to_rgba8();
        assert_eq!(pixels.get_pixel(1, 1).0, [0, 0, 0, 255]);
        assert_eq!(pixels.get_pixel(2, 2).0, [0, 0, 0, 255]);
        assert_eq!(pixels.get_pixel(0, 0).0, [255, 120, 80, 255]);
    }
    #[test]
    fn invalid_png_is_not_released() {
        assert!(raster_mask(
            b"not png",
            (10.0, 10.0),
            &MaskProof {
                count: 0,
                masks: vec![]
            },
            "old"
        )
        .is_err());
    }
    /// Static one-page masking and cleanup proof only. This does not establish
    /// recursive target enrollment, OOPIF projection, or dynamic paint fidelity.
    #[tokio::test]
    #[ignore = "requires real Chromium; required static masked-pixel fidelity gate"]
    async fn chromium_static_mask_preserves_public_pixels_and_restores_state() {
        use super::super::client_browser::{ExecutionGate, OwnedBrowser};
        use super::super::element::ExactBinding;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        for closed_shadow in [false, true] {
            let mut owner = OwnedBrowser::launch(Default::default(), None)
                .await
                .unwrap();
            let gate = Arc::new(ExecutionGate::default());
            let page = owner.lease(gate.enter(false).unwrap()).unwrap();
            let client = page.client.clone();
            let session = page.page_session_id.clone();
            let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(30),
                cancellation,
            };
            let result:Result<(),String>=async {
                client.send_command("Emulation.setDeviceMetricsOverride",Some(json!({"width":400,"height":300,"deviceScaleFactor":1,"mobile":false})),Some(&session)).await?;
                let fixture=format!(r#"(()=>{{document.body.style.cssText='margin:0;background:rgb(25,75,125)';const host=document.createElement('div');host.style.cssText='position:absolute;left:20px;top:20px;width:120px;height:40px;background:red;box-shadow:0 0 4px white';document.body.appendChild(host);const root={closed_shadow}?host.attachShadow({{mode:'closed'}}):host;const input=document.createElement('input');input.type='password';input.value='synthetic-mask-only';input.style.cssText='position:absolute;left:0;top:0;width:100px;height:30px;border:0;padding:0;box-shadow:none;text-shadow:none;background:red';root.appendChild(input);window.__maskFixture={{host,input,style:input.getAttribute('style')}};document.body.dataset.tick='0';setInterval(()=>document.body.dataset.tick=String(Number(document.body.dataset.tick)+1),10);return true}})()"#);
                let setup=client.send_command("Runtime.evaluate",Some(json!({"expression":fixture,"returnByValue":true})),Some(&session)).await?;
                if setup["result"]["value"]!=true{return Err("Static masking fixture setup failed".into());}
                client.send_command("Animation.enable",Some(json!({})),Some(&session)).await?;
                client.send_command("Animation.setPlaybackRate",Some(json!({"playbackRate":0.75})),Some(&session)).await?;
                let tree=client.send_command("Page.getFrameTree",Some(json!({})),Some(&session)).await?;
                let frame=&tree["frameTree"]["frame"];
                let binding=ExactBinding{page_session:session.clone(),session:session.clone(),frame:frame["id"].as_str().ok_or("Missing static frame")?.into(),loader:frame["loaderId"].as_str().ok_or("Missing static loader")?.into(),actionable:false};
                let frames=vec![ObservationFrame{binding,offset_x:0.0,offset_y:0.0,frame_path:vec![],parent_frame_id:None,owner_backend_id:None,url:"about:blank".into()}];
                // Only this synthetic fixture is a known one-page inventory.
                // Production callers cannot use this acknowledgement as a substitute
                // for the native owner's recursive enrollment barrier.
                page.targets.acknowledge_enrollment().map_err(|_|"Static inventory acknowledgement failed")?;
                let captured=start_capture(CaptureContext{page,frames,inventory_complete:true,lifecycle_known_active:true},CaptureRequest{secure_field_selector:"input[type=\"password\" i]".into()},operation).await.map_err(|_|"Capture task failed")?.map_err(|_|"Static protected capture failed")?;
                let rate=client.send_command("Animation.getPlaybackRate",Some(json!({})),Some(&session)).await?;
                if rate["playbackRate"].as_f64()!=Some(0.75){return Err("Animation playback was not restored".into());}
                let controls=client.send_command("Runtime.evaluate",Some(json!({"expression":"window.__maskFixture.input.value==='synthetic-mask-only' && window.__maskFixture.input.getAttribute('style')===window.__maskFixture.style","returnByValue":true})),Some(&session)).await?;
                if controls["result"]["value"]!=true{return Err("Capture changed the synthetic control".into());}
                let before=client.send_command("Runtime.evaluate",Some(json!({"expression":"Number(document.body.dataset.tick)","returnByValue":true})),Some(&session)).await?["result"]["value"].as_u64().ok_or("Missing synthetic timer")?;
                tokio::time::timeout(Duration::from_secs(3),async {
                    loop {
                        let value=client.send_command("Runtime.evaluate",Some(json!({"expression":"Number(document.body.dataset.tick)","returnByValue":true})),Some(&session)).await?;
                        if value["result"]["value"].as_u64().is_some_and(|tick|tick>before){return Ok::<(),String>(());}
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await.map_err(|_|"Synthetic timer did not resume")??;
                let pixels=image::load_from_memory(&captured.png).map_err(|_|"Masked PNG invalid")?.to_rgba8();
                if pixels.dimensions()!=(400,300){return Err("Unexpected static screenshot dimensions".into());}
                if pixels.get_pixel(25,25).0 != [0,0,0,255]{return Err("Protected pixels were not black".into());}
                if pixels.get_pixel(300,200).0 != [25,75,125,255]{return Err(if closed_shadow {"Closed-shadow masking erased public background"}else{"Password masking erased public background"}.into());}
                Ok(())
            }.await;
            drop(sender);
            let cleanup = owner.close().await;
            assert!(cleanup.is_ok(), "Static fixture context cleanup failed");
            result.unwrap();
        }
    }
}
