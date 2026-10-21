//! Exact-operation test-only races after actual screenshot acquisition. Raw
//! bytes remain private; a retired frame cannot become a returned MaskedCapture.
use super::super::client_browser::{ExecutionGate, OwnedBrowser};
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};
#[derive(Clone, Copy)]
enum Mode {
    Navigate,
    Detach,
    Deadline,
}
struct Hook {
    mode: Mode,
    reached: AtomicBool,
}
static HOOKS: OnceLock<Mutex<HashMap<u64, Arc<Hook>>>> = OnceLock::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(2_000_000);
struct Guard(u64);
impl Drop for Guard {
    fn drop(&mut self) {
        HOOKS.get().unwrap().lock().unwrap().remove(&self.0);
    }
}
pub(super) async fn after_raw_capture(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<(), CaptureReason> {
    let hook = HOOKS
        .get()
        .and_then(|m| m.lock().unwrap().get(&operation.sequence).cloned());
    let Some(hook) = hook else { return Ok(()) };
    hook.reached.store(true, Ordering::SeqCst);
    match hook.mode {
        Mode::Navigate => {
            let client = &context.page.client;
            let session = &context.page.page_session_id;
            tokio::time::timeout(Duration::from_secs(3), async {
                let before = client
                    .send_command_no_params("Page.getFrameTree", Some(session))
                    .await?;
                let old = before["frameTree"]["frame"]["loaderId"].clone();
                client
                    .send_command(
                        "Page.navigate",
                        Some(json!({"url":"data:text/html,<button>Replacement</button>"})),
                        Some(session),
                    )
                    .await?;
                loop {
                    let after = client
                        .send_command_no_params("Page.getFrameTree", Some(session))
                        .await?;
                    if after["frameTree"]["frame"]["loaderId"] != old {
                        return Ok::<(), String>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| CaptureReason::BrowserFailure)?
            .map_err(|_| CaptureReason::BrowserFailure)?;
        }
        Mode::Detach => {
            context.page.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('iframe').remove();true","returnByValue":true})),Some(&context.page.page_session_id)).await.map_err(|_|CaptureReason::BrowserFailure)?;
        }
        Mode::Deadline => {
            tokio::time::sleep_until((operation.deadline + Duration::from_millis(10)).into()).await
        }
    }
    Ok(())
}
#[tokio::test]
#[ignore = "hosted Chromium: protected screenshot retirement/no output versus deadline"]
async fn chromium_capture_retirement_races_publish_no_pixels_and_keep_typed_reason() {
    for mode in [Mode::Navigate, Mode::Detach, Mode::Deadline] {
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let page = owner.lease(gate.enter(false).unwrap()).unwrap();
        let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let hook = Arc::new(Hook {
            mode,
            reached: AtomicBool::new(false),
        });
        HOOKS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(sequence, hook.clone());
        let _guard = Guard(sequence);
        let (tx, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence,
            deadline: Instant::now()
                + Duration::from_secs(if matches!(mode, Mode::Deadline) {
                    3
                } else {
                    30
                }),
            cancellation,
        };
        let result=async {
            let setup=page.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"new Promise(resolve=>{document.body.innerHTML='<input type="password" value="synthetic-main">';const f=document.createElement('iframe');f.onload=()=>resolve(true);f.srcdoc='<input type="password" value="synthetic-child">';document.body.append(f);})"#,"awaitPromise":true,"returnByValue":true})),Some(&page.page_session_id)).await?;assert_eq!(setup["result"]["value"],true);
            let frames=super::super::client_observation::enumerate_frames(&page.client,&page.page_session_id,&HashMap::new(),&operation).await.map_err(|_|"Frame enumeration failed")?;assert_eq!(frames.len(),2);
            page.targets.acknowledge_enrollment().map_err(|_|"Fixture enrollment failed")?;
            let identity=page.identity_scope.clone();
            let outcome=start_capture(CaptureContext{page,frames,inventory_complete:true},CaptureRequest{secure_field_selector:"input[type=\"password\" i]".into()},operation).await.map_err(|_|"Retained capture task failed")?;
            let failure=match outcome{Err(error)=>error,Ok(_)=>panic!("Retired capture returned pixels")};
            assert!(hook.reached.load(Ordering::SeqCst),"Race must occur after actual screenshot, not preflight");
            assert_eq!(failure.reason,if matches!(mode,Mode::Deadline){CaptureReason::Deadline}else{CaptureReason::StaleScope});assert_eq!(failure.identity_scope,identity);Ok::<(),String>(())
        }.await;
        drop(tx);
        owner.close().await.unwrap();
        result.unwrap();
    }
}

#[test]
fn raster_png_dimensions_and_truncated_or_invalid_header_contract() {
    let image = image::RgbaImage::from_pixel(2, 2, image::Rgba([20, 40, 80, 255]));
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .unwrap();
    let bytes = encoded.into_inner();
    let viewport = Viewport {
        width: 2.,
        height: 2.,
        offset_x: 0.,
        offset_y: 0.,
        scale: 1.,
        layout_width: 2.,
        layout_height: 2.,
    };
    let proof = MaskProof {
        secure_nodes: Vec::new(),
        count: 0,
        masks: Vec::new(),
    };
    let result = raster_mask(&bytes, viewport, &proof, "png-fixture").unwrap();
    assert_eq!((result.width, result.height), (2, 2));
    let decoded = image::load_from_memory(&result.png).unwrap().to_rgba8();
    assert_eq!(decoded.dimensions(), (2, 2));
    assert_eq!(decoded.get_pixel(1, 1).0, [20, 40, 80, 255]);
    assert!(raster_mask(&bytes[..20], viewport, &proof, "png-fixture").is_err());
    assert!(raster_mask(&[0; 64], viewport, &proof, "png-fixture").is_err());
}
