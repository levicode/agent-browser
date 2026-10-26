// Real CDP reader/writer and real ffmpeg proofs for the recording component.
// No RecordingState, segment bytes, encoder join, or frame count is seeded.
// These are not ClientBrowser restart or renderer screenshot-fidelity proofs.
use super::*;
use base64::Engine as _;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy)]
enum Mode {
    Silent,
    DelayedInitialImage,
    RejectScreencastStart,
}
struct WireFixture {
    pages: [BrowserExecutionLease; 2],
    states: [ClientPageState; 2],
    geometry: [GeometrySnapshot; 2],
    refs: RefMap,
    frames: HashMap<String, String>,
    blobs: BlobStore,
    owner: Arc<client_debt::OwnerDebtLedger>,
    deadline: Instant,
    cancel: tokio::sync::watch::Sender<CancelSignal>,
    requests: Log,
    replies: Log,
    image_reached: Option<oneshot::Receiver<()>>,
    image_release: Option<oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}
fn jpeg(width: u32, height: u32) -> String {
    let image = image::RgbImage::from_pixel(width, height, image::Rgb([20, 40, 80]));
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image)
        .write_to(&mut bytes, image::ImageFormat::Jpeg)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes.into_inner())
}
impl WireFixture {
    async fn new(mode: Mode) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let requests: Log = Default::default();
        let replies: Log = Default::default();
        let seen = requests.clone();
        let acknowledged = replies.clone();
        let images = [jpeg(320, 200), jpeg(390, 600)];
        let (image_seen, image_reached) = oneshot::channel();
        let (image_release, release_image) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut image_seen = Some(image_seen);
            let mut release_image = Some(release_image);
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                seen.lock().unwrap().push(request.clone());
                let second = request["sessionId"] == "page2";
                let (width, height) = if second { (390, 600) } else { (320, 200) };
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => json!({"frameTree":{"frame":{
                        "id":if second {"frame2"} else {"frame1"},"loaderId":"document","url":"about:blank"}}}),
                    "Page.getLayoutMetrics" => json!({
                        "cssLayoutViewport":{"clientWidth":width,"clientHeight":height},
                        "cssVisualViewport":{"clientWidth":width,"clientHeight":height,"offsetX":0,"offsetY":0,"scale":1}}),
                    "Runtime.evaluate" => {
                        assert_eq!(
                            request["params"]["expression"],
                            "[window.innerWidth, window.innerHeight]"
                        );
                        json!({"result":{"value":[width,height]}})
                    }
                    "Page.captureScreenshot" => {
                        assert_eq!(request["params"]["format"], "jpeg");
                        if matches!(mode, Mode::DelayedInitialImage) {
                            if let Some(reached) = image_seen.take() {
                                reached.send(()).unwrap();
                                release_image.take().unwrap().await.unwrap();
                            }
                        }
                        json!({"data":images[usize::from(second)]})
                    }
                    "Target.attachToTarget" => {
                        assert_eq!(request["params"]["flatten"], true);
                        let target = request["params"]["targetId"].as_str().unwrap();
                        assert!(matches!(target, "target1" | "target2"));
                        json!({"sessionId":if target=="target1" {"capture1"} else {"capture2"}})
                    }
                    "Page.startScreencast" | "Page.stopScreencast" => {
                        assert!(matches!(
                            request["sessionId"].as_str(),
                            Some("capture1" | "capture2")
                        ));
                        json!({})
                    }
                    "Target.detachFromTarget" => {
                        assert!(matches!(
                            request["params"]["sessionId"].as_str(),
                            Some("capture1" | "capture2")
                        ));
                        json!({})
                    }
                    method => panic!("unexpected recording fixture request: {method}"),
                };
                let mut reply = if matches!(mode, Mode::RejectScreencastStart)
                    && request["method"] == "Page.startScreencast"
                {
                    json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic screencast start refusal"}})
                } else {
                    json!({"id":request["id"],"result":result})
                };
                if let Some(session) = request.get("sessionId") {
                    reply["sessionId"] = session.clone();
                }
                if socket.send(Message::Text(reply.to_string())).await.is_err() {
                    break;
                }
                acknowledged
                    .lock()
                    .unwrap()
                    .push(json!({"request":request,"reply":reply}));
                // Deliberately never emit Page.screencastFrame: all positive
                // output must come from the actual initial-image producer.
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let gate = Arc::new(ExecutionGate::default());
        let targets = ClientTargets::new("recording-context".into(), "recording-wire".into());
        let mut pages = [1, 2].map(|n| BrowserExecutionLease {
            client: client.clone(),
            page_session_id: format!("page{n}"),
            target_id: format!("target{n}"),
            identity_scope: "recording-wire".into(),
            permit: gate.enter(false).unwrap(),
            targets: targets.clone(),
        });
        for page in &pages {
            enroll_recording_fixture(page).await;
        }
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let deadline = Instant::now() + Duration::from_secs(30);
        let setup = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline,
            cancellation,
        };
        let mut captures = Vec::new();
        for (index, page) in pages.iter().enumerate() {
            let frames = [super::super::super::client_observation::ObservationFrame {
                parent_frame_id: None,
                owner_backend_id: None,
                url: "about:blank".into(),
                binding: ExactBinding {
                    page_session: page.page_session_id.clone(),
                    session: page.page_session_id.clone(),
                    frame: format!("frame{}", index + 1),
                    loader: "document".into(),
                    actionable: true,
                },
                offset_x: 0.,
                offset_y: 0.,
                frame_path: vec![],
            }];
            captures.push(
                GeometrySnapshot::capture(&client, &page.page_session_id, &frames, &setup)
                    .await
                    .unwrap(),
            );
        }
        let geometry: [GeometrySnapshot; 2] = captures.try_into().ok().unwrap();
        let owner = client_debt::OwnerDebtLedger::new(1, "recording-wire".into());
        owner.bind_context("recording-context").unwrap();
        for page in &pages {
            owner
                .bind_session("recording-context", &page.target_id, &page.page_session_id)
                .unwrap();
        }
        targets.bind_eval_owner(&owner, 1).unwrap();
        client.install_debt_ledger(owner.clone()).unwrap();
        let view = client.owner_view(owner.clone()).unwrap();
        for page in &mut pages {
            page.client = view.clone();
        }
        let limits = if matches!(mode, Mode::RejectScreencastStart) {
            // One full-budget producer exposes a retained failed-start charge.
            BlobLimits {
                max_blob_bytes: 4 * 1024 * 1024,
                max_total_bytes: 4 * 1024 * 1024,
                max_handles: 1,
            }
        } else {
            BlobLimits::default()
        };
        let blobs = BlobStore::new(limits).unwrap();
        blobs
            .activate_scope(BlobScope {
                generation: 1,
                identity_scope: "recording-wire".into(),
            })
            .unwrap();
        let states = [1, 2]
            .map(|_| ClientPageState::new("recording-wire".into(), "recording-context".into()));
        Self {
            pages,
            states,
            geometry,
            refs: RefMap::new(),
            frames: HashMap::new(),
            blobs,
            owner,
            deadline,
            cancel,
            requests,
            replies,
            image_reached: Some(image_reached),
            image_release: Some(image_release),
            server,
        }
    }
    fn operation(&self, sequence: u64) -> OperationLease {
        OperationLease {
            is_callback: false,
            generation: 1,
            sequence,
            deadline: self.deadline,
            cancellation: self.cancel.subscribe(),
        }
    }
    fn journal(&self, page: usize, op: &OperationLease) -> OperationJournalHandle {
        let journal = self
            .owner
            .operation(
                client_debt::OperationKey {
                    generation: 1,
                    operation_seq: op.sequence,
                },
                self.pages[page].target_id.clone(),
                self.pages[page].page_session_id.clone(),
            )
            .unwrap();
        journal.bind_operation(op).unwrap();
        journal
    }
    fn context<'a>(&'a self, page: usize, operation: &'a OperationLease) -> ActionContext<'a> {
        ActionContext {
            realm_authority: ActionRealmAuthority::UntrackedFixture,
            page: &self.pages[page],
            operation,
            page_state: &self.states[page],
            refs: &self.refs,
            revision: 1,
            observation_after: None,
            observed_revision: 0,
            iframe_sessions: &self.frames,
            observation_frames: &[],
            blobs: &self.blobs,
            geometry: &self.geometry[page],
        }
    }
    fn count(&self, method: &str, session: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| {
                request["method"] == method
                    && if method == "Target.detachFromTarget" {
                        request["params"]["sessionId"] == session
                    } else {
                        request["sessionId"] == session
                    }
            })
            .count()
    }
    fn clean(&self) -> bool {
        let debt = self.owner.snapshot();
        debt.outstanding_commands == 0
            && debt.input_debt == 0
            && debt.object_debt == 0
            && !debt.integrity_lost
            && self.pages[0].targets.auxiliary_cleanup_complete() == Ok(true)
    }
    async fn close(self) {
        self.pages[0].client.close().await;
        self.server.abort();
    }
}
fn action_error(error: ActionFailure) -> String {
    format!(
        "recording {:?}/{:?}/cleanup={}",
        error.error, error.effects, error.cleanup_failed
    )
}
async fn decoded_segment(f: &WireFixture, segment: &Value, size: (u32, u32)) -> Result<(), String> {
    let scope = BlobScope {
        generation: 1,
        identity_scope: "recording-wire".into(),
    };
    let handle = segment["handle"]
        .as_str()
        .ok_or("missing recording handle")?;
    let length = segment["size"].as_u64().ok_or("missing recording size")? as usize;
    let mut bytes = Vec::new();
    while bytes.len() < length {
        bytes.extend(
            f.blobs
                .read(
                    &scope,
                    handle,
                    bytes.len(),
                    (length - bytes.len()).min(super::super::super::client_blobs::MAX_CHUNK_BYTES),
                )
                .map_err(|_| "blob read")?,
        );
    }
    f.blobs
        .release(&scope, handle)
        .map_err(|_| "blob release")?;
    let directory = OwnedDirectory::create().map_err(|_| "decode directory")?;
    let result = async {
        let video = directory.path.join("recording.webm");
        let image = directory.path.join("first.png");
        tokio::fs::write(&video, &bytes)
            .await
            .map_err(|_| "video write")?;
        let probe = tokio::process::Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=codec_name,width,height",
                "-of",
                "json",
            ])
            .arg(&video)
            .output()
            .await
            .map_err(|_| "ffprobe required")?;
        if !probe.status.success() {
            return Err("ffprobe did not decode owned segment".into());
        }
        let facts: Value = serde_json::from_slice(&probe.stdout).map_err(|_| "ffprobe JSON")?;
        if facts["streams"][0]["codec_name"] != "vp8"
            || facts["streams"][0]["width"] != size.0
            || facts["streams"][0]["height"] != size.1
        {
            return Err(format!("wrong encoded size: {facts}"));
        }
        let decoded = tokio::process::Command::new("ffmpeg")
            .args(["-v", "error", "-i"])
            .arg(&video)
            .args(["-frames:v", "1"])
            .arg(&image)
            .output()
            .await
            .map_err(|_| "ffmpeg required")?;
        if !decoded.status.success() {
            return Err("owned first frame did not decode".into());
        }
        let image = image::open(&image).map_err(|_| "decoded PNG")?.to_rgb8();
        if image.dimensions() != size
            || image
                .get_pixel(size.0 / 2, size.1 / 2)
                .0
                .into_iter()
                .zip([20u8, 40, 80])
                .any(|(actual, expected)| actual.abs_diff(expected) >= 20)
        {
            return Err("first frame was blank or changed dimensions".into());
        }
        Ok::<(), String>(())
    }
    .await;
    directory.close().map_err(|_| "decode directory cleanup")?;
    result
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe: owner-bound CDP initial-frame delay, silent capture, bounded stop and decoded output"]
async fn recording_delayed_initial_frame_precedes_ready_and_silent_stop_is_bounded() {
    let mut f = WireFixture::new(Mode::DelayedInitialImage).await;
    let reached = f.image_reached.take().unwrap();
    let release = f.image_release.take().unwrap();
    let actions = ClientActions::default();
    let result=async {
        let op=f.operation(2); let journal=f.journal(0,&op);
        let args=json!({"identityScope":"recording-wire"});
        let start=journal.scope(actions.execute(f.context(0,&op),"recording.start",&args)); tokio::pin!(start);
        tokio::select! { result=&mut start => return Err(format!("start settled before held screenshot: {:?}",result.map(|_|()).map_err(action_error))),
            entered=reached => entered.map_err(|_|"initial image never requested")? }
        let held=Instant::now();
        tokio::select! { result=&mut start => return Err(format!("start settled without initial image ACK: {:?}",result.map(|_|()).map_err(action_error))),
            _=tokio::time::sleep(Duration::from_millis(150)) => {} }
        release.send(()).map_err(|_|"initial frame owner disappeared")?;
        start.await.map_err(action_error)?;
        if held.elapsed()<Duration::from_millis(140) {return Err("initial frame wait was bypassed".into());}
        let (encoder,cleanup)= {
            let ledger=actions.recording.lock().await; let current=ledger.current.as_ref().ok_or("missing live recording")?;
            if !ledger.armed || current.state.shared_captured_count.as_ref().ok_or("missing capture counter")?.load(Ordering::Relaxed)!=1 {
                return Err("start did not retain the real initial frame".into());
            }
            (current.state.encoder_complete.clone(),current.cleanup_complete.clone())
        };
        let stop_op=f.operation(3);let stop_journal=f.journal(0,&stop_op);let stopping=Instant::now();
        let output=stop_journal.scope(actions.execute(f.context(0,&stop_op),"recording.stop",&args)).await.map_err(action_error)?;
        if stopping.elapsed()>=Duration::from_secs(3) {return Err("silent capture stop exceeded original public upper bound".into());}
        let segments=output["segments"].as_array().ok_or("missing segments")?;
        if segments.len()!=1 || !encoder.load(Ordering::SeqCst) || !cleanup.load(Ordering::SeqCst) || !f.clean()
            || f.count("Page.startScreencast","capture1")!=1 || f.count("Page.stopScreencast","capture1")!=1 || f.count("Target.detachFromTarget","capture1")!=1 {
            return Err("silent capture did not close its exact encoder/session once".into());
        }
        decoded_segment(&f,&segments[0],(320,200)).await
    }.await;
    let cleanup = actions.cleanup().await;
    f.close().await;
    assert_eq!(cleanup, Ok(()));
    result.unwrap();
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe: real pageOpened dimensions and two exact owned segment lifetimes"]
async fn recording_page_opened_remeasures_second_viewport_and_stops_each_capture_once() {
    let f = WireFixture::new(Mode::Silent).await;
    let actions = ClientActions::default();
    let result: Result<(), String> = async {
        let args = json!({"identityScope":"recording-wire"});
        let first = f.operation(2);
        let journal = f.journal(0, &first);
        journal
            .scope(actions.execute(f.context(0, &first), "recording.start", &args))
            .await
            .map_err(action_error)?;
        let closing = f.operation(3);
        let journal = f.journal(0, &closing);
        journal
            .scope(actions.recording_page_closing("recording-wire", &f.blobs))
            .await
            .map_err(|e| format!("page close {e:?}"))?;
        if !actions
            .is_recording_armed()
            .await
            .map_err(|e| format!("armed {e:?}"))?
            || !f.clean()
            || f.count("Page.stopScreencast", "capture1") != 1
        {
            return Err("first segment not settled before actual pageOpened".into());
        }
        let second = f.operation(4);
        let journal = f.journal(1, &second);
        journal
            .scope(actions.recording_page_opened(f.context(1, &second)))
            .await
            .map_err(action_error)?;
        let stop = f.operation(5);
        let journal = f.journal(1, &stop);
        let output = journal
            .scope(actions.execute(f.context(1, &stop), "recording.stop", &args))
            .await
            .map_err(action_error)?;
        let segments = output["segments"].as_array().ok_or("missing segments")?;
        if segments.len() != 2
            || actions
                .is_recording_armed()
                .await
                .map_err(|e| format!("armed {e:?}"))?
            || !f.clean()
        {
            return Err("two-segment recording did not settle".into());
        }
        let times = segments
            .iter()
            .map(|segment| {
                chrono::DateTime::parse_from_rfc3339(
                    segment["startedAt"]
                        .as_str()
                        .ok_or("missing start instant")?,
                )
                .map_err(|_| "invalid start instant")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if times[0] > times[1] {
            return Err("segment start order reversed".into());
        }
        for (index, size) in [(0, (320, 200)), (1, (390, 600))] {
            let session = format!("capture{}", index + 1);
            if f.count("Page.startScreencast", &session) != 1
                || f.count("Page.stopScreencast", &session) != 1
                || f.count("Target.detachFromTarget", &session) != 1
            {
                return Err("capture was replayed or stopped twice".into());
            }
            let requests = f.requests.lock().unwrap();
            let start = requests
                .iter()
                .find(|request| {
                    request["method"] == "Page.startScreencast" && request["sessionId"] == session
                })
                .ok_or("missing capture start")?;
            if start["params"]["maxWidth"] != size.0 || start["params"]["maxHeight"] != size.1 {
                return Err("pageOpened retained old viewport size".into());
            }
            drop(requests);
            decoded_segment(&f, &segments[index], size).await?;
        }
        let request_count = f.requests.lock().unwrap().len();
        let empty = f.operation(6);
        let journal = f.journal(1, &empty);
        if journal
            .scope(actions.execute(f.context(1, &empty), "recording.stop", &args))
            .await
            .map_err(action_error)?["segments"]
            != json!([])
        {
            return Err("segments published twice".into());
        }
        if f.requests.lock().unwrap().len() != request_count {
            return Err("empty collection dispatched another stop".into());
        }
        Ok(())
    }
    .await;
    let cleanup = actions.cleanup().await;
    f.close().await;
    assert_eq!(cleanup, Ok(()));
    result.unwrap();
}

#[tokio::test]
#[ignore = "hosted ffmpeg: actual screencast-start error after initial frame and owned encoder; no preflight substitution"]
async fn recording_real_screencast_start_error_disarms_and_joins_without_late_segment() {
    let f = WireFixture::new(Mode::RejectScreencastStart).await;
    let actions = ClientActions::default();
    let result = async {
        let args = json!({"identityScope":"recording-wire"});
        let op = f.operation(2);
        let journal = f.journal(0, &op);
        let failure = journal
            .scope(actions.execute(f.context(0, &op), "recording.start", &args))
            .await
            .err()
            .ok_or("actual screencast refusal unexpectedly succeeded")?;
        if failure.error != ProtocolError::BrowserFailure
            || failure.effects != Effects::Unknown
            || failure.cleanup_failed
            || !journal.snapshot().mutation_dispatched
            || !f.clean()
        {
            return Err(format!(
                "wrong failed-start classification: {}",
                action_error(failure)
            ));
        }
        let requests = f.requests.lock().unwrap().clone();
        let expected = [
            "Page.captureScreenshot",
            "Target.attachToTarget",
            "Page.startScreencast",
            "Page.stopScreencast",
            "Target.detachFromTarget",
        ];
        let actual: Vec<_> = requests
            .iter()
            .filter_map(|r| r["method"].as_str().filter(|m| expected.contains(m)))
            .collect();
        if actual != expected
            || !f.replies.lock().unwrap().iter().any(|entry| {
                entry["request"]["method"] == "Page.startScreencast"
                    && entry["reply"]["sessionId"] == "capture1"
                    && entry["reply"]["error"]["code"] == -32000
            })
        {
            return Err("failure did not reach the actual start RPC and exact cleanup".into());
        }
        {
            let ledger = actions.recording.lock().await;
            if ledger.armed
                || ledger.current.is_some()
                || !ledger.finished.is_empty()
                || ledger.ordinal != 1
                || ledger.cleanup_failed
                || ledger.lost.is_some()
            {
                return Err("failed real start retained an armed or publishable segment".into());
            }
        }
        let late = f.operation(3);
        let journal = f.journal(1, &late);
        journal
            .scope(actions.recording_page_opened(f.context(1, &late)))
            .await
            .map_err(action_error)?;
        let stop = f.operation(4);
        let journal = f.journal(1, &stop);
        if journal
            .scope(actions.execute(f.context(1, &stop), "recording.stop", &args))
            .await
            .map_err(action_error)?["segments"]
            != json!([])
            || *f.requests.lock().unwrap() != requests
            || actions
                .is_recording_armed()
                .await
                .map_err(|e| format!("armed {e:?}"))?
        {
            return Err("late pageOpened/stop restarted or published the failed segment".into());
        }
        f.blobs
            .check_budget_integrity()
            .map_err(|_| "failed-start budget integrity")?;
        drop(
            f.blobs
                .reserve_producer(BlobScope {
                    generation: 1,
                    identity_scope: "recording-wire".into(),
                })
                .map_err(|_| "failed start retained producer reservation")?,
        );
        Ok(())
    }
    .await;
    let cleanup = actions.cleanup().await;
    f.close().await;
    assert_eq!(cleanup, Ok(()));
    result.unwrap();
}
