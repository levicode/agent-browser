//! Producer-private semantic geometry authority. Policy/budget omission is not
//! evidence of hidden content and never grants pixel or action geometry access.
use super::frame_policy::{DocumentCapture, FrameTraversal, Omission};
use super::*;
use std::collections::HashSet;

#[derive(Clone, Debug, Default)]
pub(crate) struct SemanticFrameProof {
    // The genuine hidden proof already pins the *complete* inventory, even
    // with no hidden frames. Reuse it instead of copying potentially long URLs.
    hidden: HiddenFrameProof,
    policy: ObservationFramePolicy,
    records: Vec<DocumentCapture>,
    omissions: HashMap<String, Omission>,
    excluded: HashSet<String>,
    identity_scope: String,
    revision: u64,
    generation: u64,
    sequence: u64,
    cancellation: Option<tokio::sync::watch::Receiver<CancelSignal>>,
    max_nodes: usize,
}
impl SemanticFrameProof {
    pub(super) fn new(
        frames: &[ObservationFrame],
        traversal: &FrameTraversal<'_>,
        options: &ObservationOptions,
        identity_scope: &str,
        revision: u64,
        lease: &OperationLease,
    ) -> Result<Self, ObservationError> {
        let hidden_frames = traversal
            .omissions
            .iter()
            .filter(|(_, reason)| **reason == Omission::Hidden)
            .map(|(id, _)| id.clone())
            .collect();
        let hidden =
            HiddenFrameProof::new(frames, &traversal.hidden_owners(), hidden_frames, options)?;
        let proof = Self {
            hidden,
            policy: options.frame_policy.clone(),
            records: traversal.records.clone(),
            omissions: traversal.omissions.clone(),
            excluded: traversal.omissions.keys().cloned().collect(),
            identity_scope: identity_scope.into(),
            revision,
            generation: lease.generation,
            sequence: lease.sequence,
            cancellation: Some(lease.cancellation.clone()),
            max_nodes: options.max_nodes,
        };
        proof.validate_context(
            frames,
            &options.frame_policy,
            identity_scope,
            revision,
            lease,
        )?;
        Ok(proof)
    }
    pub(crate) fn excluded_frames(&self) -> &HashSet<String> {
        &self.excluded
    }
    pub(crate) fn validate_context(
        &self,
        frames: &[ObservationFrame],
        policy: &ObservationFramePolicy,
        identity_scope: &str,
        revision: u64,
        lease: &OperationLease,
    ) -> Result<(), ObservationError> {
        if policy != &self.policy
            || identity_scope != self.identity_scope
            || revision != self.revision
            || lease.generation != self.generation
            || lease.sequence != self.sequence
            || self
                .cancellation
                .as_ref()
                .is_none_or(|owner| !owner.same_channel(&lease.cancellation))
        {
            return Err(ObservationError::StaleReference);
        }
        self.hidden.validate_inventory(frames)?;
        for expected in &self.hidden.inventory {
            let actual = frames
                .iter()
                .find(|frame| frame.binding.frame == expected.binding.frame)
                .ok_or(ObservationError::StaleReference)?;
            if actual.binding != expected.binding
                || actual.parent_frame_id != expected.parent_frame_id
                || actual.owner_backend_id != expected.owner_backend_id
                || actual.url != expected.url
            {
                return Err(ObservationError::StaleReference);
            }
        }
        let mut replay = FrameTraversal::new(frames, policy, self.max_nodes)?;
        for record in &self.records {
            if replay
                .next()?
                .is_none_or(|frame| frame.binding.frame != record.frame)
            {
                return Err(ObservationError::BackendFailure);
            }
            replay.record(record.clone())?;
        }
        if replay.next()?.is_some()
            || replay.omissions != self.omissions
            || self.excluded != self.omissions.keys().cloned().collect()
            || self.hidden.excluded_frames()
                != &self
                    .omissions
                    .iter()
                    .filter(|(_, reason)| **reason == Omission::Hidden)
                    .map(|(id, _)| id.clone())
                    .collect::<HashSet<_>>()
        {
            return Err(ObservationError::BackendFailure);
        }
        Ok(())
    }
    /// Used with the *already acquired* native tree in semantic geometry.
    /// A URL change can alter site policy without replacing the loader. Strict
    /// pixel/action geometry does not use this observation-only predicate.
    pub(crate) fn validate_frame_url(
        &self,
        binding: &ExactBinding,
        url: Option<&str>,
    ) -> Result<(), ObservationError> {
        let expected = self
            .hidden
            .inventory
            .iter()
            .find(|frame| frame.binding.frame == binding.frame)
            .ok_or(ObservationError::StaleReference)?;
        if expected.binding != *binding {
            return Err(ObservationError::StaleReference);
        }
        validate_semantic_frame_url(&expected.url, url)
    }
    pub(crate) async fn revalidate(
        &self,
        client: &CdpClient,
        lease: &OperationLease,
    ) -> Result<(), ObservationError> {
        check(lease)?;
        self.validate_context(
            &self.hidden.inventory,
            &self.policy,
            &self.identity_scope,
            self.revision,
            lease,
        )?;
        self.hidden.revalidate(client, lease).await?;
        check(lease)
    }
    #[cfg(test)]
    pub(crate) fn for_test(
        frames: &[ObservationFrame],
        children: &[&str],
        identity_scope: &str,
        revision: u64,
        lease: &OperationLease,
    ) -> Self {
        let options = ObservationOptions::default();
        let hidden = HiddenFrameProof::for_test(frames, children);
        let mut traversal =
            FrameTraversal::new(frames, &options.frame_policy, options.max_nodes).unwrap();
        while let Some(frame) = traversal.next().unwrap() {
            let direct: Vec<_> = frames
                .iter()
                .filter(|child| child.parent_frame_id.as_ref() == Some(&frame.binding.frame))
                .collect();
            traversal
                .record(DocumentCapture {
                    frame: frame.binding.frame.clone(),
                    node_count: 1 + direct
                        .iter()
                        .filter(|child| !hidden.excluded_frames().contains(&child.binding.frame))
                        .count(),
                    truncated: false,
                    emitted_owners: direct
                        .iter()
                        .filter(|child| !hidden.excluded_frames().contains(&child.binding.frame))
                        .map(|child| child.owner_backend_id.unwrap())
                        .collect(),
                    hidden_owners: direct
                        .iter()
                        .filter(|child| hidden.excluded_frames().contains(&child.binding.frame))
                        .map(|child| child.owner_backend_id.unwrap())
                        .collect(),
                })
                .unwrap();
        }
        Self::new(
            frames,
            &traversal,
            &options,
            identity_scope,
            revision,
            lease,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> Vec<ObservationFrame> {
        let root = ObservationFrame {
            parent_frame_id: None,
            owner_backend_id: None,
            url: "https://main.invalid/".into(),
            binding: ExactBinding {
                page_session: "page".into(),
                session: "page".into(),
                frame: "main".into(),
                loader: "main-doc".into(),
                actionable: false,
            },
            offset_x: 0.,
            offset_y: 0.,
            frame_path: vec![],
        };
        let mut child = root.clone();
        child.binding.frame = "ad".into();
        child.binding.loader = "ad-doc".into();
        child.parent_frame_id = Some("main".into());
        child.owner_backend_id = Some(2);
        child.url = "data:text/html,Ad".into();
        let mut nested = child.clone();
        nested.binding.frame = "nested".into();
        nested.binding.loader = "nested-doc".into();
        nested.parent_frame_id = Some("ad".into());
        nested.owner_backend_id = Some(3);
        nested.url = "about:srcdoc".into();
        vec![root, child, nested]
    }
    fn operation() -> (OperationLease, tokio::sync::watch::Sender<CancelSignal>) {
        let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        (
            OperationLease {
                is_callback: false,
                generation: 11,
                sequence: 12,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
                cancellation,
            },
            sender,
        )
    }
    fn proof(frames: &[ObservationFrame], lease: &OperationLease) -> SemanticFrameProof {
        let options = ObservationOptions {
            max_nodes: 3,
            ..Default::default()
        };
        let mut traversal =
            FrameTraversal::new(frames, &options.frame_policy, options.max_nodes).unwrap();
        assert_eq!(traversal.next().unwrap().unwrap().binding.frame, "main");
        traversal
            .record(DocumentCapture {
                frame: "main".into(),
                node_count: 3,
                truncated: false,
                emitted_owners: vec![2],
                hidden_owners: HashSet::new(),
            })
            .unwrap();
        assert!(traversal.next().unwrap().is_none());
        SemanticFrameProof::new(frames, &traversal, &options, "scope", 13, lease).unwrap()
    }
    #[test]
    fn semantic_proof_rejects_other_owner_stale_url_policy_and_capture_revision() {
        let frames = fixtures();
        let (mut lease, _cancel) = operation();
        let proof = proof(&frames, &lease);
        let policy = ObservationFramePolicy::default();
        proof
            .validate_context(&frames, &policy, "scope", 13, &lease)
            .unwrap();
        for frame in &frames {
            proof
                .validate_frame_url(&frame.binding, Some(&frame.url))
                .unwrap();
            assert_eq!(
                proof.validate_frame_url(&frame.binding, Some("https://changed.invalid/")),
                Err(ObservationError::StaleReference)
            );
            assert_eq!(
                proof.validate_frame_url(&frame.binding, None),
                Err(ObservationError::BackendFailure)
            );
            let mut other = frame.binding.clone();
            other.session = "other-owner".into();
            assert_eq!(
                proof.validate_frame_url(&other, Some(&frame.url)),
                Err(ObservationError::StaleReference)
            );
        }
        assert!(
            proof.hidden.excluded_frames().is_empty(),
            "policy omission must not forge hidden evidence"
        );
        assert_eq!(
            proof.excluded_frames(),
            &HashSet::from(["ad".into(), "nested".into()])
        );
        for field in ["page", "session", "loader", "owner", "parent", "url"] {
            let mut changed = frames.clone();
            match field {
                "page" => changed[1].binding.page_session = "other-owner".into(),
                "session" => changed[1].binding.session = "other-renderer".into(),
                "loader" => changed[1].binding.loader = "replaced".into(),
                "owner" => changed[1].owner_backend_id = Some(99),
                "parent" => changed[2].parent_frame_id = Some("main".into()),
                _ => changed[1].url = "about:srcdoc".into(),
            }
            assert!(
                proof
                    .validate_context(&changed, &policy, "scope", 13, &lease)
                    .is_err(),
                "{field}"
            );
        }
        assert!(proof
            .validate_context(&frames[..2], &policy, "scope", 13, &lease)
            .is_err());
        assert!(proof
            .validate_context(
                &frames,
                &ObservationFramePolicy::configured(Some("main.invalid".into())),
                "scope",
                13,
                &lease
            )
            .is_err());
        assert!(proof
            .validate_context(&frames, &policy, "other-scope", 13, &lease)
            .is_err());
        assert!(proof
            .validate_context(&frames, &policy, "scope", 14, &lease)
            .is_err());
        let (other_owner, _other_cancel) = operation();
        assert!(proof
            .validate_context(&frames, &policy, "scope", 13, &other_owner)
            .is_err());
        lease.sequence += 1;
        assert!(proof
            .validate_context(&frames, &policy, "scope", 13, &lease)
            .is_err());
        lease.sequence -= 1;
        lease.generation += 1;
        assert!(proof
            .validate_context(&frames, &policy, "scope", 13, &lease)
            .is_err());
    }
    #[test]
    fn semantic_proof_replay_rejects_forged_hidden_budget_closure_and_emitted_omission() {
        let frames = fixtures();
        let (lease, _cancel) = operation();
        let original = proof(&frames, &lease);
        let policy = ObservationFramePolicy::default();
        for mutation in 0..8 {
            let mut forged = original.clone();
            match mutation {
                0 => {
                    forged.excluded.insert("main".into());
                }
                1 => {
                    forged.omissions.remove("nested");
                    forged.excluded.remove("nested");
                }
                2 => {
                    forged.omissions.insert("ad".into(), Omission::Hidden);
                }
                3 => {
                    forged.omissions.insert("ad".into(), Omission::Budget);
                }
                4 => {
                    forged.records[0].emitted_owners = vec![99];
                }
                5 => {
                    forged.records.push(DocumentCapture {
                        frame: "ad".into(),
                        node_count: 1,
                        truncated: false,
                        emitted_owners: vec![],
                        hidden_owners: HashSet::new(),
                    });
                }
                6 => {
                    forged.records[0].node_count = 4;
                }
                _ => {
                    forged.records[0].frame = "ad".into();
                }
            }
            assert!(
                forged
                    .validate_context(&frames, &policy, "scope", 13, &lease)
                    .is_err(),
                "mutation {mutation}"
            );
        }
        assert!(SemanticFrameProof::default()
            .validate_context(&frames, &policy, "scope", 13, &lease)
            .is_err());
    }
    #[test]
    fn missing_native_url_never_inherits_the_real_empty_url_exception() {
        validate_semantic_frame_url("", Some("")).unwrap();
        for missing in [Value::Null, json!(false), json!(123), json!({})] {
            assert_eq!(
                validate_semantic_frame_url("", missing.as_str()),
                Err(ObservationError::BackendFailure)
            );
        }
        assert_eq!(
            validate_semantic_frame_url("", Some("about:srcdoc")),
            Err(ObservationError::StaleReference)
        );
    }
    #[test]
    fn frame_policy_is_not_an_observe_wire_override() {
        for field in [
            "framePolicy",
            "appSite",
            "site",
            "maxFrameDepth",
            "omittedFrames",
            "semanticFrameProof",
        ] {
            let value = json!({field: {"appSite":"other.invalid"}});
            assert!(
                serde_json::from_value::<ObservationOptions>(value).is_err(),
                "{field}"
            );
        }
        let options: ObservationOptions = serde_json::from_value(json!({})).unwrap();
        assert_eq!(options.frame_policy, ObservationFramePolicy::default());
    }
}
