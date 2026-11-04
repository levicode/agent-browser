//! The legacy app-site rule applies only to automatic semantic observations.
//! It is not a navigation, explicit query, pixel, or target-enrollment policy.
use super::{observation_frame_order, query_root, ObservationError, ObservationFrame};
use std::collections::{HashMap, HashSet};

pub(super) const MAX_FRAME_DEPTH: usize = 4;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ObservationFramePolicy {
    app_site: Option<String>,
}
impl ObservationFramePolicy {
    /// `site` is the already configured siteOf(hostname), not an origin/URL.
    /// None is deliberately not allow-all; blank/srcdoc children still qualify.
    pub(crate) fn configured(site: Option<String>) -> Self {
        Self { app_site: site }
    }
    fn admits(&self, value: &str) -> bool {
        if matches!(value, "" | "about:blank" | "about:srcdoc") {
            return true;
        }
        let Some(site) = &self.app_site else {
            return false;
        };
        let Ok(parsed) = url::Url::parse(value) else {
            return false;
        };
        parsed.scheme() != "data" && site_of(parsed.host_str().unwrap_or("")) == *site
    }
}

// Exact port of internal/urls.ts siteOf: intentionally not a PSL/suffix rule.
fn site_of(hostname: &str) -> String {
    let host = hostname.to_lowercase();
    let labels: Vec<_> = host.split('.').collect();
    let ipv4 = labels.len() == 4
        && labels.iter().all(|label| {
            (1..=3).contains(&label.len()) && label.bytes().all(|byte| byte.is_ascii_digit())
        });
    if host.starts_with('[') || ipv4 || labels.len() <= 2 {
        return host;
    }
    let last = labels[labels.len() - 1].encode_utf16().count();
    let second = labels[labels.len() - 2].encode_utf16().count();
    let keep = if last == 2 && second <= 3 { 3 } else { 2 };
    labels[labels.len() - keep..].join(".")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Omission {
    Hidden,
    Policy,
    Depth,
    Budget,
    // Parent projection exhausted its own budget before emitting this owner.
    BoundaryBudget,
}

/// Facts from one successful real document projection, before child joins.
/// Only the producer creates these; no renderer/wire omission list is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DocumentCapture {
    pub frame: String,
    pub node_count: usize,
    pub truncated: bool,
    pub emitted_owners: Vec<i64>,
    pub hidden_owners: HashSet<i64>,
}

/// Shared deterministic traversal and proof replay. Each document is projected
/// first, then its emitted child owners are visited depth first in tree order.
/// The complete native inventory is retained even for omitted documents.
#[derive(Debug)]
pub(super) struct FrameTraversal<'a> {
    frames: &'a [ObservationFrame],
    policy: &'a ObservationFramePolicy,
    pending: Vec<(&'a ObservationFrame, usize)>,
    active: Option<(&'a ObservationFrame, usize)>,
    pub omissions: HashMap<String, Omission>,
    pub records: Vec<DocumentCapture>,
    pub count: usize,
    pub truncated: bool,
    max_nodes: usize,
}
impl<'a> FrameTraversal<'a> {
    pub fn new(
        frames: &'a [ObservationFrame],
        policy: &'a ObservationFramePolicy,
        max_nodes: usize,
    ) -> Result<Self, ObservationError> {
        observation_frame_order(frames)?;
        let root = query_root(frames)?;
        if max_nodes == 0 || max_nodes > 100_000 {
            return Err(ObservationError::InvalidArguments);
        }
        let mut owners = HashSet::new();
        for frame in frames {
            if frame.binding.page_session != root.binding.page_session {
                return Err(ObservationError::StaleReference);
            }
            if let Some(parent) = &frame.parent_frame_id {
                let owner = frame
                    .owner_backend_id
                    .filter(|owner| *owner > 0)
                    .ok_or(ObservationError::BackendFailure)?;
                if !owners.insert((parent, owner)) {
                    return Err(ObservationError::BackendFailure);
                }
            } else if frame.owner_backend_id.is_some() {
                return Err(ObservationError::BackendFailure);
            }
        }
        Ok(Self {
            frames,
            policy,
            pending: vec![(root, 0)],
            active: None,
            omissions: HashMap::new(),
            records: Vec::new(),
            count: 0,
            truncated: false,
            max_nodes,
        })
    }
    fn omit(
        &mut self,
        frame: &'a ObservationFrame,
        reason: Omission,
    ) -> Result<(), ObservationError> {
        let mut pending = vec![frame];
        while let Some(frame) = pending.pop() {
            if frame.parent_frame_id.is_none()
                || self
                    .omissions
                    .insert(frame.binding.frame.clone(), reason)
                    .is_some()
                || self
                    .records
                    .iter()
                    .any(|record| record.frame == frame.binding.frame)
            {
                return Err(ObservationError::BackendFailure);
            }
            pending.extend(
                self.frames
                    .iter()
                    .filter(|child| child.parent_frame_id.as_ref() == Some(&frame.binding.frame)),
            );
        }
        Ok(())
    }
    pub fn next(&mut self) -> Result<Option<&'a ObservationFrame>, ObservationError> {
        if self.active.is_some() {
            return Err(ObservationError::BackendFailure);
        }
        while let Some((frame, depth)) = self.pending.pop() {
            if depth > 0 {
                // Site exclusion precedes depth/budget and is never truncation.
                let reason = if !self.policy.admits(&frame.url) {
                    Some(Omission::Policy)
                } else if depth > MAX_FRAME_DEPTH {
                    Some(Omission::Depth)
                } else if self.count == self.max_nodes {
                    Some(Omission::Budget)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    self.truncated |= matches!(reason, Omission::Depth | Omission::Budget);
                    self.omit(frame, reason)?;
                    continue;
                }
            }
            self.active = Some((frame, depth));
            return Ok(Some(frame));
        }
        if self.records.len() + self.omissions.len() != self.frames.len() {
            return Err(ObservationError::BackendFailure);
        }
        Ok(None)
    }
    pub fn record(&mut self, record: DocumentCapture) -> Result<(), ObservationError> {
        let (frame, depth) = self.active.take().ok_or(ObservationError::BackendFailure)?;
        if record.frame != frame.binding.frame
            || record.node_count <= record.emitted_owners.len()
            || record.node_count > self.max_nodes - self.count
            || (record.truncated && record.node_count != self.max_nodes - self.count)
            || self.records.iter().any(|prior| prior.frame == record.frame)
        {
            return Err(ObservationError::BackendFailure);
        }
        let mut emitted = HashSet::new();
        if record.emitted_owners.iter().any(|owner| {
            *owner <= 0 || !emitted.insert(*owner) || record.hidden_owners.contains(owner)
        }) {
            return Err(ObservationError::BackendFailure);
        }
        let mut children = Vec::new();
        for child in self
            .frames
            .iter()
            .filter(|child| child.parent_frame_id.as_ref() == Some(&frame.binding.frame))
        {
            let owner = child
                .owner_backend_id
                .ok_or(ObservationError::BackendFailure)?;
            if record.hidden_owners.contains(&owner) {
                self.omit(child, Omission::Hidden)?;
            } else if let Some(index) = record.emitted_owners.iter().position(|id| *id == owner) {
                children.push((index, child));
            } else if record.truncated {
                self.omit(child, Omission::BoundaryBudget)?;
            } else {
                return Err(ObservationError::BackendFailure);
            }
        }
        children.sort_by_key(|(index, _)| *index);
        self.pending.extend(
            children
                .into_iter()
                .rev()
                .map(|(_, child)| (child, depth + 1)),
        );
        self.count += record.node_count;
        self.truncated |= record.truncated;
        self.records.push(record);
        Ok(())
    }
    pub fn hidden_owners(&self) -> HashSet<(String, i64)> {
        self.records
            .iter()
            .flat_map(|record| {
                record
                    .hidden_owners
                    .iter()
                    .map(|owner| (record.frame.clone(), *owner))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ExactBinding;
    use super::*;
    pub(super) fn frame(
        id: &str,
        parent: Option<&str>,
        owner: Option<i64>,
        url: &str,
    ) -> ObservationFrame {
        ObservationFrame {
            parent_frame_id: parent.map(str::to_owned),
            owner_backend_id: owner,
            url: url.into(),
            binding: ExactBinding {
                page_session: "page".into(),
                session: "page".into(),
                frame: id.into(),
                loader: format!("{id}-doc"),
                actionable: false,
            },
            offset_x: 0.,
            offset_y: 0.,
            frame_path: vec![],
        }
    }
    fn record(frame: &str, nodes: usize, owners: &[i64]) -> DocumentCapture {
        DocumentCapture {
            frame: frame.into(),
            node_count: nodes,
            truncated: false,
            emitted_owners: owners.to_vec(),
            hidden_owners: HashSet::new(),
        }
    }
    #[test]
    fn original_typescript_url_and_hostname_truth_table() {
        // Frozen oracle: E2E 1d9d58299d58aa663af3349e376b7420ce8a2574
        // observation.ts isOnSiteFrame and internal/urls.ts siteOf, unmodified
        // function bodies executed with only TypeScript syntax removed.
        let cases = [
            ("", None, true),
            ("about:blank", None, true),
            ("about:srcdoc", None, true),
            ("about:blank#fragment", None, false),
            ("data:text/html,<button>Ad</button>", None, false),
            ("https://example.com/child", None, false),
            ("https://a.example.com/x", Some("example.com"), true),
            ("http://b.example.com:9000/y", Some("example.com"), true),
            ("https://example.com.evil.test/", Some("example.com"), false),
            ("https://shop.example.co.uk/", Some("example.co.uk"), true),
            ("https://other.co.uk/", Some("example.co.uk"), false),
            ("http://127.0.0.1:9000/", Some("127.0.0.1"), true),
            ("http://127.0.0.2/", Some("127.0.0.1"), false),
            ("http://[::1]:9000/", Some("[::1]"), true),
            ("http://localhost/", Some("localhost"), true),
            ("http://app.localhost/", Some("localhost"), false),
            ("https://EXAMPLE.COM/", Some("example.com"), true),
            ("https://example.com./", Some("example.com"), false),
            ("https://bücher.de/", Some("xn--bcher-kva.de"), true),
            ("https://example.com/", Some("EXAMPLE.COM"), false),
            ("data:text/html,x", Some("example.com"), false),
            ("blob:https://example.com/id", Some("example.com"), false),
            ("not a URL", Some("example.com"), false),
            ("ftp://app.example.com/", Some("example.com"), true),
            ("ws://app.example.com/", Some("example.com"), true),
            ("file:///a", Some(""), true),
            ("blob:https://example.com/id", Some(""), true),
            ("data:text/html,x", Some(""), false),
        ];
        for (url, site, allowed) in cases {
            assert_eq!(
                ObservationFramePolicy::configured(site.map(str::to_owned)).admits(url),
                allowed,
                "url={url:?} site={site:?}"
            );
        }
    }
    #[test]
    fn original_typescript_hostname_truth_table() {
        assert_eq!(site_of("tester.army"), "tester.army");
        assert_eq!(site_of("auth.tester.army"), "tester.army");
        assert_eq!(site_of("a.b.app.example.com"), "example.com");
        assert_eq!(site_of("shop.example.co.uk"), "example.co.uk");
        assert_eq!(site_of("example.co.uk"), "example.co.uk");
        assert_eq!(site_of("Example.COM"), "example.com");
        assert_eq!(site_of("localhost"), "localhost");
        assert_eq!(site_of("app.localhost"), "app.localhost");
        assert_eq!(site_of("127.0.0.1"), "127.0.0.1");
        assert_eq!(site_of("[::1]"), "[::1]");
        assert_eq!(site_of("example.com."), "com.");
    }
    #[test]
    fn exact_budget_three_excludes_data_without_truncating_and_closes_descendants() {
        let frames = [
            frame("main", None, None, "https://main.invalid/"),
            frame("ad", Some("main"), Some(2), "data:text/html,Ad"),
            frame("blank", Some("ad"), Some(3), "about:srcdoc"),
        ];
        let policy = ObservationFramePolicy::default();
        let mut traversal = FrameTraversal::new(&frames, &policy, 3).unwrap();
        assert_eq!(traversal.next().unwrap().unwrap().binding.frame, "main");
        traversal.record(record("main", 3, &[2])).unwrap();
        assert!(traversal.next().unwrap().is_none());
        assert_eq!(traversal.count, 3);
        assert!(!traversal.truncated);
        assert_eq!(
            traversal.omissions,
            HashMap::from([
                ("ad".into(), Omission::Policy),
                ("blank".into(), Omission::Policy)
            ])
        );
        let mut onsite = frames.clone();
        onsite[1].url = "about:srcdoc".into();
        let mut traversal = FrameTraversal::new(&onsite, &policy, 3).unwrap();
        traversal.next().unwrap();
        traversal.record(record("main", 3, &[2])).unwrap();
        assert!(traversal.next().unwrap().is_none());
        assert!(traversal.truncated);
        assert!(traversal
            .omissions
            .values()
            .all(|reason| *reason == Omission::Budget));
    }
    #[test]
    fn exact_depth_four_five_and_site_before_depth() {
        let mut frames = vec![frame("main", None, None, "https://main.invalid/")];
        for depth in 1..=5 {
            let parent = if depth == 1 {
                "main".into()
            } else {
                format!("level{}", depth - 1)
            };
            frames.push(frame(
                &format!("level{depth}"),
                Some(&parent),
                Some(depth as i64),
                "about:srcdoc",
            ));
        }
        let policy = ObservationFramePolicy::default();
        for count in [5, 6] {
            let mut traversal = FrameTraversal::new(&frames[..count], &policy, 1000).unwrap();
            while let Some(frame) = traversal.next().unwrap() {
                let owners = frames[..count]
                    .iter()
                    .filter(|child| child.parent_frame_id.as_ref() == Some(&frame.binding.frame))
                    .map(|child| child.owner_backend_id.unwrap())
                    .collect::<Vec<_>>();
                traversal
                    .record(record(&frame.binding.frame, 2 + owners.len(), &owners))
                    .unwrap();
            }
            assert_eq!(traversal.records.len(), 5);
            assert_eq!(traversal.truncated, count == 6);
            assert_eq!(
                traversal.omissions.get("level5"),
                if count == 6 {
                    Some(&Omission::Depth)
                } else {
                    None
                }
            );
        }
        frames[5].url = "data:text/html,Ad".into();
        let mut traversal = FrameTraversal::new(&frames, &policy, 1000).unwrap();
        while let Some(frame) = traversal.next().unwrap() {
            let owners = frames
                .iter()
                .filter(|child| child.parent_frame_id.as_ref() == Some(&frame.binding.frame))
                .map(|child| child.owner_backend_id.unwrap())
                .collect::<Vec<_>>();
            traversal
                .record(record(&frame.binding.frame, 2 + owners.len(), &owners))
                .unwrap();
        }
        assert!(!traversal.truncated);
        assert_eq!(traversal.omissions.get("level5"), Some(&Omission::Policy));
    }
    #[test]
    fn original_document_then_child_dfs_budget_order() {
        // Deliberately shuffled inventory; emitted owners, not inventory order,
        // select A before B, and A's grandchild before B.
        let frames = [
            frame("main", None, None, "https://main.invalid/"),
            frame("b", Some("main"), Some(2), "about:srcdoc"),
            frame("a", Some("main"), Some(1), "about:srcdoc"),
            frame("grand", Some("a"), Some(3), "about:srcdoc"),
        ];
        let policy = ObservationFramePolicy::default();
        for budget in [8, 100] {
            let mut traversal = FrameTraversal::new(&frames, &policy, budget).unwrap();
            while let Some(frame) = traversal.next().unwrap() {
                let next = match frame.binding.frame.as_str() {
                    "main" => record("main", 3, &[1, 2]),
                    "a" => record("a", 3, &[3]),
                    "grand" => record("grand", 2, &[]),
                    "b" => record("b", 2, &[]),
                    _ => unreachable!(),
                };
                traversal.record(next).unwrap();
            }
            let order = traversal
                .records
                .iter()
                .map(|record| record.frame.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                order,
                if budget == 8 {
                    vec!["main", "a", "grand"]
                } else {
                    vec!["main", "a", "grand", "b"]
                }
            );
            assert_eq!(traversal.count, if budget == 8 { 8 } else { 10 });
            assert_eq!(traversal.truncated, budget == 8);
        }
    }
    #[test]
    fn hidden_before_budget_and_missing_owner_is_not_a_policy_exemption() {
        let frames = [
            frame("main", None, None, "https://main.invalid/"),
            frame("hidden", Some("main"), Some(2), "about:srcdoc"),
        ];
        let policy = ObservationFramePolicy::default();
        let mut traversal = FrameTraversal::new(&frames, &policy, 1).unwrap();
        traversal.next().unwrap();
        let mut main = record("main", 1, &[]);
        main.hidden_owners.insert(2);
        traversal.record(main).unwrap();
        assert!(traversal.next().unwrap().is_none());
        assert!(!traversal.truncated);
        assert_eq!(traversal.omissions["hidden"], Omission::Hidden);
        let mut traversal = FrameTraversal::new(&frames, &policy, 10).unwrap();
        traversal.next().unwrap();
        assert!(traversal.record(record("main", 1, &[])).is_err());
        for owner in [None, Some(0), Some(-1)] {
            let mut invalid = frames.clone();
            invalid[1].owner_backend_id = owner;
            assert!(FrameTraversal::new(&invalid, &policy, 10).is_err());
        }
        let mut invalid = frames.to_vec();
        invalid.push(frame("other", Some("main"), Some(2), "about:srcdoc"));
        assert!(FrameTraversal::new(&invalid, &policy, 10).is_err());
        let mut invalid = frames.clone();
        invalid[1].parent_frame_id = Some("unknown".into());
        assert!(FrameTraversal::new(&invalid, &policy, 10).is_err());
    }
}
