//! Equality-only facts for paying the settle cost of a form control once.
//! The ordinary protected capture still owns visibility, policy, geometry,
//! complete candidate inventory, and every action reference.
use super::super::element::{parse_ref, NativeReferenceKind};
use super::{ObservationFrame, RefMap, SemanticNode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Kind {
    Radio,
    Button,
    Field,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Sample {
    kind: Kind,
    owner: usize,
    control: usize,
    #[serde(skip)]
    backends: Option<(i64, i64)>,
    checked: Option<bool>,
    hovered: Option<bool>,
    #[serde(default)]
    stable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(super) struct Control {
    kind: Kind,
    stable: bool,
    owner: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    checked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hovered: Option<bool>,
}

fn identity(frame: &ObservationFrame, scope: &str, backend: i64, control: i64) -> String {
    let binding = &frame.binding;
    let mut hash = Sha256::new();
    for part in [
        scope,
        &binding.page_session,
        &binding.session,
        &binding.frame,
        &binding.loader,
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(backend.to_be_bytes());
    hash.update(control.to_be_bytes());
    format!("{:x}", hash.finalize())
}

impl Sample {
    /// The renderer compared actual objects inside one exact CDP receiver batch.
    /// Pseudo receivers, missing owners and other batches cannot supply equality.
    pub(super) fn bind_receivers(&mut self, nodes: &[&super::AXNode], pseudo: &[Option<i64>]) {
        if pseudo.get(self.owner) == Some(&None) && pseudo.get(self.control) == Some(&None) {
            let backend = |slot: usize| nodes.get(slot).and_then(|node| node.backend_d_o_m_node_id);
            self.backends = backend(self.owner).zip(backend(self.control));
        }
    }
}

/// Mint equality-only facts for nodes with a live actionable issuance on this document.
pub(super) fn bind(
    frame: &ObservationFrame,
    scope: &str,
    refs: &RefMap,
    nodes: &mut HashMap<i64, SemanticNode>,
) {
    if frame.binding.loader.is_empty() {
        return;
    }
    let mut binding = frame.binding.clone();
    binding.actionable = true;
    for (&id, node) in nodes.iter_mut() {
        let Some(sample) = node.replay_sample.take() else {
            continue;
        };
        let Some((form, control)) = sample.backends else {
            continue;
        };
        if form <= 0
            || control <= 0
            || (sample.kind == Kind::Radio
                && (sample.checked.is_none() || sample.hovered.is_none()))
        {
            continue;
        }
        let issued = parse_ref(&node.reference.id).and_then(|key| refs.get(&key));
        if issued.is_some_and(|entry| {
            entry.kind == NativeReferenceKind::Dom
                && entry.backend_node_id == Some(id)
                && entry.exact_binding.as_ref() == Some(&binding)
                && entry.issued_wire_revision().as_ref() == Some(&node.reference.revision)
        }) {
            node.replay_control = Some(Control {
                kind: sample.kind,
                stable: sample.stable,
                owner: identity(frame, scope, form, form),
                target: identity(frame, scope, id, control),
                checked: sample.checked,
                hovered: sample.hovered,
            });
        }
    }
}

/// Only refs actually retained in a complete protected tree get a hint. Omit
/// the entire map if oversized; it is never a source of action authority.
pub(crate) fn published(root: &SemanticNode, truncated: bool) -> Option<Value> {
    if truncated {
        return None;
    }
    let mut result = serde_json::Map::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if let Some(control) = &n.replay_control {
            if result.len() >= 256 {
                return None;
            }
            result.insert(n.reference.id.clone(), serde_json::to_value(control).ok()?);
        }
        stack.extend(&n.children);
    }
    (!result.is_empty()).then_some(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_membership_requires_two_exact_non_pseudo_receivers() {
        let owner = super::super::synthetic_ax(11);
        let field = super::super::synthetic_ax(12);
        let nodes = [&owner, &field];
        let sample = || {
            serde_json::from_value::<Sample>(serde_json::json!({
                "kind": "field", "owner": 0, "control": 1, "stable": true
            }))
            .unwrap()
        };
        let mut exact = sample();
        exact.bind_receivers(&nodes, &[None, None]);
        assert_eq!(exact.backends, Some((11, 12)));
        for pseudo in [vec![Some(3), None], vec![None, Some(4)], vec![None]] {
            let mut refused = sample();
            refused.bind_receivers(&nodes, &pseudo);
            assert_eq!(refused.backends, None);
        }
    }
}
