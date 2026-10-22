//! Author line projection over native DOM ownership. The renderer supplies only
//! bounded facts; references and tree assembly remain in the native pipeline.
use super::{ObservationError, SemanticNode};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const LIMIT: usize = 100_000;
const TEXT_LIMIT: usize = 512;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Facts {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub node_type: i64,
    #[serde(default)]
    pub inline: bool,
    #[serde(default)]
    pub breaking: bool,
    #[serde(default)]
    pub action: bool,
    #[serde(default)]
    pub suppress: bool,
    #[serde(default)]
    pub skips_content: bool,
    #[serde(default)]
    pub visible: bool,
    #[serde(default)]
    pub line_visible: Option<bool>,
    #[serde(default)]
    pub text: String,
}

impl Facts {
    fn line_visible(&self) -> bool {
        self.line_visible.unwrap_or(self.visible)
    }
}

#[derive(Debug)]
struct Entry {
    id: i64,
    kind: i64,
    pseudo: bool,
    assigned_slot: Option<i64>,
    distributed: Option<Vec<i64>>,
    children: Vec<i64>,
    rendered: Vec<i64>,
}
#[derive(Debug)]
pub(super) struct Graph {
    entries: HashMap<i64, Entry>,
    pub ids: Vec<i64>,
    roots: Vec<i64>,
}
impl Graph {
    pub fn read(root: &Value) -> Result<Self, ObservationError> {
        let mut graph = Self {
            entries: HashMap::new(),
            ids: Vec::new(),
            roots: Vec::new(),
        };
        fn visit(
            node: &Value,
            graph: &mut Graph,
            depth: usize,
            visited: &mut usize,
        ) -> Result<Vec<i64>, ObservationError> {
            *visited += 1;
            if depth > 256 || *visited > LIMIT {
                return Err(ObservationError::ResourceLimit);
            }
            if node["shadowRootType"] == "user-agent" {
                return Ok(Vec::new());
            }
            let kind = node["nodeType"]
                .as_i64()
                .ok_or(ObservationError::BackendFailure)?;
            if ![1, 3, 9, 11].contains(&kind) {
                return Ok(Vec::new());
            }
            let mut children = Vec::new();
            for child in node["children"].as_array().into_iter().flatten() {
                children.extend(visit(child, graph, depth + 1, visited)?);
            }
            let mut shadow = Vec::new();
            let mut has_author_shadow = false;
            for child in node["shadowRoots"].as_array().into_iter().flatten() {
                has_author_shadow |= child["shadowRootType"] != "user-agent";
                shadow.extend(visit(child, graph, depth + 1, visited)?);
            }
            let mut rendered = if has_author_shadow {
                shadow.clone()
            } else {
                children.clone()
            };
            children.extend(shadow);
            let distributed = node
                .get("distributedNodes")
                .map(|value| {
                    let edges = value.as_array().ok_or(ObservationError::BackendFailure)?;
                    if edges.len() > LIMIT.saturating_sub(*visited) {
                        return Err(ObservationError::ResourceLimit);
                    }
                    *visited += edges.len();
                    edges
                        .iter()
                        .map(|child| {
                            child["backendNodeId"]
                                .as_i64()
                                .ok_or(ObservationError::BackendFailure)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            if let Some(assigned) = distributed.as_ref().filter(|nodes| !nodes.is_empty()) {
                rendered = assigned.clone();
            }
            let assigned_slot = node
                .get("assignedSlot")
                .map(|slot| {
                    slot["backendNodeId"]
                        .as_i64()
                        .ok_or(ObservationError::BackendFailure)
                })
                .transpose()?;
            if assigned_slot.is_some() {
                *visited += 1;
                if *visited > LIMIT {
                    return Err(ObservationError::ResourceLimit);
                }
            }
            for child in node["pseudoElements"].as_array().into_iter().flatten() {
                children.extend(visit(child, graph, depth + 1, visited)?);
            }
            if kind == 11 {
                return Ok(children);
            }
            let id = node["backendNodeId"]
                .as_i64()
                .ok_or(ObservationError::BackendFailure)?;
            if graph
                .entries
                .insert(
                    id,
                    Entry {
                        id,
                        kind,
                        pseudo: node["pseudoType"].is_string(),
                        assigned_slot,
                        distributed,
                        children,
                        rendered,
                    },
                )
                .is_some()
            {
                return Err(ObservationError::BackendFailure);
            }
            graph.ids.push(id);
            Ok(vec![id])
        }
        graph.roots = visit(root, &mut graph, 0, &mut 0)?;
        let browser_internal = super::browser_internal_ids(root)?;
        for entry in graph.entries.values() {
            if entry
                .rendered
                .iter()
                .any(|id| !graph.entries.contains_key(id))
            {
                return Err(ObservationError::BackendFailure);
            }
            if let Some(slot) = entry
                .assigned_slot
                .filter(|slot| !browser_internal.contains(slot))
            {
                let target = graph
                    .entries
                    .get(&slot)
                    .ok_or(ObservationError::BackendFailure)?;
                if !target
                    .distributed
                    .as_ref()
                    .is_some_and(|ids| ids.contains(&entry.id))
                {
                    return Err(ObservationError::BackendFailure);
                }
            }
            for child in entry.distributed.as_deref().unwrap_or_default() {
                let target = graph
                    .entries
                    .get(child)
                    .ok_or(ObservationError::BackendFailure)?;
                if target.assigned_slot.is_some_and(|slot| slot != entry.id) {
                    return Err(ObservationError::BackendFailure);
                }
            }
        }
        Ok(graph)
    }
}

fn facts(node: &SemanticNode) -> Result<&Facts, ObservationError> {
    node.author.as_ref().ok_or(ObservationError::BackendFailure)
}
fn collapse(text: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(ch);
            space = false;
        }
    }
    out
}

/// The complete run is capped one character beyond the public text bound. That
/// extra character is a proof that descendants must not be suppressed as covered.
pub(super) fn compact(
    graph: &Graph,
    mut nodes: HashMap<i64, SemanticNode>,
    limit: usize,
) -> Result<(Vec<SemanticNode>, bool), ObservationError> {
    let mut rendered_parent = HashMap::new();
    // Slot assignment takes precedence over the light-DOM parent. Unassigned
    // light nodes have no rendered parent and cannot claim coverage by the host.
    for entry in graph.entries.values() {
        for child in &entry.rendered {
            if rendered_parent.insert(*child, entry.id).is_some() {
                return Err(ObservationError::BackendFailure);
            }
        }
    }
    // Content visibility suppresses descendants, not the owner's painted box.
    // Follow proven native rendered edges, including closed-root slot ownership,
    // rather than guessing a flat-tree parent from renderer-visible properties.
    fn skipped_content(
        id: i64,
        nodes: &HashMap<i64, SemanticNode>,
        parents: &HashMap<i64, i64>,
        cache: &mut HashMap<i64, bool>,
        depth: usize,
    ) -> Result<bool, ObservationError> {
        if let Some(value) = cache.get(&id) {
            return Ok(*value);
        }
        if depth > 256 {
            return Err(ObservationError::BackendFailure);
        }
        let skipped = if let Some(parent) = parents.get(&id) {
            facts(nodes.get(parent).ok_or(ObservationError::BackendFailure)?)?.skips_content
                || skipped_content(*parent, nodes, parents, cache, depth + 1)?
        } else {
            false
        };
        cache.insert(id, skipped);
        Ok(skipped)
    }
    // Pseudos have native owner edges but are intentionally absent from line
    // flow. They still inherit content skipping from that exact owner.
    let mut content_parent = rendered_parent.clone();
    for entry in graph.entries.values() {
        for child in &entry.children {
            if graph.entries.get(child).is_some_and(|node| node.pseudo)
                && content_parent.insert(*child, entry.id).is_some()
            {
                return Err(ObservationError::BackendFailure);
            }
        }
    }
    let mut skipped = HashMap::new();
    for id in &graph.ids {
        skipped_content(*id, &nodes, &content_parent, &mut skipped, 0)?;
    }
    for (id, suppressed) in skipped {
        if suppressed {
            nodes
                .get_mut(&id)
                .and_then(|node| node.author.as_mut())
                .ok_or(ObservationError::BackendFailure)?
                .suppress = true;
        }
    }
    // A hidden select offers no visible options. Suppress its entire native
    // ownership branch before line projection/child promotion, including any
    // optgroup descendants. Ordinary zero-box wrappers still promote children.
    // These are observation-local facts; exact query/read nodes stay unchanged.
    for node in nodes.values_mut() {
        let f = node
            .author
            .as_mut()
            .ok_or(ObservationError::BackendFailure)?;
        if f.tag == "select" && !f.visible {
            f.suppress = true;
        }
    }
    let mut runs: HashMap<i64, String> = HashMap::new();
    let mut direct = HashSet::new();
    let mut visiting = HashSet::new();
    #[allow(clippy::too_many_arguments)] // Explicit immutable graph and bounded traversal state.
    fn run(
        id: i64,
        graph: &Graph,
        nodes: &HashMap<i64, SemanticNode>,
        runs: &mut HashMap<i64, String>,
        direct: &mut HashSet<i64>,
        visiting: &mut HashSet<i64>,
        depth: usize,
    ) -> Result<String, ObservationError> {
        if let Some(run) = runs.get(&id) {
            return Ok(run.clone());
        }
        if depth > 256 || !visiting.insert(id) {
            return Err(ObservationError::BackendFailure);
        }
        let entry = &graph.entries[&id];
        let node = nodes.get(&id).ok_or(ObservationError::BackendFailure)?;
        let f = facts(node)?;
        let mut text = String::new();
        if !f.suppress {
            if entry.kind == 3 {
                if f.visible {
                    text = f.text.clone();
                }
            } else {
                for child in &entry.rendered {
                    let child_entry = &graph.entries[child];
                    let child_node = nodes.get(child).ok_or(ObservationError::BackendFailure)?;
                    let child_facts = facts(child_node)?;
                    let value = run(*child, graph, nodes, runs, direct, visiting, depth + 1)?;
                    if child_facts.suppress {
                        continue;
                    }
                    if child_entry.kind == 3 {
                        if !value.trim().is_empty() {
                            direct.insert(id);
                        }
                        text.push_str(&value);
                    } else if child_facts.inline
                        && child_facts.line_visible()
                        && !child_facts.breaking
                    {
                        text.push_str(&value);
                    } else if child_facts.breaking
                        || !child_facts.inline
                        || child_facts.line_visible()
                    {
                        text.push(' ');
                    }
                    // Bound intermediate concatenation too, not only the wire.
                    text = collapse(&text).chars().take(TEXT_LIMIT + 1).collect();
                }
            }
        }
        visiting.remove(&id);
        // Text leaves retain their whitespace until their owner's run joins.
        if entry.kind != 3 {
            text = collapse(&text);
        }
        runs.insert(id, text.clone());
        Ok(text)
    }
    for id in &graph.ids {
        run(*id, graph, &nodes, &mut runs, &mut direct, &mut visiting, 0)?;
    }
    let mut coverage = HashMap::new();
    fn covered(
        id: i64,
        nodes: &HashMap<i64, SemanticNode>,
        parents: &HashMap<i64, i64>,
        direct: &HashSet<i64>,
        runs: &HashMap<i64, String>,
        cache: &mut HashMap<i64, bool>,
        depth: usize,
    ) -> Result<bool, ObservationError> {
        if let Some(value) = cache.get(&id) {
            return Ok(*value);
        }
        if depth > 256 {
            return Err(ObservationError::BackendFailure);
        }
        let f = facts(&nodes[&id])?;
        let value = if !f.inline || !f.line_visible() || f.breaking {
            false
        } else if let Some(parent) = parents.get(&id) {
            let p = facts(&nodes[parent])?;
            if p.suppress || !p.line_visible() {
                false
            } else if direct.contains(parent)
                || (p.action && covered(*parent, nodes, parents, direct, runs, cache, depth + 1)?)
            {
                // A capped trailing space is still the overflow sentinel. Trimming
                // it must not falsely prove the following endpoint was covered.
                runs[parent].chars().count() <= TEXT_LIMIT
            } else {
                covered(*parent, nodes, parents, direct, runs, cache, depth + 1)?
            }
        } else {
            false
        };
        cache.insert(id, value);
        Ok(value)
    }
    for id in &graph.ids {
        covered(
            *id,
            &nodes,
            &rendered_parent,
            &direct,
            &runs,
            &mut coverage,
            0,
        )?;
    }
    let options: HashSet<i64> = graph
        .entries
        .values()
        .filter(|entry| {
            nodes
                .get(&entry.id)
                .and_then(|node| node.author.as_ref())
                .is_some_and(|f| f.tag == "select" && f.visible && !f.suppress)
        })
        .flat_map(|entry| entry.children.iter().copied())
        .collect();
    let mut retained = HashSet::new();
    for id in &graph.ids {
        let entry = &graph.entries[id];
        let node = nodes.get_mut(id).ok_or(ObservationError::BackendFailure)?;
        let mut f = facts(node)?.clone();
        if options.contains(id) && f.tag == "option" {
            f.visible = true;
            node.states.insert("hidden".into(), false);
            node.value = None;
        }
        if f.suppress {
            continue;
        }
        if entry.kind == 3 {
            continue;
        }
        if entry.kind == 9 {
            node.role = Some("document".into());
            node.text = None;
            retained.insert(*id);
            continue;
        }
        if entry.pseudo {
            retained.insert(*id);
            continue;
        }
        let owns = direct.contains(id) || (f.action && coverage[id]);
        let text = if owns {
            runs[id].trim().chars().take(TEXT_LIMIT).collect::<String>()
        } else {
            String::new()
        };
        node.text = (!text.is_empty() || f.skips_content).then_some(text);
        let independent = node.role.is_some()
            || node.test_id.is_some()
            || node.name.is_some()
            || (f.action && coverage[id] && node.text.is_some());
        if f.visible && !f.suppress && (independent || (owns && !coverage[id])) {
            retained.insert(*id);
        }
    }
    let mut count = 0usize;
    let mut truncated = false;
    #[allow(clippy::too_many_arguments)] // One staged owner map and publication budget.
    fn emit(
        id: i64,
        graph: &Graph,
        nodes: &mut HashMap<i64, SemanticNode>,
        retained: &HashSet<i64>,
        count: &mut usize,
        limit: usize,
        truncated: &mut bool,
        depth: usize,
    ) -> Result<Vec<SemanticNode>, ObservationError> {
        if depth > 256 {
            return Err(ObservationError::BackendFailure);
        }
        let entry = &graph.entries[&id];
        let mut node = nodes.remove(&id).ok_or(ObservationError::BackendFailure)?;
        if facts(&node)?.suppress {
            return Ok(Vec::new());
        }
        let keep = retained.contains(&id);
        if keep && *count == limit {
            *truncated = true;
            return Ok(Vec::new());
        }
        if keep {
            *count += 1;
        }
        let mut children = Vec::new();
        for child in &entry.children {
            children.extend(emit(
                *child,
                graph,
                nodes,
                retained,
                count,
                limit,
                truncated,
                depth + 1,
            )?);
        }
        if keep {
            node.children = children;
            Ok(vec![node])
        } else {
            Ok(children)
        }
    }
    let mut roots = Vec::new();
    for root in &graph.roots {
        roots.extend(emit(
            *root,
            graph,
            &mut nodes,
            &retained,
            &mut count,
            limit,
            &mut truncated,
            0,
        )?);
    }
    Ok((roots, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::client_observation::NodeReference;
    use serde_json::json;

    #[derive(Default)]
    struct Fixture {
        next: i64,
        nodes: HashMap<i64, SemanticNode>,
    }
    impl Fixture {
        fn node(&mut self, kind: i64, f: Facts, role: Option<&str>, children: Vec<Value>) -> Value {
            self.next += 1;
            let id = self.next;
            self.nodes.insert(
                id,
                SemanticNode {
                    reference: NodeReference {
                        id: format!("@fixture{id}"),
                        revision: "1".into(),
                    },
                    role: role.map(str::to_owned),
                    author: Some(f),
                    ..Default::default()
                },
            );
            json!({"nodeType":kind,"backendNodeId":id,"children":children})
        }
        fn text(&mut self, text: &str) -> Value {
            self.node(
                3,
                Facts {
                    inline: true,
                    visible: true,
                    text: text.into(),
                    ..Default::default()
                },
                Some("text"),
                vec![],
            )
        }
        fn el(&mut self, tag: &str, role: Option<&str>, children: Vec<Value>) -> Value {
            self.node(
                1,
                Facts {
                    tag: tag.into(),
                    visible: true,
                    inline: matches!(
                        tag,
                        "a" | "span" | "strong" | "em" | "code" | "slot" | "host"
                    ),
                    action: tag == "a",
                    breaking: matches!(tag, "button" | "select" | "br" | "input"),
                    ..Default::default()
                },
                role,
                children,
            )
        }
        fn run(mut self, children: Vec<Value>) -> Vec<SemanticNode> {
            let root = self.node(
                9,
                Facts {
                    visible: true,
                    ..Default::default()
                },
                Some("document"),
                children,
            );
            let graph = Graph::read(&root).unwrap();
            compact(&graph, self.nodes, 100)
                .unwrap()
                .0
                .remove(0)
                .children
        }
        fn facts_mut(&mut self, node: &Value) -> &mut Facts {
            self.nodes
                .get_mut(&node["backendNodeId"].as_i64().unwrap())
                .unwrap()
                .author
                .as_mut()
                .unwrap()
        }
    }
    fn flat(nodes: &[SemanticNode]) -> Vec<&SemanticNode> {
        let mut out = Vec::new();
        for node in nodes {
            out.push(node);
            out.extend(flat(&node.children));
        }
        out
    }
    fn texts(nodes: &[SemanticNode]) -> Vec<Option<&str>> {
        flat(nodes).into_iter().map(|n| n.text.as_deref()).collect()
    }
    #[test]
    fn emitted_flags_remain_raw_until_public_serialization() {
        let mut fixture = Fixture::default();
        let element = fixture.el("button", Some("button"), vec![]);
        let id = element["backendNodeId"].as_i64().unwrap();
        let node = fixture.nodes.get_mut(&id).unwrap();
        for name in [
            "disabled", "focused", "hidden", "secure", "checked", "selected", "expanded", "pressed",
        ] {
            node.states.insert(name.into(), false);
        }
        let result = fixture.run(vec![element]);
        assert_eq!(result[0].states.len(), 8);
        let encoded = serde_json::to_value(&result[0]).unwrap();
        assert_eq!(
            encoded["states"],
            json!({"checked":false,"selected":false,"expanded":false,"pressed":false})
        );
        for name in [
            "disabled", "focused", "hidden", "secure", "checked", "selected", "expanded", "pressed",
        ] {
            assert_eq!(result[0].states.get(name), Some(&false));
        }
        assert_eq!(encoded["ref"]["id"], format!("@fixture{id}"));
    }

    fn reference(node: &Value) -> String {
        format!("@fixture{}", node["backendNodeId"])
    }

    #[test]
    fn hidden_select_prunes_direct_and_optgroup_branches_but_not_visible_siblings() {
        let mut f = Fixture::default();
        let plain = f.el("option", Some("option"), vec![]);
        let warm = f.el("option", Some("option"), vec![]);
        let warm_group = f.el("optgroup", Some("group"), vec![warm.clone()]);
        let folded = f.el("select", Some("combobox"), vec![plain.clone(), warm_group]);
        f.facts_mut(&folded).visible = false;
        let cool = f.el("option", Some("option"), vec![]);
        f.facts_mut(&cool).visible = false;
        let cool_id = cool["backendNodeId"].as_i64().unwrap();
        let raw_option = f.nodes.get_mut(&cool_id).unwrap();
        raw_option.value = Some("internal-cool-token".into());
        raw_option.states.insert("hidden".into(), true);
        raw_option.states.insert("selected".into(), true);
        raw_option.states.insert("disabled".into(), true);
        let shown = f.el("select", Some("combobox"), vec![cool.clone()]);
        let button = f.el("button", Some("button"), vec![]);
        let wrapper = f.el(
            "div",
            None,
            vec![folded.clone(), shown.clone(), button.clone()],
        );
        f.facts_mut(&wrapper).visible = false;
        let raw_nodes = f.nodes.clone();
        let nodes = f.run(vec![wrapper]);
        let emitted = flat(&nodes);
        assert_eq!(
            emitted
                .iter()
                .map(|node| node.reference.id.clone())
                .collect::<Vec<_>>(),
            vec![reference(&shown), reference(&cool), reference(&button)]
        );
        assert_eq!(emitted[1].states.get("hidden"), Some(&false));
        assert_eq!(emitted[1].states.get("selected"), Some(&true));
        assert_eq!(emitted[1].states.get("disabled"), Some(&true));
        assert_eq!(emitted[1].value, None);
        // Compaction changes the observed copy, not exact-query/read facts.
        assert_eq!(raw_nodes[&cool_id].states.get("hidden"), Some(&true));
        assert_eq!(
            raw_nodes[&cool_id].value.as_deref(),
            Some("internal-cool-token")
        );
        assert!(!facts(&raw_nodes[&cool_id]).unwrap().visible);
        assert!(
            !facts(&raw_nodes[&folded["backendNodeId"].as_i64().unwrap()])
                .unwrap()
                .suppress
        );
        for absent in [folded, plain, warm] {
            assert!(!emitted
                .iter()
                .any(|node| node.reference.id == reference(&absent)));
        }
    }

    #[test]
    fn select_option_exception_does_not_escape_suppressed_native_owners() {
        // aria-hidden, inert and display:none share the renderer's suppress
        // fact; content-visibility has its separate rendered-ownership gate.
        for suppression in ["aria-hidden", "inert", "display-none", "content-visibility"] {
            let mut f = Fixture::default();
            let option = f.el("option", Some("option"), vec![]);
            f.facts_mut(&option).visible = false;
            let select = f.el("select", Some("combobox"), vec![option]);
            let ancestor = f.el("div", None, vec![select]);
            if suppression == "content-visibility" {
                f.facts_mut(&ancestor).skips_content = true;
            } else {
                f.facts_mut(&ancestor).suppress = true;
            }
            let separate_option = f.el("option", Some("option"), vec![]);
            f.facts_mut(&separate_option).visible = false;
            let separate = f.el("select", Some("combobox"), vec![separate_option.clone()]);
            let nodes = f.run(vec![ancestor, separate.clone()]);
            assert_eq!(
                flat(&nodes)
                    .iter()
                    .map(|node| node.reference.id.clone())
                    .collect::<Vec<_>>(),
                vec![reference(&separate), reference(&separate_option)],
                "{suppression}"
            );
        }
        // A select that skips its own content cannot re-enable child options.
        let mut f = Fixture::default();
        let option = f.el("option", Some("option"), vec![]);
        let select = f.el("select", Some("combobox"), vec![option]);
        f.facts_mut(&select).skips_content = true;
        let nodes = f.run(vec![select.clone()]);
        assert_eq!(flat(&nodes).len(), 1);
        assert_eq!(nodes[0].reference.id, reference(&select));
    }

    #[test]
    fn option_exception_does_not_rebind_optgroup_or_unowned_nodes() {
        let mut f = Fixture::default();
        let unowned = f.el("option", Some("option"), vec![]);
        f.facts_mut(&unowned).visible = false;
        let grouped = f.el("option", Some("option"), vec![]);
        let group = f.el("optgroup", Some("group"), vec![grouped.clone()]);
        let select = f.el("select", Some("combobox"), vec![group.clone()]);
        let nodes = f.run(vec![unowned, select.clone()]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].reference.id, reference(&select));
        assert_eq!(nodes[0].children[0].reference.id, reference(&group));
        assert_eq!(
            nodes[0].children[0].children[0].reference.id,
            reference(&grouped)
        );
        // This correction does not flatten optgroups or broaden the existing
        // direct-option exception to unrelated native ownership branches.
    }

    #[test]
    fn hidden_select_branch_uses_no_publication_budget_or_omitted_references() {
        let mut f = Fixture::default();
        let hidden_options = (0..4)
            .map(|_| f.el("option", Some("option"), vec![]))
            .collect();
        let hidden = f.el("select", Some("combobox"), hidden_options);
        f.facts_mut(&hidden).visible = false;
        let first = f.el("option", Some("option"), vec![]);
        let second = f.el("option", Some("option"), vec![]);
        f.facts_mut(&first).visible = false;
        f.facts_mut(&second).visible = false;
        let shown = f.el(
            "select",
            Some("combobox"),
            vec![first.clone(), second.clone()],
        );
        let root = f.node(
            9,
            Facts {
                visible: true,
                ..Default::default()
            },
            Some("document"),
            vec![hidden.clone(), shown.clone()],
        );
        let graph = Graph::read(&root).unwrap();
        let (nodes, truncated) = compact(&graph, f.nodes, 3).unwrap();
        assert!(truncated);
        let emitted = flat(&nodes);
        assert_eq!(
            emitted
                .iter()
                .map(|node| node.reference.id.clone())
                .collect::<Vec<_>>(),
            vec![reference(&root), reference(&shown), reference(&first)]
        );
        for omitted in [hidden, second] {
            assert!(!emitted
                .iter()
                .any(|node| node.reference.id == reference(&omitted)));
        }
    }

    #[test]
    fn line_keeps_independent_link_and_omits_formatting_duplicates() {
        let mut f = Fixture::default();
        let before = f.text("Read our ");
        let words = f.text("privacy policy");
        let link = f.el("a", Some("link"), vec![words]);
        let link_ref = reference(&link);
        let after = f.text(" for details.");
        let p = f.el("p", None, vec![before, link, after]);
        let nodes = f.run(vec![p]);
        assert_eq!(
            texts(&nodes),
            vec![
                Some("Read our privacy policy for details."),
                Some("privacy policy")
            ]
        );
        assert_eq!(nodes[0].children[0].reference.id, link_ref);
        let mut f = Fixture::default();
        let before = f.text("Use ");
        let bold = f.text("bold ");
        let strong = f.el("strong", None, vec![bold]);
        let code = f.text("code");
        let code = f.el("code", None, vec![code]);
        let p = f.el("p", None, vec![before, strong, code]);
        assert_eq!(texts(&f.run(vec![p])), vec![Some("Use bold code")]);
    }
    #[test]
    fn coverage_preserves_test_id_and_roleless_action_endpoints() {
        let mut f = Fixture::default();
        let before = f.text("Total ");
        let amount = f.text("$10");
        let span = f.el("span", None, vec![amount]);
        f.nodes
            .get_mut(&span["backendNodeId"].as_i64().unwrap())
            .unwrap()
            .test_id = Some("total".into());
        let span_ref = reference(&span);
        let after = f.text(" due today");
        let p = f.el("p", None, vec![before, span, after]);
        let nodes = f.run(vec![p]);
        assert_eq!(
            texts(&nodes),
            vec![Some("Total $10 due today"), Some("$10")]
        );
        assert_eq!(nodes[0].children[0].reference.id, span_ref);
        let mut f = Fixture::default();
        let before = f.text("Text ");
        let label = f.text("change");
        let span = f.el("span", None, vec![label]);
        f.facts_mut(&span).action = true;
        let after = f.text(" here");
        let p = f.el("p", None, vec![before, span, after]);
        assert_eq!(
            texts(&f.run(vec![p])),
            vec![Some("Text change here"), Some("change")]
        );
    }
    #[test]
    fn wrapper_without_direct_text_promotes_children_without_losing_button_label() {
        let mut f = Fixture::default();
        let one = f.text("One");
        let one = f.el("span", None, vec![one]);
        let two = f.text("Two");
        let two = f.el("span", None, vec![two]);
        let wrapper = f.el("div", None, vec![one, two]);
        let save = f.text("Save");
        let span = f.el("span", None, vec![save]);
        let button = f.el("button", Some("button"), vec![span]);
        assert_eq!(
            texts(&f.run(vec![wrapper, button])),
            vec![Some("One"), Some("Two"), None, Some("Save")]
        );
    }
    #[test]
    fn block_and_control_boundaries_separate_text_and_hidden_runs_contribute_nothing() {
        let mut f = Fixture::default();
        let intro = f.text("Intro");
        let block = f.text("Block");
        let block = f.el("p", None, vec![block]);
        let tail = f.text("tail");
        let div = f.el("div", None, vec![intro, block, tail]);
        let one = f.text("one");
        let br = f.el("br", None, vec![]);
        let two = f.text("two");
        let p = f.el("p", None, vec![one, br, two]);
        let shown = f.text("Shown ");
        let hidden = f.text("secret");
        let hidden = f.el("span", None, vec![hidden]);
        f.facts_mut(&hidden).suppress = true;
        let end = f.text(" end");
        let hidden_p = f.el("p", None, vec![shown, hidden, end]);
        assert_eq!(
            texts(&f.run(vec![div, p, hidden_p])),
            vec![
                Some("Intro tail"),
                Some("Block"),
                Some("one two"),
                Some("Shown end")
            ]
        );
    }
    #[test]
    fn native_shadow_and_slot_edges_supply_rendered_order_not_duplicate_light_text() {
        let mut f = Fixture::default();
        let before = f.text("Hello ");
        let ada = f.text("Ada");
        let dear = f.text("dear ");
        let mut slot = f.el("slot", None, vec![]);
        // Empty fallback has no raw box, but the visible slot renders its
        // native assigned text into the surrounding line.
        f.facts_mut(&slot).visible = false;
        f.facts_mut(&slot).line_visible = Some(true);
        slot["distributedNodes"] = json!([{"backendNodeId":ada["backendNodeId"]}]);
        let mut host = f.el("host", None, vec![ada]);
        host["shadowRoots"] = json!([{"nodeType":11,"backendNodeId":999,"shadowRootType":"closed","children":[dear,slot]}]);
        let end = f.text("!");
        let p = f.el("p", None, vec![before, host, end]);
        assert_eq!(texts(&f.run(vec![p])), vec![Some("Hello dear Ada!")]);
    }
    #[test]
    fn skipped_content_keeps_owner_but_drops_descendant_lines_and_controls() {
        let mut f = Fixture::default();
        let text = f.text("Skipped text");
        let button_text = f.text("Skipped");
        let button = f.el("button", Some("button"), vec![button_text]);
        let owner = f.el("div", Some("group"), vec![text, button]);
        f.facts_mut(&owner).skips_content = true;
        let owner_ref = reference(&owner);
        let nodes = f.run(vec![owner]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].reference.id, owner_ref);
        assert_eq!(nodes[0].text.as_deref(), Some(""));
        assert!(nodes[0].children.is_empty());
        assert_ne!(nodes[0].states.get("hidden"), Some(&true));
    }
    #[test]
    fn skipped_content_excludes_pseudo_without_rebinding_unsuppressed_identity() {
        for skips in [false, true] {
            let mut f = Fixture::default();
            let mut pseudo = f.el("", Some("text"), vec![]);
            pseudo["pseudoType"] = json!("before");
            let pseudo_ref = reference(&pseudo);
            let mut owner = f.el("div", Some("group"), vec![]);
            owner["pseudoElements"] = json!([pseudo]);
            f.facts_mut(&owner).skips_content = skips;
            let nodes = f.run(vec![owner]);
            if skips {
                assert_eq!(flat(&nodes).len(), 1);
            } else {
                assert!(flat(&nodes)
                    .iter()
                    .any(|node| node.reference.id == pseudo_ref));
            }
        }
    }

    #[test]
    fn skipped_closed_slot_uses_native_distributed_parent_not_light_parent() {
        let mut f = Fixture::default();
        let text = f.text("Skipped slotted text");
        let span = f.el("span", Some("button"), vec![text]);
        let mut slot = f.el("slot", None, vec![]);
        f.facts_mut(&slot).skips_content = true;
        slot["distributedNodes"] = json!([{"backendNodeId":span["backendNodeId"]}]);
        let mut host = f.el("host", Some("group"), vec![span]);
        host["shadowRoots"] = json!([{"nodeType":11,"backendNodeId":999,"shadowRootType":"closed","children":[slot]}]);
        let nodes = f.run(vec![host]);
        assert_eq!(flat(&nodes).len(), 1);
        assert!(nodes[0].children.is_empty());
        assert_eq!(nodes[0].text, None);
    }

    #[test]
    fn hidden_slot_breaks_coverage_but_visible_assigned_endpoint_survives() {
        let mut f = Fixture::default();
        let before = f.text("Status ");
        let words = f.text("shown");
        let span = f.el("span", None, vec![words]);
        let span_ref = reference(&span);
        let mut slot = f.el("slot", None, vec![]);
        f.facts_mut(&slot).visible = false;
        f.facts_mut(&slot).line_visible = Some(false);
        slot["distributedNodes"] = json!([{"backendNodeId":span["backendNodeId"]}]);
        let mut host = f.el("host", None, vec![span]);
        host["shadowRoots"] =
            json!([{"nodeType":11,"backendNodeId":999,"shadowRootType":"open","children":[slot]}]);
        let end = f.text(" end");
        let p = f.el("p", None, vec![before, host, end]);
        let nodes = f.run(vec![p]);
        assert_eq!(texts(&nodes), vec![Some("Status end"), Some("shown")]);
        assert_eq!(flat(&nodes)[1].reference.id, span_ref);
    }
    #[test]
    fn overlong_line_never_claims_coverage_of_truncated_inline_descendant() {
        let mut f = Fixture::default();
        let prefix = f.text(&"word ".repeat(120));
        let total = f.text("Total: $42");
        let strong = f.el("strong", None, vec![total]);
        let p = f.el("p", None, vec![prefix, strong]);
        let nodes = f.run(vec![p]);
        assert_eq!(flat(&nodes).len(), 2);
        assert_eq!(flat(&nodes)[1].text.as_deref(), Some("Total: $42"));
        assert_eq!(nodes[0].text.as_ref().unwrap().chars().count(), 512);
    }
    #[test]
    fn overflow_space_cannot_falsely_cover_following_inline_text() {
        let mut f = Fixture::default();
        let prefix = f.text(&("x".repeat(512) + " "));
        let tail = f.text("tail");
        let span = f.el("span", None, vec![tail]);
        let p = f.el("p", None, vec![prefix, span]);
        let nodes = f.run(vec![p]);
        assert_eq!(flat(&nodes).len(), 2);
        assert_eq!(flat(&nodes)[1].text.as_deref(), Some("tail"));
    }
    #[test]
    fn empty_author_shadow_does_not_render_unassigned_light_text() {
        let graph = Graph::read(&json!({"nodeType":1,"backendNodeId":1,"children":[
            {"nodeType":3,"backendNodeId":2}],"shadowRoots":[
            {"nodeType":11,"backendNodeId":3,"shadowRootType":"closed","children":[]}]}))
        .unwrap();
        assert!(graph.entries[&1].rendered.is_empty());
        assert_eq!(graph.entries[&1].children, vec![2]);
    }
    #[test]
    fn graph_budget_counts_nonretained_nodes_before_descent() {
        let root = json!({"nodeType":9,"backendNodeId":1,"children":
            (0..LIMIT).map(|_| json!({"nodeType":8})).collect::<Vec<_>>()});
        assert!(matches!(
            Graph::read(&root),
            Err(ObservationError::ResourceLimit)
        ));
        let edges = json!({"nodeType":1,"backendNodeId":1,"distributedNodes":
            (0..LIMIT).map(|_| json!({"backendNodeId":2})).collect::<Vec<_>>()});
        assert!(matches!(
            Graph::read(&edges),
            Err(ObservationError::ResourceLimit)
        ));
    }
    #[test]
    fn graph_rejects_conflicting_or_missing_native_slot_evidence() {
        let mut root = json!({"nodeType":1,"backendNodeId":1,"children":[
            {"nodeType":1,"backendNodeId":2,"assignedSlot":{"backendNodeId":3}},
            {"nodeType":1,"backendNodeId":3,"distributedNodes":[{"backendNodeId":2}]}]});
        assert!(Graph::read(&root).is_ok());
        root["children"][1]
            .as_object_mut()
            .unwrap()
            .remove("distributedNodes");
        assert!(Graph::read(&root).is_err());
        root["children"][1]["distributedNodes"] = json!([{"backendNodeId":2}]);
        root["children"][0]["assignedSlot"] = json!({"backendNodeId":4});
        assert!(Graph::read(&root).is_err());
    }
    #[test]
    fn graph_rejects_unproven_slot_target_and_duplicate_native_identity() {
        assert!(Graph::read(
            &json!({"nodeType":1,"backendNodeId":1,"distributedNodes":[{"backendNodeId":2}]})
        )
        .is_err());
        assert!(Graph::read(
            &json!({"nodeType":1,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":1}]})
        )
        .is_err());
    }
}
