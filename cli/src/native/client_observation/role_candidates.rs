//! Conservative role-query acquisition, not a second matcher or reference store.
//! Unknown public-role facts are varied through the production projection. Only
//! proved nonmatches may be omitted; selected receivers retain exact identity.
use super::*;
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, PartialEq)]
pub(super) struct Plan {
    pub ids: Vec<i64>,
    pub roots: fresh_query::RootInventory,
    dom: BTreeMap<i64, Value>,
    ax: BTreeMap<String, Value>,
}

fn extend_bounded<T>(
    target: &mut Vec<T>,
    values: impl IntoIterator<Item = T>,
) -> Result<(), ObservationError> {
    for value in values {
        if target.len() >= 100_000 {
            return Err(ObservationError::ResourceLimit);
        }
        target.push(value);
    }
    Ok(())
}

fn roles(expression: &LocatorExpression, out: &mut BTreeSet<String>) -> bool {
    match expression {
        LocatorExpression::Query { query, scope } => {
            let TextPattern::String { value, .. } = &query.value else {
                return false;
            };
            if !matches!(query.kind, QueryKind::Role) {
                return false;
            }
            out.insert(value.clone());
            scope.as_deref().is_none_or(|scope| roles(scope, out))
        }
        LocatorExpression::Filter { source, has, .. } => {
            roles(source, out) && has.as_deref().is_none_or(|has| roles(has, out))
        }
        LocatorExpression::Index { source, .. } => roles(source, out),
        LocatorExpression::Union { left, right } => roles(left, out) && roles(right, out),
        LocatorExpression::Selector { .. } | LocatorExpression::Frame { .. } => false,
    }
}

fn attributes(node: &Value) -> Result<Value, ObservationError> {
    let mut result = serde_json::Map::new();
    if let Some(values) = node.get("attributes") {
        let values = values.as_array().ok_or(ObservationError::BackendFailure)?;
        if values.len() % 2 != 0 {
            return Err(ObservationError::BackendFailure);
        }
        for pair in values.chunks_exact(2) {
            let key = pair[0].as_str().ok_or(ObservationError::BackendFailure)?;
            if !pair[1].is_string() || result.insert(key.into(), pair[1].clone()).is_some() {
                return Err(ObservationError::BackendFailure);
            }
        }
    }
    Ok(Value::Object(result))
}

/// A finite upper bound over every renderer fact read by project_public_role.
/// Name/state/visibility never narrow this set. AX omissions, authored tokens,
/// presentation conflicts, editor and implicit author projections are retained.
fn possible_roles(
    ax: &AXNode,
    tag: &str,
    attributes: &Value,
) -> Result<BTreeSet<String>, ObservationError> {
    let author = Some(author_projection::Facts {
        tag: tag.into(),
        node_type: 1,
        ..Default::default()
    });
    let mut facts = vec![json!({"attributes":attributes})];
    let mut dimensions = vec![
        ("presentationConflict", vec![json!(false), json!(true)]),
        ("editingHost", vec![json!(false), json!(true)]),
    ];
    match tag {
        "header" | "footer" => {
            dimensions.push(("pageLevelLandmark", vec![json!(false), json!(true)]))
        }
        "form" => dimensions.push(("formOwnName", vec![json!(false), json!(true)])),
        "img" => dimensions.push(("decorativeImage", vec![json!(false), json!(true)])),
        "select" => dimensions.push(("selectListbox", vec![json!(false), json!(true)])),
        "input" => dimensions.push(("inputDatalist", vec![json!(false), json!(true)])),
        "td" => dimensions.push(("cellTableRole", vec![Value::Null, json!("grid")])),
        "th" => {
            dimensions.push(("singleCellHeader", vec![json!(false), json!(true)]));
            dimensions.push((
                "conflictHeaderRole",
                vec![Value::Null, json!("rowheader"), json!("columnheader")],
            ));
        }
        _ => {}
    }
    for (key, values) in dimensions {
        facts = facts
            .into_iter()
            .flat_map(|fact| {
                values.iter().map(move |value| {
                    let mut fact = fact.clone();
                    fact[key] = value.clone();
                    fact
                })
            })
            .collect();
    }
    let mut result = BTreeSet::new();
    for fact in facts {
        if let Some(role) = project_public_role(ax, &fact, &author)? {
            result.insert(role);
        }
    }
    Ok(result)
}

/// The witness contains full candidate content and naming dependencies, but only
/// shallow ancestor facts. Thus replacing an unrelated sibling does not poison
/// a stable receiver; a changed related label, scope, role or secure boundary does.
pub(super) fn plan(
    root: &Value,
    ax_value: &Value,
    expression: &LocatorExpression,
    options: &QueryOptions,
) -> Result<Option<Plan>, ObservationError> {
    let mut wanted = BTreeSet::new();
    if options.secure_field_selector != default_secure_selector() || !roles(expression, &mut wanted)
    {
        return Ok(None);
    }
    let Some(roots) = fresh_query::roots(root)? else {
        return Ok(None);
    };
    let mut records = BTreeMap::new();
    let mut attrs = BTreeMap::new();
    let mut children: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    let mut by_id: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    let mut labels: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    let mut pending = vec![(root, None, 0usize)];
    while let Some((node, parent, depth)) = pending.pop() {
        if node.get("pseudoType").is_some() || node["shadowRootType"] == "user-agent" {
            continue;
        }
        if records.len() >= 100_000 || pending.len() > 100_000 || depth > 256 {
            return Err(ObservationError::ResourceLimit);
        }
        let id = node["backendNodeId"]
            .as_i64()
            .filter(|id| *id > 0)
            .ok_or(ObservationError::BackendFailure)?;
        // METADATA projects author.tag from Element.localName, not nodeName.
        // Qualified names and XML/SVG case are meaningful; never strip a prefix
        // or lowercase a guessed substitute. An unavailable native fact declines
        // this optimization before metadata acquisition, never proves absence.
        let tag = if node["nodeType"] == 1 {
            let Some(local) = node["localName"].as_str().filter(|local| {
                !local.is_empty()
                    && !local
                        .chars()
                        .any(|ch| ch.is_whitespace() || ch.is_control())
            }) else {
                return Ok(None);
            };
            local.to_owned()
        } else {
            String::new()
        };
        let attributes = attributes(node)?;
        // Ownership and slot redistribution require a composed dependency proof.
        // Keep the complete native path rather than infer their absence locally.
        if attributes.get("aria-owns").is_some()
            || tag == "slot"
            || node["distributedNodes"]
                .as_array()
                .is_some_and(|nodes| !nodes.is_empty())
        {
            return Ok(None);
        }
        if let Some(name) = attributes["id"].as_str() {
            by_id.entry(name.into()).or_default().push(id);
        }
        if tag == "label" {
            if let Some(target) = attributes["for"].as_str() {
                labels.entry(target.into()).or_default().push(id);
            }
        }
        if let Some(parent) = parent {
            children.entry(parent).or_default().push(id);
        }
        if records.insert(id, (node, parent, tag)).is_some() {
            return Err(ObservationError::BackendFailure);
        }
        attrs.insert(id, attributes);
        if matches!(node["nodeType"].as_i64(), Some(1 | 9 | 11)) {
            let list = node["children"].as_array();
            if node["childNodeCount"]
                .as_u64()
                .map_or(list.is_none(), |count| {
                    count as usize != list.map_or(0, Vec::len)
                })
            {
                return Ok(None);
            }
        }
        for key in ["children", "shadowRoots"] {
            if let Some(list) = node[key].as_array() {
                if pending.len().saturating_add(list.len()) > 100_000 {
                    return Err(ObservationError::ResourceLimit);
                }
                pending.extend(list.iter().rev().map(|child| (child, Some(id), depth + 1)));
            } else if node.get(key).is_some() {
                return Ok(None);
            }
        }
    }
    let rows = ax_value["nodes"]
        .as_array()
        .ok_or(ObservationError::BackendFailure)?;
    if rows.len() > 100_000 {
        return Err(ObservationError::ResourceLimit);
    }
    let mut ax_rows = BTreeMap::new();
    let mut ax_backend = HashMap::new();
    for row in rows {
        let parsed: AXNode =
            serde_json::from_value(row.clone()).map_err(|_| ObservationError::BackendFailure)?;
        if let Some(id) = parsed.backend_d_o_m_node_id {
            ax_backend.insert(id, parsed.clone());
        }
        if ax_rows.insert(parsed.node_id, row).is_some() {
            return Err(ObservationError::BackendFailure);
        }
    }
    let mut ids = Vec::new();
    for id in author_query_ids(root)? {
        let (_, _, tag) = records.get(&id).ok_or(ObservationError::BackendFailure)?;
        let empty = AXNode {
            node_id: String::new(),
            role: None,
            name: None,
            value: None,
            description: None,
            properties: None,
            child_ids: None,
            backend_d_o_m_node_id: Some(id),
            ignored: None,
        };
        if !possible_roles(ax_backend.get(&id).unwrap_or(&empty), tag, &attrs[&id])?
            .is_disjoint(&wanted)
        {
            ids.push(id);
        }
    }
    let mut full = HashSet::new();
    let mut shallow = HashSet::new();
    let mut dependencies = ids.clone();
    // CSS rules can participate in public names/content; record authored style
    // sheets conservatively, without making unrelated element IDs witnesses.
    extend_bounded(
        &mut dependencies,
        records
            .iter()
            .filter(|(id, (_, _, tag))| {
                tag == "style"
                    || tag == "link"
                        && attrs[id]["rel"].as_str().is_some_and(|rel| {
                            rel.split_ascii_whitespace()
                                .any(|part| part.eq_ignore_ascii_case("stylesheet"))
                        })
            })
            .map(|(id, _)| *id),
    )?;
    let mut ax = BTreeMap::new();
    let mut ax_pending = Vec::new();
    let mut work = 0usize;
    while !dependencies.is_empty() || !ax_pending.is_empty() {
        work += 1;
        if work > 1_000_000 || full.len().saturating_add(ax.len()) > 200_000 {
            return Err(ObservationError::ResourceLimit);
        }
        if let Some(id) = dependencies.pop() {
            if !full.insert(id) {
                continue;
            }
            let Some((_, parent, _)) = records.get(&id) else {
                return Ok(None);
            };
            extend_bounded(
                &mut dependencies,
                children.get(&id).into_iter().flatten().copied(),
            )?;
            if let Some(row) = ax_backend.get(&id) {
                extend_bounded(&mut ax_pending, [row.node_id.clone()])?;
            }
            if let Some(name) = attrs[&id]["id"].as_str() {
                extend_bounded(
                    &mut dependencies,
                    labels.get(name).into_iter().flatten().copied(),
                )?;
            }
            if let Some(names) = attrs[&id]["aria-labelledby"].as_str() {
                for name in names
                    .split(ecmascript_whitespace)
                    .filter(|name| !name.is_empty())
                {
                    extend_bounded(
                        &mut dependencies,
                        by_id.get(name).into_iter().flatten().copied(),
                    )?;
                }
            }
            let mut parent = *parent;
            while let Some(id) = parent {
                if !shallow.insert(id) {
                    break;
                }
                let (_, next, tag) = &records[&id];
                if tag == "label" {
                    extend_bounded(&mut dependencies, [id])?;
                }
                parent = *next;
            }
        } else if let Some(id) = ax_pending.pop() {
            if ax.contains_key(&id) {
                continue;
            }
            let Some(row) = ax_rows.get(&id) else {
                return Ok(None);
            };
            ax.insert(id, (*row).clone());
            if let Some(values) = row["childIds"].as_array() {
                for value in values {
                    extend_bounded(
                        &mut ax_pending,
                        [value
                            .as_str()
                            .map(str::to_owned)
                            .or_else(|| value.as_i64().map(|value| value.to_string()))
                            .ok_or(ObservationError::BackendFailure)?],
                    )?;
                }
            }
            let mut values = vec![*row];
            let mut count = 0usize;
            while let Some(value) = values.pop() {
                count += 1;
                if count > 100_000 || values.len() > 100_000 {
                    return Err(ObservationError::ResourceLimit);
                }
                match value {
                    Value::Object(object) => {
                        if let Some(id) = object.get("backendDOMNodeId").and_then(Value::as_i64) {
                            if records.contains_key(&id) {
                                extend_bounded(&mut dependencies, [id])?;
                            }
                        }
                        extend_bounded(&mut values, object.values())?;
                    }
                    Value::Array(array) => extend_bounded(&mut values, array)?,
                    _ => {}
                }
            }
        }
    }
    let mut dom = BTreeMap::new();
    for id in full.union(&shallow) {
        let (node, parent, _) = &records[id];
        // Never clone a subtree only to discard it: ancestor records are shallow
        // and the already bounded graph owns descendant enumeration.
        let mut object: serde_json::Map<String, Value> = node
            .as_object()
            .ok_or(ObservationError::BackendFailure)?
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "nodeId"
                        | "parentId"
                        | "children"
                        | "shadowRoots"
                        | "pseudoElements"
                        // Separate frame documents and inert/legacy inventories
                        // are not traversed by author_query_ids/security_root_ids.
                        // Frame owner facts and the caller's frame proof remain.
                        | "contentDocument"
                        | "templateContent"
                        | "importedDocument"
                        | "childNodeCount"
                )
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        object.insert("nativeParent".into(), json!(parent));
        if full.contains(id) {
            object.insert(
                "nativeChildren".into(),
                json!(children.get(id).cloned().unwrap_or_default()),
            );
        }
        dom.insert(*id, Value::Object(object));
    }
    Ok(Some(Plan {
        ids,
        roots,
        dom,
        ax,
    }))
}

pub(super) fn same_security(
    left: &SecurityInventory,
    right: &SecurityInventory,
    ids: &[i64],
) -> bool {
    left.ancestors == right.ancestors
        && left.label_ids == right.label_ids
        && left.simple_name_inventory == right.simple_name_inventory
        && ids.iter().all(|id| {
            left.local_name_inventory.contains(id) == right.local_name_inventory.contains(id)
                && (left.focused_backend == Some(*id)) == (right.focused_backend == Some(*id))
        })
}

pub(super) fn matching_facts(nodes: &[SemanticNode]) -> Value {
    json!(nodes
        .iter()
        .map(|node| json!({
            "role":node.role,"name":node.name,"level":node.level,"states":node.states,
            "labels":node.labels,"safeName":node.safe_public_name,"attributes":node.attributes,
            "text":node.text,"value":node.value
        }))
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(id: i64, tag: &str, attrs: Value, children: Vec<Value>) -> Value {
        json!({"backendNodeId":id,"nodeType":if tag=="#document" {9}else {1},"nodeName":tag,"localName":if tag=="#document" {String::new()}else{tag.to_ascii_lowercase()},"attributes":attrs,"childNodeCount":children.len(),"children":children})
    }
    fn row(id: i64, role: &str, name: &str) -> Value {
        json!({"nodeId":id.to_string(),"role":{"type":"role","value":role},"name":{"type":"computedString","value":name},"backendDOMNodeId":id,"ignored":false})
    }
    fn options(expression: Value) -> QueryOptions {
        serde_json::from_value(json!({"expression":expression,"testIdAttribute":"data-testid","secureFieldSelector":default_secure_selector()})).unwrap()
    }
    fn query(role: &str) -> Value {
        json!({"kind":"query","query":{"kind":"role","value":{"kind":"string","value":role,"exact":true}}})
    }
    fn fixture() -> (Value, Value, QueryOptions) {
        let d = node(
            1,
            "#document",
            json!([]),
            vec![node(
                2,
                "BODY",
                json!([]),
                vec![
                    node(3, "BUTTON", json!([]), vec![]),
                    node(
                        4,
                        "INPUT",
                        json!(["id", "nickname", "type", "text"]),
                        vec![],
                    ),
                ],
            )],
        );
        let a = json!({"nodes":[row(3,"button","Remove"),row(4,"textbox","Nickname")]});
        (d, a, options(query("button")))
    }
    fn plan_of(d: &Value, a: &Value, o: &QueryOptions) -> Plan {
        plan(d, a, &o.expression, o).unwrap().unwrap()
    }
    #[test]
    fn unrelated_replacement_does_not_enter_candidate_or_witness() {
        let (d, a, o) = fixture();
        let p = plan_of(&d, &a, &o);
        assert_eq!(p.ids, vec![3]);
        let mut d2 = d.clone();
        d2["children"][0]["children"][1]["backendNodeId"] = json!(40);
        let a2 = json!({"nodes":[row(3,"button","Remove"),row(40,"textbox","Nickname")]});
        assert_eq!(p, plan_of(&d2, &a2, &o));
    }
    #[test]
    fn additions_role_and_name_changes_refuse_old_plan() {
        let (d, a, o) = fixture();
        let p = plan_of(&d, &a, &o);
        let mut changed = a.clone();
        changed["nodes"][1] = row(4, "button", "New");
        assert_ne!(p, plan_of(&d, &changed, &o));
        let mut changed = a.clone();
        changed["nodes"][0] = row(3, "button", "Changed");
        assert_ne!(p, plan_of(&d, &changed, &o));
        let mut d2 = d.clone();
        d2["children"][0]["children"]
            .as_array_mut()
            .unwrap()
            .push(node(5, "DIV", json!(["role", "button"]), vec![]));
        d2["children"][0]["childNodeCount"] = json!(3);
        assert_eq!(plan_of(&d2, &a, &o).ids, vec![3, 5]);
    }
    #[test]
    fn external_labels_idrefs_and_ancestors_are_witnesses() {
        let (mut d, a, o) = fixture();
        d["children"][0]["children"][0]["attributes"] =
            json!(["id", "target", "aria-labelledby", "external"]);
        d["children"][0]["children"]
            .as_array_mut()
            .unwrap()
            .extend([
                node(6, "SPAN", json!(["id", "external", "title", "Old"]), vec![]),
                node(7, "LABEL", json!(["for", "target", "title", "Old"]), vec![]),
            ]);
        d["children"][0]["childNodeCount"] = json!(4);
        let p = plan_of(&d, &a, &o);
        assert!(p.dom.contains_key(&6) && p.dom.contains_key(&7));
        for idx in [2, 3] {
            let mut changed = d.clone();
            changed["children"][0]["children"][idx]["attributes"]
                .as_array_mut()
                .unwrap()
                .push(json!("lang"));
            changed["children"][0]["children"][idx]["attributes"]
                .as_array_mut()
                .unwrap()
                .push(json!("fr"));
            assert_ne!(p, plan_of(&changed, &a, &o));
        }
        let mut changed = d.clone();
        changed["children"][0]["attributes"] = json!(["aria-disabled", "true"]);
        assert_ne!(p, plan_of(&changed, &a, &o));
    }
    #[test]
    fn unknown_ownership_slot_custom_policy_and_nonrole_decline() {
        let (d, a, o) = fixture();
        for attrs in [json!(["aria-owns", ""]), json!(["aria-owns", "nickname"])] {
            let mut changed = d.clone();
            changed["children"][0]["attributes"] = attrs;
            assert!(plan(&changed, &a, &o.expression, &o).unwrap().is_none());
        }
        let mut changed = d.clone();
        changed["children"][0]["nodeName"] = json!("SLOT");
        changed["children"][0]["localName"] = json!("slot");
        assert!(plan(&changed, &a, &o.expression, &o).unwrap().is_none());
        let mut custom = o.clone();
        custom.secure_field_selector = "[secret]".into();
        assert!(plan(&d, &a, &custom.expression, &custom).unwrap().is_none());
        let o = options(
            json!({"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"nickname","exact":true}}}),
        );
        assert!(plan(&d, &a, &o.expression, &o).unwrap().is_none());
    }
    #[test]
    fn scope_has_union_operands_all_contribute_roles() {
        let (d, a, _) = fixture();
        let expression = json!({"kind":"filter","source":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"button","exact":true}},"scope":query("textbox")},"has":{"kind":"union","left":query("heading"),"right":query("row")}});
        let o = options(expression);
        assert_eq!(plan_of(&d, &a, &o).ids, vec![2, 3, 4]); /* Unknown editingHost keeps BODY conservatively. */
    }
    #[test]
    fn secure_and_closed_root_changes_cannot_be_absence() {
        let (d, a, o) = fixture();
        let p = plan_of(&d, &a, &o);
        let mut changed = d.clone();
        changed["children"][0]["shadowRoots"] = json!([{"backendNodeId":8,"nodeType":11,"nodeName":"#document-fragment","shadowRootType":"closed","childNodeCount":0,"children":[]}]);
        assert_ne!(p, plan_of(&changed, &a, &o));
        let mut left = SecurityInventory::default();
        let mut right = SecurityInventory::default();
        assert!(same_security(&left, &right, &[3]));
        right.ancestors.insert(2);
        assert!(!same_security(&left, &right, &[3]));
        left.ancestors.insert(2);
        right.label_ids.insert("secret".into());
        assert!(!same_security(&left, &right, &[3]));
    }
    #[test]
    fn public_role_upper_bound_contains_original_projection() {
        let tags = [
            "div", "button", "input", "h1", "form", "table", "tr", "tbody", "canvas", "svg", "img",
            "td", "th", "header", "footer", "select", "summary", "dt", "iframe", "a", "section",
            "textarea",
        ];
        let ax_roles = [
            "",
            "generic",
            "none",
            "button",
            "textbox",
            "rowheader",
            "columnheader",
            "img",
            "Iframe",
            "Date",
            "RootWebArea",
            "StaticText",
        ];
        let keys = [
            "presentationConflict",
            "editingHost",
            "pageLevelLandmark",
            "formOwnName",
            "decorativeImage",
            "selectListbox",
            "inputDatalist",
            "singleCellHeader",
        ];
        let mut checked = 0;
        for tag in tags {
            for ax_role in ax_roles {
                for authored in [
                    None,
                    Some("presentation"),
                    Some("button"),
                    Some("none heading"),
                ] {
                    let ax: AXNode = serde_json::from_value(row(3, ax_role, "")).unwrap();
                    let attrs = json!({"role":authored,"type":"text"});
                    let bound = possible_roles(&ax, tag, &attrs).unwrap();
                    let author = Some(author_projection::Facts {
                        tag: tag.into(),
                        node_type: 1,
                        ..Default::default()
                    });
                    for mask in 0..256 {
                        for cell in [Value::Null, json!("grid"), json!("treegrid")] {
                            for header in [Value::Null, json!("rowheader"), json!("columnheader")] {
                                let mut data = json!({"attributes":attrs,"cellTableRole":cell,"conflictHeaderRole":header});
                                for (bit, key) in keys.iter().enumerate() {
                                    data[*key] = json!(mask & (1 << bit) != 0);
                                }
                                if let Some(actual) =
                                    project_public_role(&ax, &data, &author).unwrap()
                                {
                                    assert!(
                                        bound.contains(&actual),
                                        "{tag}/{ax_role}/{authored:?}/{mask}/{actual}"
                                    );
                                }
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 22 * 12 * 4 * 256 * 9);
    }
}
#[cfg(test)]
mod refusal_tests {
    use super::*;
    #[test]
    fn work_queue_is_bounded_before_growth() {
        let mut values = vec![0; 100_000];
        assert_eq!(
            extend_bounded(&mut values, [1]),
            Err(ObservationError::ResourceLimit)
        );
        assert_eq!(values.len(), 100_000);
    }
    #[test]
    fn public_role_fact_dimensions_are_a_closed_reviewed_set() {
        // A new renderer fact in the shared projection must extend the conservative
        // upper bound and its exhaustive oracle before it can exclude a candidate.
        let source = include_str!("../client_observation.rs");
        let start = source.find("fn project_public_role(").unwrap();
        let code = &source[start
            ..source[start..]
                .find("#[allow(clippy::too_many_arguments)]")
                .unwrap()
                + start];
        let mut keys = BTreeSet::new();
        let mut rest = code;
        while let Some(pos) = rest.find("data[\"") {
            rest = &rest[pos + 6..];
            let end = rest.find('"').unwrap();
            keys.insert(&rest[..end]);
            rest = &rest[end + 1..];
        }
        rest = code;
        while let Some(pos) = rest.find(".get(\"") {
            rest = &rest[pos + 6..];
            let end = rest.find('"').unwrap();
            keys.insert(&rest[..end]);
            rest = &rest[end + 1..];
        }
        // conflictHeaderRole is accessed with .get as well as indexing in this helper.
        assert_eq!(
            keys,
            BTreeSet::from([
                "__nativeReadonlyPseudo",
                "attributes",
                "cellTableRole",
                "conflictHeaderRole",
                "decorativeImage",
                "editingHost",
                "formOwnName",
                "href",
                "inputDatalist",
                "pageLevelLandmark",
                "presentationConflict",
                "selectListbox",
                "singleCellHeader"
            ])
        );
    }
}

#[cfg(test)]
mod local_name_tests {
    use super::*;
    fn fixture(
        qualified: &str,
        local: Value,
        ax_role: &str,
        role: &str,
    ) -> (Value, Value, QueryOptions) {
        let dom = json!({"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","childNodeCount":1,"children":[{"backendNodeId":2,"nodeType":1,"nodeName":qualified,"localName":local,"attributes":[],"childNodeCount":0,"children":[]}]});
        let ax = json!({"nodes":[{"nodeId":"2","backendDOMNodeId":2,"role":{"type":"role","value":ax_role},"ignored":false}]});
        let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":role,"exact":true}}}})).unwrap();
        (dom, ax, options)
    }
    #[test]
    fn prefixed_native_local_names_preserve_the_public_role_upper_bound() {
        for (qualified, local, ax_role, wanted) in [
            ("s:svg", "svg", "SvgRoot", "image"),
            ("h:h1", "h1", "generic", "heading"),
            ("h:tr", "tr", "generic", "row"),
            ("h:form", "form", "generic", "form"),
        ] {
            let (dom, ax, options) = fixture(qualified, json!(local), ax_role, wanted);
            let original_ax: AXNode = serde_json::from_value(ax["nodes"][0].clone()).unwrap();
            let original = project_public_role(
                &original_ax,
                &json!({"attributes":{},"editingHost":false,"formOwnName":true}),
                &Some(author_projection::Facts {
                    tag: local.into(),
                    node_type: 1,
                    ..Default::default()
                }),
            )
            .unwrap();
            assert_eq!(original.as_deref(), Some(wanted));
            let acquired = plan(&dom, &ax, &options.expression, &options)
                .unwrap()
                .unwrap();
            assert_eq!(
                acquired.ids,
                vec![2],
                "qualified {qualified}, local {local}"
            );
        }
    }
    #[test]
    fn native_local_name_case_is_not_normalized_or_inferred_from_a_prefix() {
        for (qualified, local) in [("s:SVG", "SVG"), ("s:svg", "s:svg")] {
            let (dom, ax, options) = fixture(qualified, json!(local), "generic", "image");
            let original_ax: AXNode = serde_json::from_value(ax["nodes"][0].clone()).unwrap();
            assert_eq!(
                project_public_role(
                    &original_ax,
                    &json!({"attributes":{},"editingHost":false}),
                    &Some(author_projection::Facts {
                        tag: local.into(),
                        node_type: 1,
                        ..Default::default()
                    })
                )
                .unwrap(),
                None
            );
            assert!(plan(&dom, &ax, &options.expression, &options)
                .unwrap()
                .unwrap()
                .ids
                .is_empty());
        }
    }
    #[test]
    fn missing_or_untrustworthy_native_local_name_declines_instead_of_empty_results() {
        for local in [
            Value::Null,
            json!(17),
            json!({"toString":"svg"}),
            json!(""),
            json!("svg "),
            json!("svg\u{0000}"),
        ] {
            let (dom, ax, options) = fixture("s:svg", local, "SvgRoot", "image");
            assert!(plan(&dom, &ax, &options.expression, &options)
                .unwrap()
                .is_none());
        }
        let (mut dom, ax, options) = fixture("s:svg", json!("svg"), "SvgRoot", "image");
        dom["children"][0]
            .as_object_mut()
            .unwrap()
            .remove("localName");
        assert!(plan(&dom, &ax, &options.expression, &options)
            .unwrap()
            .is_none());
    }
}

#[cfg(test)]
mod foreign_inventory_tests {
    use super::*;
    #[test]
    fn foreign_nested_inventories_are_not_cloned_into_current_frame_witnesses() {
        let mut root = json!({"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","childNodeCount":1,"children":[{"backendNodeId":2,"nodeType":1,"nodeName":"IFRAME","localName":"iframe","frameId":"child-frame","attributes":["title","Content"],"childNodeCount":0,"children":[]}]});
        let ax = json!({"nodes":[{"nodeId":"2","backendDOMNodeId":2,"role":{"type":"role","value":"Iframe"}}]});
        let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"iframe","exact":true}}}})).unwrap();
        for key in ["contentDocument", "templateContent", "importedDocument"] {
            root["children"][0][key] = json!({"backendNodeId":90,"nodeType":9,"nodeName":"#document","localName":"","childNodeCount":1,"children":[{"backendNodeId":91,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":["type","password"],"childNodeCount":0,"children":[]}]});
        }
        let before = plan(&root, &ax, &options.expression, &options)
            .unwrap()
            .unwrap();
        assert_eq!(before.ids, vec![2]);
        assert_eq!(before.roots.0, vec![1]);
        for key in ["contentDocument", "templateContent", "importedDocument"] {
            assert!(before.dom[&2].get(key).is_none());
        }
        let mut changed = root.clone();
        for key in ["contentDocument", "templateContent", "importedDocument"] {
            changed["children"][0][key]["backendNodeId"] = json!(190);
            changed["children"][0][key]["children"][0]["backendNodeId"] = json!(191);
        }
        // These inventories were never part of current-frame query/security
        // enumeration. Removing them from a shallow record removes no such proof.
        assert_eq!(
            author_query_ids(&root).unwrap(),
            author_query_ids(&changed).unwrap()
        );
        assert_eq!(
            security_root_ids(&root).unwrap(),
            security_root_ids(&changed).unwrap()
        );
        assert_eq!(
            before,
            plan(&changed, &ax, &options.expression, &options)
                .unwrap()
                .unwrap()
        );
        // Keep actual owner/frame identity and author attributes in the witness.
        changed["children"][0]["frameId"] = json!("replacement-frame");
        assert_ne!(
            before,
            plan(&changed, &ax, &options.expression, &options)
                .unwrap()
                .unwrap()
        );
        changed = root.clone();
        changed["children"][0]["attributes"] = json!(["title", "Changed"]);
        assert_ne!(
            before,
            plan(&changed, &ax, &options.expression, &options)
                .unwrap()
                .unwrap()
        );
        // Author shadow roots remain part of native root/security acquisition.
        changed = root.clone();
        changed["children"][0]["shadowRoots"] = json!([{"backendNodeId":3,"nodeType":11,"nodeName":"#document-fragment","localName":"","shadowRootType":"closed","childNodeCount":0,"children":[]}]);
        assert_ne!(
            before,
            plan(&changed, &ax, &options.expression, &options)
                .unwrap()
                .unwrap()
        );
    }
}
