//! Atomic, reference-free samples for DOM-derived queries. AX-derived fields
//! keep the existing native AX path; a declined proof never becomes absence.
use super::*;

fn eligible(expression: &LocatorExpression, fields: &[ReadField]) -> bool {
    if fields.iter().any(|field| {
        matches!(
            field,
            ReadField::Role | ReadField::Name | ReadField::Level | ReadField::Rect
        )
    }) {
        return false;
    }
    fn dom_query(expression: &LocatorExpression) -> bool {
        match expression {
            LocatorExpression::Query { query, scope } => {
                !matches!(query.kind, QueryKind::Role) && scope.as_deref().is_none_or(dom_query)
            }
            LocatorExpression::Filter { source, has, .. } => {
                dom_query(source) && has.as_deref().is_none_or(dom_query)
            }
            LocatorExpression::Index { source, .. } => dom_query(source),
            LocatorExpression::Union { left, right } => dom_query(left) && dom_query(right),
            // Native selector-chain compilation is separate from DOM matching.
            LocatorExpression::Selector { .. } | LocatorExpression::Frame { .. } => false,
        }
    }
    dom_query(expression)
}

/// The native root inventory is authority for closed author roots and UA
/// exclusion. Churning element IDs are deliberately absent from the lease.
pub(super) type RootInventory = (Vec<i64>, Vec<bool>, Vec<usize>);

pub(super) fn roots(root: &Value) -> Result<Option<RootInventory>, ObservationError> {
    let internal = browser_internal_ids(root)?;
    let ids: Vec<i64> = security_root_ids(root)?
        .into_iter()
        .filter(|id| !internal.contains(id))
        .collect();
    let author = vec![true; ids.len()];
    // For the built-in password-only policy, an implementation root contributes
    // no additional secret unless it contains a password input itself. Decline
    // that case rather than resolving ephemeral UA roots across animation frames.
    let mut ua_pending = vec![root];
    while let Some(node) = ua_pending.pop() {
        if node["backendNodeId"]
            .as_i64()
            .is_some_and(|id| internal.contains(&id))
            && node["nodeName"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("input"))
            && node["attributes"].as_array().is_some_and(|attributes| {
                attributes.as_chunks::<2>().0.iter().any(|pair| {
                    pair[0] == "type"
                        && pair[1]
                            .as_str()
                            .is_some_and(|value| value.eq_ignore_ascii_case("password"))
                })
            })
        {
            return Ok(None);
        }
        for key in ["children", "shadowRoots"] {
            if let Some(children) = node[key].as_array() {
                ua_pending.extend(children);
            }
        }
    }
    let mut domains = Vec::new();
    let mut pending = vec![(root, 0usize)];
    let mut visited = 0usize;
    while let Some((node, depth)) = pending.pop() {
        visited += 1;
        if visited > 100_000 || depth > 256 {
            return Err(ObservationError::ResourceLimit);
        }
        if node.get("pseudoType").is_some() || node["shadowRootType"] == "user-agent" {
            continue;
        }
        if node["nodeType"] == 9 || node["shadowRootType"] == "closed" {
            let id = node["backendNodeId"]
                .as_i64()
                .ok_or(ObservationError::BackendFailure)?;
            domains.push(
                ids.iter()
                    .position(|candidate| *candidate == id)
                    .ok_or(ObservationError::BackendFailure)?,
            );
        }
        for key in ["children", "shadowRoots"] {
            if let Some(children) = node[key].as_array() {
                pending.extend(children.iter().rev().map(|child| (child, depth + 1)));
            }
        }
        if pending.len() > 100_000 {
            return Err(ObservationError::ResourceLimit);
        }
    }
    Ok(Some((ids, author, domains)))
}

pub(super) async fn fields(
    client: &CdpClient,
    frame: &ObservationFrame,
    expression: &LocatorExpression,
    options: &QueryOptions,
    fields: &[ReadField],
    lease: &OperationLease,
) -> Result<Option<Vec<Value>>, ObservationError> {
    // Arbitrary CSS can match browser implementation nodes. Its policy keeps
    // the complete native inventory path, never this UA-eliding proof.
    if !eligible(expression, fields) || options.secure_field_selector != default_secure_selector() {
        return Ok(None);
    }
    validate_frame(client, frame, lease).await?;
    let dom = frame_dom(client, frame, lease).await?;
    let Some((ids, author, domains)) = roots(&dom["root"])? else {
        return Ok(None);
    };
    let session = &frame.binding.session;
    let group = client
        .readonly_group_instance(&format!("native-query-{}-fields", lease.sequence))
        .map_err(|_| ObservationError::ResourceLimit)?;
    let result = async {
        let world = command(client, session, "Page.createIsolatedWorld", json!({"frameId":frame.binding.frame,"worldName":"agent-browser-native-observation"}), lease).await?;
        let context = world["executionContextId"].as_i64().ok_or(ObservationError::BackendFailure)?;
        use futures_util::{stream, StreamExt};
        let handles: Vec<Result<String, ObservationError>> = stream::iter(ids.iter().copied().map(|backend| {
            let group = &group;
            async move {
                let resolved = command(client, session, "DOM.resolveNode", json!({"backendNodeId":backend,"executionContextId":context,"objectGroup":group}), lease).await?;
                resolved["object"]["objectId"].as_str().map(str::to_owned).ok_or(ObservationError::StaleReference)
            }
        })).buffered(16).collect().await;
        let handles = collect_hint_results(handles)?;
        let first = handles.first().ok_or(ObservationError::BackendFailure)?;
        let function = format!("function(expression,fields,testId,secureSelector,authorRoots,domains,...roots) {{ const read={METADATA}; const matchQuery={MATCH_QUERY}; const security={SECURITY_INVENTORY}; const sample={FRESH_FIELDS}; return sample(expression,fields,testId,secureSelector,authorRoots,domains,read,matchQuery,security,...roots); }}");
        let mut arguments = vec![json!({"value":expression}), json!({"value":fields}), json!({"value":options.test_id_attribute}), json!({"value":options.secure_field_selector}), json!({"value":author}), json!({"value":domains})];
        arguments.extend(handles.iter().map(|object| json!({"objectId":object})));
        let result = command(client, session, "Runtime.callFunctionOn", json!({"objectId":first,"functionDeclaration":function,"arguments":arguments,"returnByValue":true,"objectGroup":group}), lease).await?;
        if result.get("exceptionDetails").is_some() { return Err(ObservationError::BackendFailure); }
        let value = &result["result"]["value"];
        match value["error"].as_str() {
            Some("stale-reference") => return Err(ObservationError::StaleReference),
            Some("invalid-arguments") => return Err(ObservationError::InvalidArguments),
            Some("resource-limit") => return Err(ObservationError::ResourceLimit),
            Some(_) => return Err(ObservationError::BackendFailure),
            None => {}
        }
        if value["requiresAx"] == true { return Ok(None); }
        let rows = value["values"].as_array().ok_or(ObservationError::BackendFailure)?;
        if rows.len() > super::super::element::MAX_EXACT_REFERENCES { return Err(ObservationError::ResourceLimit); }
        let empty_ax = AXNode { node_id:String::new(), role:None, name:None, value:None, description:None, properties:None, child_ids:None, backend_d_o_m_node_id:None, ignored:None };
        let mut samples = Vec::with_capacity(rows.len());
        for row in rows {
            check(lease)?;
            // No backend/ref authority is used or published. The requested
            // projection was certified not to need AX before leaving the realm.
            let node = project_node_with_refs(frame, 0, &empty_ax, None, 0, row, false)?;
            samples.push(project_fixture_fields(node, fields)?);
        }
        Ok(Some(samples))
    }.await;
    let result = settle_object_group(client, session, &group, result, lease).await?;
    // A new/retired author root invalidates the acquired policy rather than
    // turning an unseen closed domain into an empty result. Leaf churn does not.
    validate_frame(client, frame, lease).await?;
    let current = frame_dom(client, frame, lease).await?;
    if roots(&current["root"])? != Some((ids, author, domains)) {
        return Err(ObservationError::StaleReference);
    }
    check(lease)?;
    Ok(result)
}

// The functions passed here are the exact production metadata, matcher and
// policy readers. This wrapper adds acquisition lifetime, not another accname
// implementation. Selection and sampled values share one renderer operation.
const FRESH_FIELDS: &str = r#"function(expression,fields,testId,secureSelector,authorRoots,domains,read,matchQuery,security,...roots) {
 // Bound the entire author domain before any querySelectorAll result is
 // allocated by the shared security reader. These are identity/shape reads,
 // not sampled text, labels or values.
 if(roots.length>10000)return {error:'resource-limit'};
 const connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
 const owner=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get;
 for(const root of roots)if(!connected.call(root)||(root!==document&&owner.call(root)!==document))return {error:'stale-reference'};
 const kinds=new Set();
 function collect(x){if(x.kind==='query'){kinds.add(x.query.kind);if(x.scope)collect(x.scope);}else if(x.kind==='union'){collect(x.left);collect(x.right);}else{collect(x.source);if(x.has)collect(x.has);}}
 collect(expression);
 const relevant=e=>kinds.has('text')||kinds.has('testId')&&e.hasAttribute(testId)||kinds.has('placeholder')&&e.hasAttribute('placeholder')||
   kinds.has('label')&&(e.hasAttribute('aria-label')||e.hasAttribute('aria-labelledby')||e.labels?.length>0)||
   kinds.has('displayValue')&&Element.prototype.matches.call(e,'input:not([type="checkbox" i]):not([type="radio" i]),textarea,select');
 const knownRoots=new Set(roots),shadowHosts=new Set(roots.filter(root=>root instanceof ShadowRoot).map(root=>root.host)),elements=[],seen=new Set();let visited=0,hasOwnedTree=false;
 for(const domain of domains){
   const pending=[[roots[domain],0]];
   while(pending.length){
     const [root,depth]=pending.pop();if(!root||depth>256)return {error:'resource-limit'};
     const light=[[root,depth]],open=[];
     while(light.length){
       const [node,nodeDepth]=light.pop();
       if(++visited>100000||nodeDepth>256)return {error:'resource-limit'};
       if(node.nodeType===1){
         if(node.hasAttribute('aria-owns'))hasOwnedTree=true;
         if(node.shadowRoot){if(!knownRoots.has(node.shadowRoot))return {error:'stale-reference'};open.push([node.shadowRoot,nodeDepth+1]);}
         if(!seen.has(node)){seen.add(node);if(relevant(node))elements.push(node);}
       }
       const children=node.childNodes;
       if(light.length+pending.length+open.length+children.length>100000)return {error:'resource-limit'};
       for(let i=children.length-1;i>=0;i--)light.push([children[i],nodeDepth+1]);
     }
     for(let i=open.length-1;i>=0;i--)pending.push(open[i]);
   }
 }
 const policy=security(secureSelector,authorRoots,...roots);
 if(policy.__nativeStatus)return {error:policy.__nativeStatus};
 const protectedNodes=new Set(policy),protectedIds=new Set(policy.map(node=>node.getAttribute('id')).filter(id=>id!==null));
 // The normal native projection applies normalize_public_label before the
 // matcher. Preserve all three Unicode private-use ranges and ECMAScript
 // whitespace here too, before matching in this single renderer operation.
 const publicLabel=s=>s.replace(/[\uE000-\uF8FF\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}]/gu,' ').replace(/\s+/g,' ').trim();
 const data=[],labels=[],safeNames=[],protectedAncestors=[];
 for(const e of elements){
   const protectedReceiver=protectedNodes.has(e);
   const row=read.call(e,testId,secureSelector,false,protectedReceiver,false,policy.focused===e,false);
   if(row.__nativeStatus)return {error:row.__nativeStatus};
   // Same security projection as apply_security, using current native root
   // handles inside this operation rather than a previous element inventory.
   const labelled=(row.attributes['aria-labelledby']||'').split(/\p{White_Space}+/u).filter(Boolean).some(id=>protectedIds.has(id));
   if(labelled||protectedReceiver&&!row.states.secure){row.text=null;row.value=null;row.selection=null;row.labels=[];delete row.attributes.value;}
   data.push(row);labels.push(row.labels.map(publicLabel));safeNames.push(row.safePublicName);protectedAncestors.push(protectedReceiver);
 }
 const projected=data.map(row=>({states:row.states,attributes:row.attributes,...(row.testId===null?{}:{testId:row.testId}),...(row.value===null?{}:{value:row.value})}));
 const matched=matchQuery(expression,projected,labels,safeNames,secureSelector,protectedAncestors,...elements);
 if(matched.error)return matched;
 const values=[];
 for(const i of matched.indices){
   const e=elements[i],row=data[i];
   // A raw state projection is complete for native text controls without
   // authored widget state or inherited ARIA disability. Anything else needs
   // the normal AX path; never publish a partial state bag as a complete read.
   if(fields.includes('states')){
     if(hasOwnedTree)return {requiresAx:true};
     if(!(e instanceof HTMLTextAreaElement||e instanceof HTMLInputElement&&['text','search','email','tel','url','password','hidden'].includes(e.type))||
       e.hasAttribute('role')||e.hasAttribute('list')||Array.from(e.attributes).some(a=>a.name.startsWith('aria-')&&!['aria-label','aria-labelledby','aria-description','aria-describedby','aria-hidden'].includes(a.name)))return {requiresAx:true};
     let depth=0;
     // AX can inherit disabled state through slot/owned-tree ancestry that
     // is not the light DOM chain. Decline rather than invent those states;
     // a light edge into a known shadow host also covers closed assignedSlot.
     for(let p=e;p;p=p.parentElement||p.getRootNode()?.host){
       if(++depth>256)return {error:'resource-limit'};
       if(p.hasAttribute('aria-disabled')||p.assignedSlot||p.parentElement&&shadowHosts.has(p.parentElement))return {requiresAx:true};
     }
   }
   if(matched.redacted.includes(i)){row.text=null;row.value=null;row.selection=null;row.labels=[];delete row.attributes.value;}
   values.push(row);
 }
 return {values};
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn query(kind: &str) -> LocatorExpression {
        serde_json::from_value(json!({"kind":"query","query":{"kind":kind,"value":{"kind":"string","value":"city","exact":true}}})).unwrap()
    }

    #[test]
    fn atomic_projection_declines_ax_names_roles_and_nested_role_dependencies() {
        for kind in ["label", "displayValue", "testId", "placeholder", "text"] {
            assert!(eligible(&query(kind), &[ReadField::States]));
            assert!(eligible(
                &query(kind),
                &[ReadField::Value, ReadField::Attributes]
            ));
            for field in [
                ReadField::Role,
                ReadField::Name,
                ReadField::Level,
                ReadField::Rect,
            ] {
                assert!(!eligible(&query(kind), &[field]));
            }
        }
        let role = query("role");
        assert!(!eligible(&role, &[ReadField::States]));
        let nested = LocatorExpression::Filter {
            source: Box::new(query("testId")),
            has_text: None,
            has: Some(Box::new(role)),
        };
        assert!(!eligible(&nested, &[ReadField::States]));
    }

    fn inventory(leaf: i64, ua: i64, closed: i64) -> Value {
        json!({"nodeType":9,"backendNodeId":1,"children":[
            {"nodeType":1,"nodeName":"INPUT","backendNodeId":leaf,"shadowRoots":[{"nodeType":11,"backendNodeId":ua,"shadowRootType":"user-agent","children":[{"nodeType":1,"nodeName":"DIV","backendNodeId":ua+1}]}]},
            {"nodeType":1,"backendNodeId":10,"shadowRoots":[{"nodeType":11,"backendNodeId":closed,"shadowRootType":"closed","children":[]}]}
        ]})
    }

    #[test]
    fn policy_root_lifetime_ignores_leaf_and_ua_churn_but_not_closed_root_retirement() {
        let initial = roots(&inventory(2, 3, 11)).unwrap();
        assert_eq!(initial, roots(&inventory(20, 30, 11)).unwrap());
        assert_eq!(initial, Some((vec![1, 11], vec![true, true], vec![0, 1])));
        assert_ne!(initial, roots(&inventory(20, 30, 40)).unwrap());
    }

    #[test]
    fn ua_password_policy_contribution_is_declined_not_silently_elided() {
        let mut dom = inventory(2, 3, 11);
        dom["children"][0]["shadowRoots"][0]["children"][0]["nodeName"] = json!("INPUT");
        dom["children"][0]["shadowRoots"][0]["children"][0]["attributes"] =
            json!(["type", "PaSsWoRd"]);
        assert_eq!(roots(&dom).unwrap(), None);
    }
}
