//! Sparse fixture fields for a plain CSS selector. Every native author receiver
//! is still bound in the isolated realm. Only the matched elements need the
//! full metadata reader, including when a field needs its native AX role.
use super::*;

pub(super) fn eligible(
    expression: &LocatorExpression,
    security: &SecurityInventory,
    count: usize,
) -> bool {
    count > 64
        && security.simple_name_inventory
        && security.ancestors.is_empty()
        && single_css(expression)
}

/// The shared renderer parser decides whether the CSS uses a metadata-dependent extension.
pub(super) fn single_css(expression: &LocatorExpression) -> bool {
    let LocatorExpression::Selector { selector } = expression else {
        return false;
    };
    selector::parse_with_capture(selector).is_ok_and(|parsed| {
        parsed.capture.is_none() && parsed.parts.len() == 1 && parsed.parts[0].engine == "css"
    })
}

/// Matching and sampling share one synchronous isolated-world call. The
/// selected index only addresses the native receiver / AX pair already in
/// custody. No input becomes a selector string or a published reference.
#[allow(clippy::too_many_arguments)]
pub(super) async fn read(
    client: &CdpClient,
    frame: &ObservationFrame,
    candidates: &[AXNode],
    handles: &[String],
    expression: &LocatorExpression,
    options: &ObservationOptions,
    security: &SecurityInventory,
    group: &str,
    lease: &OperationLease,
) -> Result<Option<QueryEvaluation>, ObservationError> {
    static SAMPLER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let function = SAMPLER.get_or_init(|| [
        "function(expression,testId,secureSelector,focused,localNames,...nodes) { const match=",
        MATCH_QUERY,"; const read=", METADATA, r#";
        if(nodes.some(node=>node.shadowRoot)||document.querySelector('input[type="password" i],'+secureSelector))return {ordinary:true};
        const result=match(expression, null, [], [], secureSelector, [], ...nodes);
        if(result.error)return result;
        if(result.requiresMetadata||result.indices.length>64||result.redacted.length)return {ordinary:true};
        const rows=[];
        for(const index of result.indices) {
            const row=read.call(nodes[index],testId,secureSelector,false,false,true,
                index===focused,localNames[index]);
            if(row.__nativeStatus)return {error:row.__nativeStatus};
            if(row.states.secure||row.secureDescendants||row.redactName)
                return {ordinary:true};
            rows.push(row);
        }
        return {indices:result.indices,rows};
    }"#].concat());
    let first = handles.first().ok_or(ObservationError::BackendFailure)?;
    let focused = candidates.iter().position(|ax| {
        ax.backend_d_o_m_node_id.is_some() && ax.backend_d_o_m_node_id == security.focused_backend
    });
    let local_names: Vec<_> = candidates
        .iter()
        .map(|ax| {
            ax.backend_d_o_m_node_id
                .is_some_and(|id| security.local_name_inventory.contains(&id))
        })
        .collect();
    let mut arguments = vec![
        json!({"value":compile_selector_expression(expression)?}),
        json!({"value":options.test_id_attribute}),
        json!({"value":options.secure_field_selector}),
        json!({"value":focused}),
        json!({"value":local_names}),
    ];
    arguments.extend(handles.iter().map(|handle| json!({"objectId":handle})));
    let reply = command(
        client,
        &frame.binding.session,
        "Runtime.callFunctionOn",
        json!({"objectId":first,"objectGroup":group,"functionDeclaration":function,
            "arguments":arguments,"returnByValue":true}),
        lease,
    )
    .await?;
    if reply.get("exceptionDetails").is_some() {
        return Err(ObservationError::BackendFailure);
    }
    let value = &reply["result"]["value"];
    check_query_match_reply(value)?;
    if value["ordinary"] == true {
        return Ok(None);
    }
    let indices = value["indices"]
        .as_array()
        .ok_or(ObservationError::BackendFailure)?;
    let rows = value["rows"]
        .as_array()
        .ok_or(ObservationError::BackendFailure)?;
    if indices.len() != rows.len() || indices.len() > 64 {
        return Err(ObservationError::BackendFailure);
    }
    let mut seen = std::collections::HashSet::new();
    let mut matches = Vec::with_capacity(rows.len());
    for (index, row) in indices.iter().zip(rows) {
        let index = index
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(ObservationError::BackendFailure)?;
        let ax = candidates
            .get(index)
            .ok_or(ObservationError::BackendFailure)?;
        let backend = ax
            .backend_d_o_m_node_id
            .ok_or(ObservationError::BackendFailure)?;
        if !seen.insert(backend) {
            return Err(ObservationError::BackendFailure);
        }
        let mut node = project_node_with_refs(frame, backend, ax, None, 0, row, false)?;
        apply_security(&mut node, backend, security);
        matches.push(QueryMatch {
            backend_node_id: backend,
            node,
            projection_index: matches.len(),
        });
    }
    Ok(Some(QueryEvaluation {
        projection_count: matches.len(),
        matches,
    }))
}
