//! Admission matrix only: no matching, candidate ordering, or identity changes.
use super::*;

fn query_kind(kind: &str) -> Value {
    json!({"kind":"query","query":{"kind":kind,"value":{"kind":"string","value":"sample","exact":true}}})
}
fn ordinary() -> Value {
    json!({"kind":"selector","selector":"section"})
}
fn refinements(source: &Value) -> Vec<Value> {
    vec![
        source.clone(),
        json!({"kind":"index","source":source,"index":"first"}),
        json!({"kind":"index","source":source,"index":"last"}),
        json!({"kind":"index","source":source,"index":2}),
        json!({"kind":"filter","source":source,"hasText":{"kind":"string","value":"sample","exact":false}}),
        json!({"kind":"filter","source":source,"has":ordinary()}),
        json!({"kind":"frame","source":source,"selector":"iframe"}),
        json!({"kind":"filter","source":{"kind":"index","source":source,"index":0},"has":ordinary()}),
    ]
}
fn scope(source: Value) -> Value {
    let mut expression = query_kind("role");
    expression["scope"] = source;
    expression
}
fn has(source: Value) -> Value {
    json!({"kind":"filter","source":ordinary(),"has":source})
}
pub(crate) fn unsupported_expressions() -> Vec<LocatorExpression> {
    let mut expressions = Vec::new();
    for source in refinements(&query_kind("displayValue")) {
        for unsupported in [scope(source.clone()), has(source)] {
            // A refusal cannot be hidden beneath any otherwise ordinary wrapper.
            expressions.extend(refinements(&unsupported));
        }
    }
    expressions
        .into_iter()
        .map(|expression| serde_json::from_value(expression).unwrap())
        .collect()
}

#[test]
fn display_value_scope_and_has_refuse_through_every_refinement() {
    for expression in unsupported_expressions() {
        assert_eq!(
            validate_expression(&expression, 0),
            Err(ObservationError::UnsupportedCapability),
            "{expression:?}"
        );
    }
}

#[test]
fn display_value_query_resets_provenance_and_preserves_allowed_refinements() {
    let display = query_kind("displayValue");
    for expression in refinements(&display) {
        let expression = serde_json::from_value(expression).unwrap();
        assert_eq!(validate_expression(&expression, 0), Ok(true));
    }
    for root in [ordinary(), query_kind("role"), query_kind("label")] {
        for source in refinements(&root) {
            for expression in [source.clone(), scope(source.clone()), has(source.clone())] {
                let expression = serde_json::from_value(expression).unwrap();
                assert_eq!(validate_expression(&expression, 0), Ok(false));
            }
            let mut scoped_display = display.clone();
            scoped_display["scope"] = source;
            let expression = serde_json::from_value(scoped_display).unwrap();
            assert_eq!(validate_expression(&expression, 0), Ok(true));
        }
    }
}

#[test]
fn existing_syntax_and_depth_refusals_keep_their_category() {
    let bad_role = json!({"kind":"query","query":{"kind":"role","value":{"kind":"regexp","source":".*","flags":""}}});
    for bad in [json!({"kind":"selector","selector":""}), bad_role] {
        let expression = serde_json::from_value(bad.clone()).unwrap();
        assert_eq!(
            validate_expression(&expression, 0),
            Err(ObservationError::InvalidArguments)
        );
        let mut display = query_kind("displayValue");
        display["scope"] = bad;
        let expression = serde_json::from_value(display).unwrap();
        assert_eq!(
            validate_expression(&expression, 0),
            Err(ObservationError::InvalidArguments)
        );
    }
    let mut expression: LocatorExpression = serde_json::from_value(ordinary()).unwrap();
    for _ in 0..65 {
        expression = LocatorExpression::Index {
            source: Box::new(expression),
            index: QueryIndex::Number(0),
        };
    }
    assert_eq!(
        validate_expression(&expression, 0),
        Err(ObservationError::InvalidArguments)
    );
}
