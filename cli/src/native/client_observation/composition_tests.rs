//! Native composition admission, frame ownership, and retained-source contracts.
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
        for unsupported in [
            scope(source.clone()),
            has(source.clone()),
            union(source.clone(), ordinary()),
            union(ordinary(), source),
        ] {
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

fn union(left: Value, right: Value) -> Value {
    json!({"kind":"union","left":left,"right":right})
}
fn framed(source: Value, selectors: &[&str]) -> Value {
    selectors.iter().rev().fold(
        source,
        |source, selector| json!({"kind":"frame","selector":selector,"source":source}),
    )
}

#[test]
fn union_is_plain_and_composable_even_with_exact_label_visible_branches() {
    let mut label = query_kind("label");
    label["query"]["visible"] = json!(true);
    for source in [ordinary(), query_kind("role"), label] {
        for expression in refinements(&union(source, ordinary())) {
            let expression: LocatorExpression = serde_json::from_value(expression).unwrap();
            assert_eq!(validate_expression(&expression, 0), Ok(false));
            assert!(!query_uses_pinned_handles(&expression));
            assert!(!projection_holds_visible(&expression));
            let roundtrip = serde_json::to_value(&expression).unwrap();
            assert_eq!(
                serde_json::to_value(
                    serde_json::from_value::<LocatorExpression>(roundtrip.clone()).unwrap()
                )
                .unwrap(),
                roundtrip
            );
        }
    }
    for expression in [
        scope(union(ordinary(), query_kind("label"))),
        has(union(ordinary(), ordinary())),
        union(union(ordinary(), ordinary()), ordinary()),
    ] {
        assert_eq!(
            validate_expression(&serde_json::from_value(expression).unwrap(), 0),
            Ok(false)
        );
    }
    // A strict live-query origin retains the union AST rather than branch handles.
    assert_eq!(retained_query_selection(1, 0), LiveQuerySelection::Strict);
    assert_eq!(retained_query_selection(2, 1), LiveQuerySelection::Nth(1));
}

#[test]
fn union_frame_paths_are_exact_and_stripped_before_matching() {
    let chain = ["#outer", "#inner"];
    let expression = union(
        framed(ordinary(), &chain),
        framed(query_kind("label"), &chain),
    );
    let expression: LocatorExpression = serde_json::from_value(expression).unwrap();
    let (path, stripped) = split_frame_expression(&expression).unwrap();
    assert_eq!(path, chain);
    // Compare canonical ASTs, including the semantic query's default states.
    let expected: LocatorExpression =
        serde_json::from_value(union(ordinary(), query_kind("label"))).unwrap();
    assert_eq!(
        serde_json::to_value(stripped).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    for other in [
        vec![],
        vec!["#outer"],
        vec!["#inner", "#outer"],
        vec!["css=#outer", "#inner"],
    ] {
        let expression: LocatorExpression = serde_json::from_value(union(
            framed(ordinary(), &chain),
            framed(ordinary(), &other),
        ))
        .unwrap();
        assert!(matches!(
            split_frame_expression(&expression),
            Err(ObservationError::UnsupportedCapability)
        ));
    }
    let expression: LocatorExpression = serde_json::from_value(has(union(
        framed(ordinary(), &chain),
        framed(ordinary(), &chain),
    )))
    .unwrap();
    assert!(matches!(
        split_frame_expression(&expression),
        Err(ObservationError::InvalidArguments)
    ));
}

#[test]
fn union_validates_both_branches_without_weakening_syntax_or_depth_limits() {
    for expression in [
        union(
            query_kind("displayValue"),
            json!({"kind":"selector","selector":""}),
        ),
        union(json!({"kind":"selector","selector":""}), ordinary()),
    ] {
        assert_eq!(
            validate_expression(&serde_json::from_value(expression).unwrap(), 0),
            Err(ObservationError::InvalidArguments)
        );
    }
    for expression in [
        json!({"kind":"union","left":ordinary()}),
        json!({"kind":"union","left":ordinary(),"right":ordinary(),"source":ordinary()}),
        json!({"kind":"union","left":null,"right":ordinary()}),
    ] {
        assert!(serde_json::from_value::<LocatorExpression>(expression).is_err());
    }
    let mut expression = ordinary();
    for _ in 0..65 {
        expression = union(ordinary(), expression);
    }
    assert_eq!(
        validate_expression(&serde_json::from_value(expression).unwrap(), 0),
        Err(ObservationError::InvalidArguments)
    );
}

pub(crate) fn oversized_expression() -> LocatorExpression {
    fn balanced(depth: usize) -> LocatorExpression {
        if depth == 0 {
            return LocatorExpression::Selector {
                selector: "button".into(),
            };
        }
        let branch = balanced(depth - 1);
        LocatorExpression::Union {
            left: Box::new(branch.clone()),
            right: Box::new(branch),
        }
    }
    // A balanced depth-11 union contains 4095 occurrences; wrappers count too.
    LocatorExpression::Index {
        source: Box::new(LocatorExpression::Index {
            source: Box::new(balanced(11)),
            index: QueryIndex::Number(0),
        }),
        index: QueryIndex::Number(0),
    }
}

#[test]
fn union_admission_counts_all_occurrences_at_the_shared_node_budget() {
    let over = oversized_expression();
    let LocatorExpression::Index { source, .. } = &over else {
        unreachable!()
    };
    assert_eq!(validate_expression(source, 0), Ok(false)); // Exactly 4096.
    assert_eq!(
        validate_expression(&over, 0),
        Err(ObservationError::ResourceLimit)
    );
}
