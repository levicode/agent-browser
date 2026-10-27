use super::*;

#[test]
fn selector_compilation_preserves_the_wire_and_retained_source() {
    let source = r#"[data-testid="row"] >> nth=2 >> *css=div"#;
    let expression = LocatorExpression::Selector {
        selector: source.into(),
    };
    assert_eq!(validate_expression(&expression, 0), Ok(false));
    let compiled = compile_selector_expression(&expression).unwrap();
    assert_eq!(compiled["selector"], source);
    assert_eq!(
        compiled["nativeParts"],
        json!([
            {"engine":"css","body":"[data-testid=\"row\"]"},
            {"engine":"nth","body":"2"},
            {"engine":"css","body":"div"},
        ])
    );
    assert_eq!(
        serde_json::to_value(expression).unwrap(),
        json!({"kind":"selector","selector":source})
    );
}

#[test]
fn capture_refusal_survives_nested_scopes_filters_unions_and_frames() {
    let invalid = json!({"kind":"selector","selector":"*css=article >> text=Hello"});
    let valid = json!({"kind":"selector","selector":"section"});
    for value in [
        invalid.clone(),
        json!({"kind":"index","index":0,"source":invalid}),
        json!({"kind":"filter","source":valid,"has":invalid}),
        json!({"kind":"union","left":valid,"right":invalid}),
        json!({"kind":"frame","selector":"iframe","source":invalid}),
        json!({"kind":"frame","selector":"*css=div >> iframe","source":valid}),
        json!({"kind":"query","query":{"kind":"text","value":{"kind":"string","value":"Hello","exact":true}},"scope":invalid}),
    ] {
        let expression = serde_json::from_value(value).unwrap();
        assert_eq!(
            validate_expression(&expression, 0),
            Err(ObservationError::InvalidLocator)
        );
    }
}

#[test]
fn malformed_protocol_arguments_are_not_relabelled_as_user_selectors() {
    let expression = LocatorExpression::Selector {
        selector: String::new(),
    };
    assert_eq!(
        validate_expression(&expression, 0),
        Err(ObservationError::InvalidArguments)
    );
    assert!(serde_json::from_value::<LocatorExpression>(
        json!({"kind":"selector","selector":"div","nativeParts":[]})
    )
    .is_err());
    let expression = LocatorExpression::Selector {
        selector: "role=button".into(),
    };
    assert_eq!(
        validate_expression(&expression, 0),
        Err(ObservationError::UnsupportedCapability)
    );
}

#[test]
fn nested_selector_leaves_compile_without_changing_semantic_queries() {
    let original = json!({"kind":"filter","source":{"kind":"selector","selector":"section >> nth=-1"},"has":{"kind":"selector","selector":"ul >> li"}});
    let expression = serde_json::from_value(original.clone()).unwrap();
    let compiled = compile_selector_expression(&expression).unwrap();
    assert_eq!(
        compiled["source"]["nativeParts"][1],
        json!({"engine":"nth","body":"-1"})
    );
    assert_eq!(
        compiled["has"]["nativeParts"][1],
        json!({"engine":"css","body":"li"})
    );
    assert_eq!(serde_json::to_value(expression).unwrap(), original);
}
