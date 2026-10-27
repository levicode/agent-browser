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

#[test]
fn attribute_engines_compile_inside_the_existing_chain() {
    let source = r#"main >> data-testid=row >> nth=-1 >> *data-test-id:light=cell"#;
    let expression = LocatorExpression::Selector {
        selector: source.into(),
    };
    assert_eq!(validate_expression(&expression, 0), Ok(false));
    let compiled = compile_selector_expression(&expression).unwrap();
    assert_eq!(compiled["selector"], source);
    assert_eq!(
        compiled["nativeParts"],
        json!([
            {"engine":"css","body":"main"},
            {"engine":"data-testid","body":"row"},
            {"engine":"nth","body":"-1"},
            {"engine":"data-test-id:light","body":"cell"},
        ])
    );
    for selector in [
        "id=row",
        "id:light=row",
        "data-testid=",
        r#"data-testid="a\"b""#,
        r#"data-test="a >> b""#,
        "data-test-id=日本",
    ] {
        let expression = LocatorExpression::Selector {
            selector: selector.into(),
        };
        assert_eq!(validate_expression(&expression, 0), Ok(false), "{selector}");
        assert!(
            compile_selector_expression(&expression).is_ok(),
            "{selector}"
        );
    }
    for selector in [
        "role=button",
        "data-k=row",
        "div >>",
        "*data-testid=row >> css=div >> nth=0",
    ] {
        let expression = LocatorExpression::Selector {
            selector: selector.into(),
        };
        assert!(validate_expression(&expression, 0).is_err(), "{selector}");
    }
}

#[test]
fn visible_engine_compiles_inside_the_existing_chain() {
    let source = r#"main >> visible=true >> visible=false >> nth=0"#;
    let expression = LocatorExpression::Selector {
        selector: source.into(),
    };
    assert_eq!(validate_expression(&expression, 0), Ok(false));
    let compiled = compile_selector_expression(&expression).unwrap();
    assert_eq!(compiled["selector"], source);
    assert_eq!(
        compiled["nativeParts"],
        json!([
            {"engine": "css", "body": "main"},
            {"engine": "visible", "body": "true"},
            {"engine": "visible", "body": "false"},
            {"engine": "nth", "body": "0"},
        ])
    );
    // An empty body is a real Playwright visible body ("not visible"), so it
    // stays legal and reaches the renderer unchanged.
    for selector in [
        "visible=true",
        "visible=false",
        "visible=",
        "visible=TRUE",
        "*visible=true",
        "div >> visible=false >> span",
    ] {
        let expression = LocatorExpression::Selector {
            selector: selector.into(),
        };
        assert_eq!(validate_expression(&expression, 0), Ok(false), "{selector}");
        let compiled = compile_selector_expression(&expression).unwrap();
        assert!(compiled["nativeParts"].is_array(), "{selector}");
    }
    // Capture placement and final-only rules are unchanged.
    for selector in ["*visible=true >> css=div", "div >> *visible=true >> nth=0"] {
        let expression = LocatorExpression::Selector {
            selector: selector.into(),
        };
        assert_eq!(
            validate_expression(&expression, 0),
            Err(ObservationError::InvalidLocator),
            "{selector}"
        );
    }
}
