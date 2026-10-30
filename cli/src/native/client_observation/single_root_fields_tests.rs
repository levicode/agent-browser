//! Pure eligibility controls; no callback operation is converted into an ordinary read.
use super::*;

fn options() -> QueryOptions {
    serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"city","exact":true}}}})).unwrap()
}

#[test]
fn callback_and_unsupported_fields_decline_single_root_optimization() {
    let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let mut lease = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
        cancellation,
    };
    let options = options();
    assert_eq!(
        single_root_fields::eligible(&options, &[ReadField::Value], &lease),
        Ok(true)
    );
    assert_eq!(
        single_root_fields::eligible(&options, &[ReadField::States], &lease),
        Ok(true)
    );
    lease.is_callback = true;
    assert_eq!(
        single_root_fields::eligible(&options, &[ReadField::Value], &lease),
        Ok(false)
    );
    assert_eq!(
        single_root_fields::eligible(&options, &[ReadField::States], &lease),
        Ok(false)
    );
    lease.is_callback = false;
    assert_eq!(
        single_root_fields::eligible(&options, &[ReadField::Name], &lease),
        Ok(false)
    );
    let mut custom = options.clone();
    custom.secure_field_selector = "input.private".into();
    assert_eq!(
        single_root_fields::eligible(&custom, &[ReadField::Value], &lease),
        Ok(false)
    );
}

#[test]
fn singleton_topology_declines_children_but_rejects_malformed_evidence() {
    let tree = json!({"frameTree":{"frame":{"id":"root","loaderId":"loader","url":"about:blank"}}});
    let root = single_root_fields::root_frame(&tree, "session")
        .unwrap()
        .unwrap();
    assert_eq!(root.binding.frame, "root");
    assert_eq!(root.binding.loader, "loader");
    assert_eq!(root.binding.session, "session");
    let mut child = tree.clone();
    child["frameTree"]["childFrames"] = json!([{"frame":{"id":"child","loaderId":"child-loader","parentId":"root","url":"about:blank"}}]);
    assert!(single_root_fields::root_frame(&child, "session")
        .unwrap()
        .is_none());
    for malformed in [
        json!({"frameTree":{"frame":{"id":"root","loaderId":"","url":"about:blank"}}}),
        json!({"frameTree":{"frame":{"id":"root","loaderId":"loader","url":"about:blank"},"childFrames":{}}}),
        json!({"frameTree":{"frame":{"id":"root","loaderId":"loader","url":"about:blank","parentId":42}}}),
    ] {
        assert!(matches!(
            single_root_fields::root_frame(&malformed, "session"),
            Err(ObservationError::BackendFailure)
        ));
    }
}
