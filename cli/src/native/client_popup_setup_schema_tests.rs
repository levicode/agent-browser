// Included only in eval_admission_schema_tests. Real serde, not a length model.
#[test]
fn popup_setup_refusal_codes_are_closed_and_fit_existing_record_budget() {
    let cases = [
        (
            PopupSetupCheckpoint::ConfigurationEntered,
            PopupReceiptStage::Unissued,
            "p-c1s0",
        ),
        (
            PopupSetupCheckpoint::ConfigurationEntered,
            PopupReceiptStage::Issued,
            "p-c1s1",
        ),
        (
            PopupSetupCheckpoint::ConfigurationEntered,
            PopupReceiptStage::Completed,
            "p-c1s2",
        ),
        (
            PopupSetupCheckpoint::ConfigurationEntered,
            PopupReceiptStage::Released,
            "p-c1s3",
        ),
        (
            PopupSetupCheckpoint::ConfigurationEntered,
            PopupReceiptStage::Unknown,
            "p-c1sx",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableEntered,
            PopupReceiptStage::Unissued,
            "p-c2s0",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableEntered,
            PopupReceiptStage::Issued,
            "p-c2s1",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableEntered,
            PopupReceiptStage::Completed,
            "p-c2s2",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableEntered,
            PopupReceiptStage::Released,
            "p-c2s3",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableEntered,
            PopupReceiptStage::Unknown,
            "p-c2sx",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableAcknowledged,
            PopupReceiptStage::Unissued,
            "p-c3s0",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableAcknowledged,
            PopupReceiptStage::Issued,
            "p-c3s1",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableAcknowledged,
            PopupReceiptStage::Completed,
            "p-c3s2",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableAcknowledged,
            PopupReceiptStage::Released,
            "p-c3s3",
        ),
        (
            PopupSetupCheckpoint::RuntimeEnableAcknowledged,
            PopupReceiptStage::Unknown,
            "p-c3sx",
        ),
        (
            PopupSetupCheckpoint::ScriptsAcknowledged,
            PopupReceiptStage::Unissued,
            "p-c4s0",
        ),
        (
            PopupSetupCheckpoint::ScriptsAcknowledged,
            PopupReceiptStage::Issued,
            "p-c4s1",
        ),
        (
            PopupSetupCheckpoint::ScriptsAcknowledged,
            PopupReceiptStage::Completed,
            "p-c4s2",
        ),
        (
            PopupSetupCheckpoint::ScriptsAcknowledged,
            PopupReceiptStage::Released,
            "p-c4s3",
        ),
        (
            PopupSetupCheckpoint::ScriptsAcknowledged,
            PopupReceiptStage::Unknown,
            "p-c4sx",
        ),
        (
            PopupSetupCheckpoint::RecursiveAttachAcknowledged,
            PopupReceiptStage::Unissued,
            "p-c5s0",
        ),
        (
            PopupSetupCheckpoint::RecursiveAttachAcknowledged,
            PopupReceiptStage::Issued,
            "p-c5s1",
        ),
        (
            PopupSetupCheckpoint::RecursiveAttachAcknowledged,
            PopupReceiptStage::Completed,
            "p-c5s2",
        ),
        (
            PopupSetupCheckpoint::RecursiveAttachAcknowledged,
            PopupReceiptStage::Released,
            "p-c5s3",
        ),
        (
            PopupSetupCheckpoint::RecursiveAttachAcknowledged,
            PopupReceiptStage::Unknown,
            "p-c5sx",
        ),
        (
            PopupSetupCheckpoint::ConfiguredCommitObserved,
            PopupReceiptStage::Unissued,
            "p-c6s0",
        ),
        (
            PopupSetupCheckpoint::ConfiguredCommitObserved,
            PopupReceiptStage::Issued,
            "p-c6s1",
        ),
        (
            PopupSetupCheckpoint::ConfiguredCommitObserved,
            PopupReceiptStage::Completed,
            "p-c6s2",
        ),
        (
            PopupSetupCheckpoint::ConfiguredCommitObserved,
            PopupReceiptStage::Released,
            "p-c6s3",
        ),
        (
            PopupSetupCheckpoint::ConfiguredCommitObserved,
            PopupReceiptStage::Unknown,
            "p-c6sx",
        ),
    ];
    let mut codes = std::collections::BTreeSet::new();
    for (checkpoint, stage, code) in cases {
        assert!(codes.insert(code));
        let reason =
            EvalAdmissionReason::from(EvalPreparationRefusal::UnconfiguredAt(checkpoint, stage));
        assert_eq!(serde_json::to_value(reason).unwrap(), code);
        let record = Record {
            schema_version: 2,
            source: Source::Native,
            pid: u32::MAX,
            record: SAFE_INTEGER,
            operation_seq: SAFE_INTEGER,
            phase: Phase::EvalAdmission,
            dropped_before: SAFE_INTEGER,
            emitted_before: SAFE_INTEGER,
            suppressed_before: SAFE_INTEGER,
            overflow: false,
            facts: Facts {
                generation: Some(SAFE_INTEGER),
                eval: Some(EvalAdmissionFacts {
                    reason,
                    ..maximum()
                }),
                ..Facts::default()
            },
        };
        let mut bytes = serde_json::to_vec(&record).unwrap();
        bytes.push(b'\n');
        assert!(
            bytes.len() <= MAX_RECORD_BYTES,
            "{code}: {} bytes including LF",
            bytes.len()
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["eval"]["c"], code);
        assert_eq!(value["pid"], u32::MAX);
        for field in [
            "record",
            "operationSeq",
            "generation",
            "droppedBefore",
            "emittedBefore",
            "suppressedBefore",
        ] {
            assert_eq!(value[field], SAFE_INTEGER);
        }
        let mut keys = value["eval"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, vec!["c", "e", "h", "p", "r", "s", "t", "v", "w"]);
    }
    assert_eq!(codes.len(), 30);
    for unknown in ["p-c0s0", "p-c7s0", "p-c1s4", "p-c1sy", "p-c1s00", "PRIVATE"] {
        assert!(!codes.contains(unknown));
    }
}
