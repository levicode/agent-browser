use super::*;

#[test]
fn custody_input_opens_are_read_only_and_nonblocking() {
    assert_eq!(NONBLOCKING_READ_FLAGS & libc::O_ACCMODE, libc::O_RDONLY);
    assert_ne!(NONBLOCKING_READ_FLAGS & libc::O_NONBLOCK, 0);
}

fn fixture() -> Invocation {
    Invocation {
        schema_version: 2,
        pid: 101,
        nonce: "a".repeat(64),
        trace_directory: "/tmp/p-0123456789ab/.e2e/native-trace".into(),
        native_executable: "/verified/agent-browser".into(),
        native_sha256: "b".repeat(64),
        wrapper_sha256: "c".repeat(64),
        run: "123".into(),
        attempt: "1".into(),
        source_commit: "d".repeat(40),
        source_tree: "e".repeat(40),
    }
}

fn valid(receipt: &Invocation, proxy: u32, child: u32) -> bool {
    validate(
        receipt,
        proxy,
        child,
        Path::new("/verified/agent-browser"),
        &"b".repeat(64),
    )
    .is_some()
}

#[test]
fn current_proxy_and_exact_distinct_child_are_required() {
    assert!(valid(&fixture(), 101, 509));
    assert!(!valid(&fixture(), 102, 509));
    assert!(!valid(&fixture(), 101, 101));
    assert!(!valid(&fixture(), 101, 0));
}

#[test]
fn no_trace_derived_pid_or_receipt_executable_is_trusted() {
    let mut value = fixture();
    value.pid = 509;
    assert!(!valid(&value, 101, 509));
    value = fixture();
    value.native_executable = "/unrelated/file".into();
    assert!(!valid(&value, 101, 509));
    value = fixture();
    value.native_sha256 = "c".repeat(64);
    assert!(!valid(&value, 101, 509));
}

#[test]
fn receipt_nonce_source_identity_and_trace_shape_are_closed() {
    for field in [
        "nonce", "wrapper", "commit", "tree", "run", "attempt", "trace",
    ] {
        let mut value = fixture();
        match field {
            "nonce" => value.nonce = "arbitrary".into(),
            "wrapper" => value.wrapper_sha256 = "secret".into(),
            "commit" => value.source_commit = "x".repeat(40),
            "tree" => value.source_tree.clear(),
            "run" => value.run = "0".into(),
            "attempt" => value.attempt = "01".into(),
            "trace" => value.trace_directory = "/tmp/unowned/.e2e/native-trace".into(),
            _ => unreachable!(),
        }
        assert!(!valid(&value, 101, 509), "{field}");
    }
}

#[test]
fn mapping_retains_nonce_and_exact_receipt_digest_not_a_pid_offset() {
    let value = fixture();
    let mapping = Mapping {
        schema_version: 1,
        kind: "spawn-owned-daemon",
        proxy_pid: 101,
        daemon_pid: 509,
        nonce: &value.nonce,
        invocation_sha256: format!("{:x}", Sha256::digest(b"exact receipt\n")),
    };
    let encoded = serde_json::to_value(mapping).unwrap();
    assert_eq!(encoded["proxyPID"], 101);
    assert_eq!(encoded["daemonPID"], 509);
    assert_eq!(encoded["nonce"], value.nonce);
    assert_eq!(encoded.as_object().unwrap().len(), 6);
}
