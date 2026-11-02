//! Linux acceptance-only transport observation; never a production authority.
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

const SCRIPT_SHA256: &str = "e928c2161272a1f89f4c11ee4b0d70e3a2a0eb0b70dc1776f59894adbb31c8cd";
const PREFIX: &str = "AGENT_BROWSER_ACCEPTANCE_POPUP_RELAY_";
const FAILURE: &str = "Acceptance popup relay unavailable";

pub(super) struct RelayGuard {
    child: Child,
    input: Option<ChildStdin>,
    script: PathBuf,
}
impl Drop for RelayGuard {
    fn drop(&mut self) {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let _ = fs::remove_file(&self.script);
    }
}

fn canonical(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| FAILURE)? != path {
        return Err(FAILURE.into());
    }
    for part in path.ancestors() {
        if fs::symlink_metadata(part).map_err(|_| FAILURE)?.file_type().is_symlink() {
            return Err(FAILURE.into());
        }
    }
    Ok(())
}

fn endpoint(value: &str, readiness: bool) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|_| FAILURE)?;
    if url.scheme() != "ws" || url.host_str() != Some("127.0.0.1")
        || url.port().is_none_or(|port| port == 0) || !url.username().is_empty()
        || url.password().is_some() || url.query().is_some() || url.fragment().is_some()
        || !url.path().starts_with("/devtools/browser/")
        || (readiness && url.path() != "/devtools/browser/passive-joint")
        || value.len() > 1024
    {
        return Err(FAILURE.into());
    }
    Ok(value.to_owned())
}

fn readiness(bytes: &[u8]) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ready { endpoint: String }
    if bytes.len() > 1024 || bytes.last() != Some(&b'\n') {
        return Err(FAILURE.into());
    }
    let ready: Ready = serde_json::from_slice(bytes).map_err(|_| FAILURE)?;
    endpoint(&ready.endpoint, true)
}

fn enabled(values: &[Option<std::ffi::OsString>]) -> Result<bool, String> {
    if values.iter().all(Option::is_none) { return Ok(false); }
    if values.len() != 4 || values.iter().any(Option::is_none) { return Err(FAILURE.into()); }
    Ok(true)
}

/// Own the verified script snapshot and relay until the real Chrome owner drops.
pub(super) fn start(upstream: &str) -> Result<Option<(String, RelayGuard)>, String> {
    let values: Vec<_> = ["SCRIPT", "SCRIPT_SHA256", "PYTHON", "EVIDENCE"]
        .iter().map(|name| std::env::var_os(format!("{PREFIX}{name}"))).collect();
    if !enabled(&values)? { return Ok(None); }
    let script = PathBuf::from(values[0].as_ref().unwrap());
    let python = PathBuf::from(values[2].as_ref().unwrap());
    let evidence = PathBuf::from(values[3].as_ref().unwrap());
    if values[1].as_ref().and_then(|value| value.to_str()) != Some(SCRIPT_SHA256) { return Err(FAILURE.into()); }
    endpoint(upstream, false)?;
    canonical(&script)?;
    canonical(&python)?;
    let parent = evidence.parent().ok_or(FAILURE)?;
    canonical(parent)?;
    let directory = fs::symlink_metadata(parent).map_err(|_| FAILURE)?;
    if !directory.is_dir() || directory.uid() != unsafe { libc::geteuid() }
        || directory.mode() & 0o777 != 0o700 || evidence.file_name().is_none()
        || fs::symlink_metadata(&evidence).is_ok()
    { return Err(FAILURE.into()); }
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&script).map_err(|_| FAILURE)?;
    let before = file.metadata().map_err(|_| FAILURE)?;
    if !before.is_file() || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1 || before.mode() & 0o022 != 0 || before.len() > 64 * 1024
    { return Err(FAILURE.into()); }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(64 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| FAILURE)?;
    let after = file.metadata().map_err(|_| FAILURE)?;
    if bytes.len() as u64 != before.len() || before.len() != after.len()
        || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
        || before.dev() != after.dev() || before.ino() != after.ino()
        || before.uid() != after.uid() || before.mode() != after.mode() || before.nlink() != after.nlink()
        || hex::encode(Sha256::digest(&bytes)) != SCRIPT_SHA256
    { return Err(FAILURE.into()); }
    let interpreter = fs::metadata(&python).map_err(|_| FAILURE)?;
    if !interpreter.is_file() || interpreter.mode() & 0o022 != 0
        || (interpreter.uid() != 0 && interpreter.uid() != unsafe { libc::geteuid() })
    { return Err(FAILURE.into()); }
    let snapshot = parent.join(format!("relay-{}.py", uuid::Uuid::new_v4()));
    let mut copied = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&snapshot).map_err(|_| FAILURE)?;
    if copied.write_all(&bytes).is_err() {
        let _ = fs::remove_file(&snapshot); return Err(FAILURE.into());
    }
    drop(copied);
    let child = Command::new(&python).arg("-I").arg("-B").arg(&snapshot).arg(upstream).arg(&evidence)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(_) => { let _ = fs::remove_file(&snapshot); return Err(FAILURE.into()); }
    };
    let input = child.stdin.take();
    let mut guard = RelayGuard { child, input, script: snapshot };
    let mut output = guard.child.stdout.take().ok_or(FAILURE)?;
    let endpoint = await_readiness(&mut output, Instant::now() + Duration::from_secs(5))?;
    Ok(Some((endpoint, guard)))
}

fn await_readiness(output: &mut std::process::ChildStdout, deadline: Instant) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(FAILURE.into()); }
        let mut descriptor = libc::pollfd { fd: output.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let polled = unsafe { libc::poll(&mut descriptor, 1, left.as_millis().max(1) as i32) };
        if polled <= 0 { return Err(FAILURE.into()); }
        let mut byte = [0];
        if output.read(&mut byte).map_err(|_| FAILURE)? != 1 { return Err(FAILURE.into()); }
        line.push(byte[0]);
        if line.len() > 1024 { return Err(FAILURE.into()); }
        if byte[0] == b'\n' { return readiness(&line); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn popup_relay_readiness_accepts_only_closed_loopback_metadata() {
        assert!(readiness(b"{\"endpoint\":\"ws://127.0.0.1:1234/devtools/browser/passive-joint\"}\n").is_ok());
        for value in ["ws://example.com:1234/devtools/browser/passive-joint", "ws://u@127.0.0.1:1234/devtools/browser/passive-joint", "ws://127.0.0.1:1234/devtools/browser/passive-joint?secret=x", "ws://127.0.0.1:1234/devtools/browser/other", "wss://127.0.0.1:1234/devtools/browser/passive-joint"] {
            assert!(endpoint(value, true).is_err());
        }
        assert!(readiness(b"{\"endpoint\":\"ws://127.0.0.1:1234/devtools/browser/passive-joint\",\"raw\":\"secret\"}\n").is_err());
        assert!(readiness(&vec![b'x'; 1025]).is_err());
        assert!(readiness(b"{}\n").is_err());
    }
    #[test]
    fn popup_relay_partial_configuration_is_not_silent_disable() {
        assert!(!enabled(&[None, None, None, None]).unwrap());
        assert!(enabled(&[Some("private".into()), None, None, None]).is_err());
        assert!(enabled(&[Some("a".into()), Some("b".into()), Some("c".into()), Some("d".into())]).unwrap());
    }

    #[test]
    fn popup_relay_symlink_and_relative_paths_are_refused() {
        let root = std::env::temp_dir().join(format!("popup-relay-control-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let file = root.join("file"); fs::write(&file, b"synthetic").unwrap();
        let link = root.join("link"); std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(canonical(&file).is_ok());
        assert!(canonical(&link).is_err());
        assert!(canonical(Path::new("relative")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn popup_relay_guard_owns_stdin_eof_and_reaps_child_without_browser() {
        let script = std::env::temp_dir().join(format!("popup-relay-control-{}", uuid::Uuid::new_v4()));
        fs::write(&script, b"synthetic").unwrap();
        let mut child = Command::new("/bin/sh").args(["-c", "read value"])
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let id = child.id(); let input = child.stdin.take();
        drop(RelayGuard { child, input, script: script.clone() });
        assert!(!script.exists());
        assert_eq!(unsafe { libc::waitpid(id as i32, std::ptr::null_mut(), libc::WNOHANG) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn popup_relay_guard_forces_hung_child_stop_without_browser() {
        let script = std::env::temp_dir().join(format!("popup-relay-control-{}", uuid::Uuid::new_v4()));
        fs::write(&script, b"synthetic").unwrap();
        let mut child = Command::new("/bin/sleep").arg("30")
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let id = child.id(); let input = child.stdin.take(); let start = Instant::now();
        drop(RelayGuard { child, input, script: script.clone() });
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(!script.exists());
        assert_eq!(unsafe { libc::waitpid(id as i32, std::ptr::null_mut(), libc::WNOHANG) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn popup_relay_readiness_pipe_failure_and_timeout_remain_bounded() {
        for command in ["printf '{}\\n'", "exit 0", "exec sleep 30"] {
            let script = std::env::temp_dir().join(format!("popup-relay-control-{}", uuid::Uuid::new_v4()));
            fs::write(&script, b"synthetic").unwrap();
            let mut child = Command::new("/bin/sh").args(["-c", command])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
            let input = child.stdin.take(); let mut output = child.stdout.take().unwrap();
            let guard = RelayGuard { child, input, script };
            assert!(await_readiness(&mut output, Instant::now() + Duration::from_millis(20)).is_err());
            drop(guard);
        }
    }

}
