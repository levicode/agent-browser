//! Default-off CI custody only. Missing evidence must never change browser behavior.
//!
//! The wrapper is the foreground proxy, not its freshly spawned native daemon.
//! Bind the actual Child::id() to the pre-exec wrapper receipt without deriving
//! identity from trace contents, PID proximity, or a reusable daemon sidecar.

#[cfg(target_os = "linux")]
mod linux {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    // Reject non-regular inputs below without first blocking on a FIFO open.
    const NONBLOCKING_READ_FLAGS: i32 = libc::O_RDONLY | libc::O_NONBLOCK;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Invocation {
        schema_version: u8,
        pid: u32,
        nonce: String,
        trace_directory: String,
        native_executable: String,
        #[serde(rename = "nativeSHA256")]
        native_sha256: String,
        #[serde(rename = "wrapperSHA256")]
        wrapper_sha256: String,
        run: String,
        attempt: String,
        source_commit: String,
        source_tree: String,
    }

    #[derive(Serialize, Debug, PartialEq)]
    #[serde(rename_all = "camelCase")]
    struct Mapping<'a> {
        schema_version: u8,
        kind: &'static str,
        #[serde(rename = "proxyPID")]
        proxy_pid: u32,
        #[serde(rename = "daemonPID")]
        daemon_pid: u32,
        nonce: &'a str,
        #[serde(rename = "invocationSHA256")]
        invocation_sha256: String,
    }

    fn hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn positive_decimal(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 20
            && !value.starts_with('0')
            && value.bytes().all(|b| b.is_ascii_digit())
    }

    fn validate(
        receipt: &Invocation,
        proxy_pid: u32,
        daemon_pid: u32,
        executable: &Path,
        executable_sha256: &str,
    ) -> Option<()> {
        let trace = Path::new(&receipt.trace_directory);
        let project = trace.parent()?.parent()?;
        let project_name = project.file_name()?.to_str()?;
        (receipt.schema_version == 2
            && receipt.pid == proxy_pid
            && daemon_pid != 0
            && daemon_pid != proxy_pid
            && hex(&receipt.nonce, 64)
            && hex(&receipt.native_sha256, 64)
            && hex(&receipt.wrapper_sha256, 64)
            && hex(&receipt.source_commit, 40)
            && hex(&receipt.source_tree, 40)
            && positive_decimal(&receipt.run)
            && positive_decimal(&receipt.attempt)
            && Path::new(&receipt.native_executable) == executable
            && receipt.native_sha256 == executable_sha256
            && trace.is_absolute()
            && trace.file_name()?.to_str()? == "native-trace"
            && trace.parent()?.file_name()?.to_str()? == ".e2e"
            && project_name.starts_with("p-")
            && hex(project_name.strip_prefix("p-")?, 12))
        .then_some(())
    }

    fn directory_without_symlinks(path: &Path) -> Option<File> {
        if !path.is_absolute() {
            return None;
        }
        let mut directory = File::open("/").ok()?;
        for component in path.components() {
            let Component::Normal(name) = component else {
                if component == Component::RootDir {
                    continue;
                }
                return None;
            };
            let name = std::ffi::CString::new(name.as_bytes()).ok()?;
            // Walk each directory relative to its already-open parent. Unlike
            // lstat-then-open, ancestor symlink swaps cannot redirect this walk.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return None;
            }
            directory = unsafe { File::from_raw_fd(fd) };
        }
        Some(directory)
    }

    fn opened_at(directory: &File, name: &str, flags: i32) -> Option<File> {
        let name = std::ffi::CString::new(name).ok()?;
        // Both names are generated from the current PID, never receipt input.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        (fd >= 0).then(|| unsafe { File::from_raw_fd(fd) })
    }

    fn record(daemon_pid: u32) -> Option<()> {
        let workspace = std::env::var_os("GITHUB_WORKSPACE")?;
        let root = Path::new(&workspace).join("evidence/fixture-invocations");
        let directory = directory_without_symlinks(&root)?;
        let metadata = directory.metadata().ok()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
            return None;
        }
        let proxy_pid = std::process::id();
        let mut input = opened_at(
            &directory,
            &format!("invocation-{proxy_pid}.json"),
            NONBLOCKING_READ_FLAGS,
        )?;
        let metadata = input.metadata().ok()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > 4096
        {
            return None;
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut input)
            .take(4097)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
            return None;
        }
        let receipt: Invocation = serde_json::from_slice(&bytes).ok()?;
        // Hash only this executable, never a pathname supplied in the receipt.
        let executable = std::env::current_exe().ok()?;
        let executable_parent = directory_without_symlinks(executable.parent()?)?;
        let executable_name = executable.file_name()?.to_str()?;
        let mut executable_file =
            opened_at(&executable_parent, executable_name, NONBLOCKING_READ_FLAGS)?;
        let file_metadata = executable_file.metadata().ok()?;
        let running_metadata = fs::metadata("/proc/self/exe").ok()?;
        if !file_metadata.is_file()
            || file_metadata.dev() != running_metadata.dev()
            || file_metadata.ino() != running_metadata.ino()
        {
            return None;
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = executable_file.read(&mut buffer).ok()?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let executable_sha256 = format!("{:x}", hasher.finalize());
        validate(
            &receipt,
            proxy_pid,
            daemon_pid,
            &executable,
            &executable_sha256,
        )?;
        let mapping = Mapping {
            schema_version: 1,
            kind: "spawn-owned-daemon",
            proxy_pid,
            daemon_pid,
            nonce: &receipt.nonce,
            invocation_sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        let mut output = opened_at(
            &directory,
            &format!("daemon-{proxy_pid}.json"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let mut encoded = serde_json::to_vec(&mapping).ok()?;
        encoded.push(b'\n');
        output.write_all(&encoded).ok()?;
        Some(())
    }

    pub(super) fn record_spawned(daemon_pid: u32) {
        if std::env::var_os("AGENT_BROWSER_INVOCATION_CUSTODY").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            // Missing/invalid custody remains a diagnostic failure, never an
            // altered browser result or a replacement of its original error.
            let _ = record(daemon_pid);
        }
    }

    #[cfg(test)]
    mod tests {
        include!("diagnostic_invocation_tests.rs");
    }
}

pub(super) fn record_spawned(daemon_pid: u32) {
    #[cfg(target_os = "linux")]
    linux::record_spawned(daemon_pid);
    #[cfg(not(target_os = "linux"))]
    let _ = daemon_pid; // Unsupported capture is missing evidence, not success.
}
