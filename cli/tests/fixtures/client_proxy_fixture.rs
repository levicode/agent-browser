//! Harness-free test child. This deliberately bypasses daemon startup, not the
//! production byte proxy. It is not a CLI command or an existing-daemon claim.
#![allow(dead_code)]
// This harness-free crate imports production modules under cfg(test), but Rust
// removes their #[test] functions. Their test-only imports are therefore unused
// here; retain warnings everywhere else rather than editing those modules.
#![allow(unused_imports)]

#[path = "../../src/native/client_protocol.rs"]
pub mod client_protocol;
#[path = "../../src/native/client_settlement_trace.rs"]
mod client_settlement_trace;
mod native {
    pub use crate::client_protocol;
    pub(crate) use crate::client_settlement_trace;
}
#[path = "../../src/color.rs"]
mod color;
#[path = "../../src/connection.rs"]
mod connection;
#[path = "../../src/test_utils.rs"]
mod test_utils;
#[path = "../../src/validation.rs"]
mod validation;

fn main() {
    // The explicit target can be compiled without ever opening a socket. Reject
    // ordinary test-runner arguments instead of claiming any proxy test passed.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--proxy-session" {
        eprintln!("client-proxy-fixture requires explicit --proxy-session");
        std::process::exit(2);
    }
    if !cfg!(unix) || !validation::is_valid_session_name(&args[1]) {
        std::process::exit(2);
    }
    let Some(directory) = std::env::var_os("AGENT_BROWSER_SOCKET_DIR") else {
        std::process::exit(2);
    };
    if !std::path::Path::new(&directory).is_absolute() {
        std::process::exit(2);
    }
    // Match the standalone proxy's pipe policy without going through its daemon
    // ownership/startup path. Diagnostics never contain argv, paths or frames.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    connection::client_proxy_trace::enable();
    if connection::proxy_client_session(&args[1]).is_err() {
        std::process::exit(1);
    }
}
