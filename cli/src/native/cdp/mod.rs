pub mod chrome;
pub mod client;
pub mod discovery;
pub(crate) mod dom_epoch;
pub(crate) mod observation_ax;
pub mod lightpanda;
pub mod obscura;
pub mod types;
#[cfg(windows)]
mod windows_process;

#[cfg(all(feature = "acceptance-faults", target_os = "linux"))]
mod popup_relay;
