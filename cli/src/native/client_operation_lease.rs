//! Browser-independent operation lease and cancellation signal.
//! Shared with diagnostics without importing the session broker runtime.
use std::time::Instant;

use tokio::sync::watch;

use crate::native::client_protocol::ProtocolError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelSignal {
    None,
    Requested,
    DeadlineExceeded,
    SessionClosed,
    /// Private enrollment producer stop; no public/wire representation.
    OwnerRetirement,
}

impl CancelSignal {
    pub(crate) fn error(self) -> Option<ProtocolError> {
        match self {
            Self::None => None,
            Self::Requested | Self::SessionClosed | Self::OwnerRetirement => {
                Some(ProtocolError::Cancelled)
            }
            Self::DeadlineExceeded => Some(ProtocolError::DeadlineExceeded),
        }
    }
}

pub struct OperationLease {
    pub is_callback: bool,
    pub generation: u64,
    pub sequence: u64,
    pub deadline: Instant,
    pub cancellation: watch::Receiver<CancelSignal>,
}
