//! Test-only I/O observations around the same std::io::copy calls used by the
//! production proxy. These observations can perturb scheduling; passing this
//! fixture does not prove the browser-backed semantic fault scenario passes.
//! The independent runtime phase sink, its drop policy and caps are unchanged.
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Serialize;

const MAX_RECORDS: u64 = 128;
static ENABLED: AtomicBool = AtomicBool::new(false);
static ORDINAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Leg {
    StdinRead,
    SocketWrite,
    SocketRead,
    StdoutWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Failure {
    BrokenPipe,
    ConnectionReset,
    ConnectionAborted,
    Interrupted,
    WouldBlock,
    TimedOut,
    UnexpectedEof,
    NotConnected,
    InvalidData,
    Other,
}

impl From<io::ErrorKind> for Failure {
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            io::ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            io::ErrorKind::NotConnected => Self::NotConnected,
            io::ErrorKind::InvalidData => Self::InvalidData,
            _ => Self::Other,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    schema_version: u8,
    ordinal: u64,
    leg: Leg,
    bytes: usize,
    total_bytes: u64,
    error: Option<Failure>,
    capture_limit: bool,
}

// Called only by the explicit proxy fixture entry; normal cfg(test) imports stay disabled.
#[allow(dead_code)]
pub(crate) fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

fn record(leg: Leg, result: &io::Result<usize>, total: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let ordinal = ORDINAL.fetch_add(1, Ordering::Relaxed);
    if ordinal > MAX_RECORDS {
        return;
    }
    let record = Record {
        schema_version: 1,
        ordinal,
        leg,
        bytes: result.as_ref().copied().unwrap_or(0),
        total_bytes: total,
        error: result.as_ref().err().map(|error| error.kind().into()),
        capture_limit: ordinal == MAX_RECORDS,
    };
    // At most 129 closed-schema records. Never format the source I/O error or
    // retain bytes. An absent terminal observation is not evidence of absence.
    if let Ok(line) = serde_json::to_string(&record) {
        let _ = writeln!(io::stderr().lock(), "{line}");
    }
}

struct Observed<'a, T> {
    inner: &'a mut T,
    leg: Leg,
    total: u64,
}

impl<T: Read> Read for Observed<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(bytes);
        if let Ok(count) = result.as_ref() {
            self.total = self.total.saturating_add(*count as u64);
        }
        record(self.leg, &result, self.total);
        result
    }
}

impl<T: Write> Write for Observed<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(bytes);
        if let Ok(count) = result.as_ref() {
            self.total = self.total.saturating_add(*count as u64);
        }
        record(self.leg, &result, self.total);
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn copy<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    read_leg: Leg,
    write_leg: Leg,
) -> io::Result<u64> {
    std::io::copy(
        &mut Observed {
            inner: reader,
            leg: read_leg,
            total: 0,
        },
        &mut Observed {
            inner: writer,
            leg: write_leg,
            total: 0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_copy_keeps_exact_bytes_without_decoding_frames() {
        let bytes = b"synthetic\0bytes\nsecond\n";
        let mut output = Vec::new();
        let count = copy(
            &mut bytes.as_slice(),
            &mut output,
            Leg::StdinRead,
            Leg::SocketWrite,
        )
        .unwrap();
        assert_eq!(count, bytes.len() as u64);
        assert_eq!(output, bytes);
    }

    #[test]
    fn observed_write_keeps_error_kind_and_partial_byte_count() {
        struct ShortWriter(bool);
        impl Write for ShortWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::ErrorKind::BrokenPipe.into())
                } else {
                    self.0 = true;
                    Ok(2)
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut target = ShortWriter(false);
        let mut writer = Observed {
            inner: &mut target,
            leg: Leg::SocketWrite,
            total: 0,
        };
        let error = writer.write_all(b"synthetic").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(writer.total, 2);
        assert_eq!(Failure::from(error.kind()), Failure::BrokenPipe);
    }
}
