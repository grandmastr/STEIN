//! Narrow Windows transport broker for STEIN private client sessions.
//!
//! The broker authenticates both native pipe peers and forwards complete,
//! bounded protocol frames without decoding, retaining, or logging them. It
//! owns no domain state, grants, workflow lifecycle, or delivery behavior.

use std::{io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

#[cfg(windows)]
mod windows;

/// Fixed session-local endpoint exposed by the AppContainer broker.
pub const BROKER_RELAY_PIPE: &str = stein_broker_windows::BROKER_RELAY_PIPE;
/// Fixed session-local endpoint owned by the unpackaged per-user CORE daemon.
pub const CORE_PRIVATE_PIPE: &str = stein_broker_windows::CORE_PRIVATE_PIPE;
/// Matches the typed IPC transport's accepted JSON frame bound.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

const FRAME_BODY_DEADLINE: Duration = Duration::from_secs(5);
const FRAME_WRITE_DEADLINE: Duration = Duration::from_secs(5);
const FIRST_FRAME_START_DEADLINE: Duration = Duration::from_secs(10);

#[cfg(not(feature = "development-package"))]
pub const PACKAGE_NAME: &str = stein_broker_windows::PRODUCTION_PACKAGE_NAME;
#[cfg(feature = "development-package")]
pub const PACKAGE_NAME: &str = "STEIN.PersonalIntelligence.Dev";

/// The manifest application identities are stable. Their full AUMIDs are
/// `<kernel-verified PFN>!<application id>` at runtime.
pub const DESKTOP_APPLICATION_ID: &str = stein_broker_windows::DESKTOP_APPLICATION_ID;
pub const BROKER_APPLICATION_ID: &str = stein_broker_windows::BROKER_APPLICATION_ID;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerError {
    #[error("runtime identity verification failed")]
    RuntimeIdentity,
    #[error("relay endpoint creation failed")]
    RelayEndpoint,
    #[error("desktop connection deadline exceeded")]
    DesktopDeadline,
    #[error("desktop admission failed")]
    DesktopAdmission,
    #[error("CORE connection failed")]
    CoreConnection,
    #[error("CORE server verification failed")]
    CoreAdmission,
    #[error("connection admission expired")]
    AdmissionExpired,
    #[error("framed relay failed")]
    Relay,
    #[error("release build is not pinned to a CORE image")]
    MissingCorePin,
}

#[cfg(windows)]
pub async fn run() -> Result<(), BrokerError> {
    windows::run().await
}

fn pinned_core_digest() -> Result<[u8; 32], BrokerError> {
    decode_sha256_hex(env!("STEIN_PINNED_CORE_SHA256")).ok_or(BrokerError::MissingCorePin)
}

fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = decode_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_nibble(pair[1])?)?;
    }
    if digest.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(digest)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

async fn forward_frames<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    forward_frames_with_first_deadline(&mut reader, &mut writer, FIRST_FRAME_START_DEADLINE).await
}

async fn forward_frames_with_first_deadline<R, W>(
    mut reader: R,
    mut writer: W,
    first_frame_start_deadline: Duration,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut first_frame = true;
    loop {
        let start_deadline = first_frame.then_some(first_frame_start_deadline);
        let Some((header, body)) = read_bounded_frame(&mut reader, start_deadline).await? else {
            return Ok(());
        };
        first_frame = false;

        timeout(FRAME_WRITE_DEADLINE, async {
            writer.write_all(&header).await?;
            writer.write_all(&body.0).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame write deadline"))??;
    }
}

async fn read_bounded_frame<R>(
    reader: &mut R,
    start_deadline: Option<Duration>,
) -> io::Result<Option<([u8; 4], SensitiveFrame)>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    let first_byte = async { reader.read(&mut header[..1]).await };
    let first_byte_count = match start_deadline {
        Some(deadline) => timeout(deadline, first_byte)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "first frame deadline"))??,
        None => first_byte.await?,
    };
    if first_byte_count == 0 {
        return Ok(None);
    }

    timeout(FRAME_BODY_DEADLINE, reader.read_exact(&mut header[1..]))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame header deadline"))??;

    let length = u32::from_le_bytes(header) as usize;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length outside configured bound",
        ));
    }

    let mut body = SensitiveFrame(vec![0_u8; length]);
    timeout(FRAME_BODY_DEADLINE, reader.read_exact(&mut body.0))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame body deadline"))??;
    Ok(Some((header, body)))
}

struct SensitiveFrame(Vec<u8>);

impl Drop for SensitiveFrame {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn endpoints_are_distinct_fixed_local_names() {
        assert_ne!(BROKER_RELAY_PIPE, CORE_PRIVATE_PIPE);
        for endpoint in [BROKER_RELAY_PIPE, CORE_PRIVATE_PIPE] {
            assert!(endpoint.starts_with(r"\\.\pipe\LOCAL\"));
            assert!(!endpoint.contains("{sid}"));
        }
    }

    #[test]
    fn release_package_identity_is_not_the_development_identity() {
        #[cfg(not(feature = "development-package"))]
        assert_eq!(PACKAGE_NAME, "STEIN.PersonalIntelligence");
        #[cfg(feature = "development-package")]
        assert_eq!(PACKAGE_NAME, "STEIN.PersonalIntelligence.Dev");
    }

    #[test]
    fn digest_decoder_rejects_missing_malformed_and_zero_pins() {
        assert!(decode_sha256_hex("").is_none());
        assert!(decode_sha256_hex(&"0".repeat(64)).is_none());
        assert!(decode_sha256_hex(&"g".repeat(64)).is_none());
        assert!(decode_sha256_hex(&"a".repeat(63)).is_none());
        assert_eq!(decode_sha256_hex(&"ab".repeat(32)), Some([0xab; 32]));
    }

    #[tokio::test]
    async fn relay_forwards_an_exact_opaque_frame() {
        let (mut sender, source) = tokio::io::duplex(64);
        let (destination, mut receiver) = tokio::io::duplex(64);
        let payload = [0xff, 0x00, 0x7b, 0x80, 0x42];
        let mut expected = (payload.len() as u32).to_le_bytes().to_vec();
        expected.extend_from_slice(&payload);

        let relay = tokio::spawn(forward_frames(source, destination));
        sender.write_all(&expected).await.expect("write fixture");
        sender.shutdown().await.expect("close fixture");

        let mut actual = Vec::new();
        receiver
            .read_to_end(&mut actual)
            .await
            .expect("read fixture");
        relay.await.expect("relay task").expect("relay result");
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn relay_rejects_zero_and_oversized_frames_without_forwarding() {
        for length in [0_u32, (MAX_FRAME_BYTES + 1) as u32] {
            let (mut sender, source) = tokio::io::duplex(16);
            let (destination, mut receiver) = tokio::io::duplex(16);
            let relay = tokio::spawn(forward_frames(source, destination));
            sender
                .write_all(&length.to_le_bytes())
                .await
                .expect("write fixture");
            sender.shutdown().await.expect("close fixture");

            let error = relay
                .await
                .expect("relay task")
                .expect_err("invalid frame must fail");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let mut actual = Vec::new();
            receiver
                .read_to_end(&mut actual)
                .await
                .expect("read fixture");
            assert!(actual.is_empty());
        }
    }

    #[tokio::test]
    async fn relay_bounds_only_the_initial_frame_start() {
        let (stalled_sender, stalled_source) = tokio::io::duplex(16);
        let (stalled_destination, _stalled_receiver) = tokio::io::duplex(16);
        let error = forward_frames_with_first_deadline(
            stalled_source,
            stalled_destination,
            Duration::from_millis(10),
        )
        .await
        .expect_err("the initial frame must have a start deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(stalled_sender);

        let (mut sender, source) = tokio::io::duplex(64);
        let (destination, mut receiver) = tokio::io::duplex(64);
        let first = [1_u8, 2, 3];
        let second = [4_u8, 5, 6];
        let relay = tokio::spawn(forward_frames_with_first_deadline(
            source,
            destination,
            Duration::from_millis(20),
        ));

        sender
            .write_all(&(first.len() as u32).to_le_bytes())
            .await
            .expect("write first header");
        sender.write_all(&first).await.expect("write first body");
        tokio::time::sleep(Duration::from_millis(40)).await;
        sender
            .write_all(&(second.len() as u32).to_le_bytes())
            .await
            .expect("write second header after idle");
        sender.write_all(&second).await.expect("write second body");
        sender.shutdown().await.expect("close fixture");

        let mut actual = Vec::new();
        receiver
            .read_to_end(&mut actual)
            .await
            .expect("read relayed frames");
        relay.await.expect("relay task").expect("relay result");

        let mut expected = (first.len() as u32).to_le_bytes().to_vec();
        expected.extend_from_slice(&first);
        expected.extend_from_slice(&(second.len() as u32).to_le_bytes());
        expected.extend_from_slice(&second);
        assert_eq!(actual, expected);
    }
}
