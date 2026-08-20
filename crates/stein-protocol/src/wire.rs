use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{ClientMessage, ServerMessage};

pub const LENGTH_PREFIX_BYTES: usize = 4;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Serializes one message as a little-endian length-prefixed JSON frame.
pub fn encode_frame<T: Serialize>(message: &T, maximum: usize) -> Result<Vec<u8>, WireError> {
    let payload = serde_json::to_vec(message).map_err(WireError::json)?;
    validate_payload_length(payload.len(), maximum)?;
    let wire_length = u32::try_from(payload.len()).map_err(|_| WireError::LengthOverflow)?;

    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&wire_length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Parses and validates the four-byte frame prefix before a transport allocates
/// a payload buffer.
pub fn parse_length_prefix(
    prefix: [u8; LENGTH_PREFIX_BYTES],
    maximum: usize,
) -> Result<usize, WireError> {
    let payload_length = u32::from_le_bytes(prefix) as usize;
    validate_payload_length(payload_length, maximum)?;
    Ok(payload_length)
}

/// Decodes a JSON payload after the transport has consumed its length prefix.
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8], maximum: usize) -> Result<T, WireError> {
    validate_payload_length(payload.len(), maximum)?;
    serde_json::from_slice(payload).map_err(WireError::json)
}

pub fn decode_client_payload(payload: &[u8], maximum: usize) -> Result<ClientMessage, WireError> {
    decode_payload(payload, maximum)
}

pub fn decode_server_payload(payload: &[u8], maximum: usize) -> Result<ServerMessage, WireError> {
    decode_payload(payload, maximum)
}

/// Splits a complete frame for tests and buffered transports. Streaming IPC
/// should call [`parse_length_prefix`] and then read exactly the returned size.
pub fn split_complete_frame(frame: &[u8], maximum: usize) -> Result<&[u8], WireError> {
    if frame.len() < LENGTH_PREFIX_BYTES {
        return Err(WireError::TruncatedPrefix {
            actual: frame.len(),
        });
    }

    let prefix: [u8; LENGTH_PREFIX_BYTES] = frame[..LENGTH_PREFIX_BYTES]
        .try_into()
        .expect("slice length was checked");
    let declared = parse_length_prefix(prefix, maximum)?;
    let actual = frame.len() - LENGTH_PREFIX_BYTES;
    if declared != actual {
        return Err(WireError::LengthMismatch { declared, actual });
    }

    Ok(&frame[LENGTH_PREFIX_BYTES..])
}

fn validate_payload_length(actual: usize, maximum: usize) -> Result<(), WireError> {
    if actual == 0 {
        return Err(WireError::EmptyPayload);
    }
    if actual > maximum {
        return Err(WireError::FrameTooLarge { actual, maximum });
    }
    if actual > u32::MAX as usize {
        return Err(WireError::LengthOverflow);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("frame payload cannot be empty")]
    EmptyPayload,
    #[error("frame payload is {actual} bytes; maximum is {maximum} bytes")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("frame length cannot be represented by the wire prefix")]
    LengthOverflow,
    #[error("frame prefix is truncated: received {actual} of 4 bytes")]
    TruncatedPrefix { actual: usize },
    #[error("frame declares {declared} bytes but contains {actual} bytes")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("invalid JSON protocol message at line {line}, column {column}")]
    Json {
        #[source]
        source: serde_json::Error,
        line: usize,
        column: usize,
    },
}

impl WireError {
    fn json(source: serde_json::Error) -> Self {
        let line = source.line();
        let column = source.column();
        Self::Json {
            source,
            line,
            column,
        }
    }
}

impl WireError {
    #[must_use]
    pub const fn is_size_error(&self) -> bool {
        matches!(
            self,
            Self::EmptyPayload | Self::FrameTooLarge { .. } | Self::LengthOverflow
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_error_classification_is_private_to_codec() {
        assert!(WireError::EmptyPayload.is_size_error());
        assert!(!WireError::TruncatedPrefix { actual: 2 }.is_size_error());
    }
}
