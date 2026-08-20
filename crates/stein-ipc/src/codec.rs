use std::io;

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard limit applied before JSON decoding.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32_le().await? as usize;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length protocol frame",
        ));
    }
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol frame exceeds configured limit",
        ));
    }

    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid protocol JSON"))
}

pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message serialization failed"))?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "serialized protocol frame is outside configured limits",
        ));
    }

    writer.write_u32_le(body.len() as u32).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Fixture {
        value: String,
    }

    #[tokio::test]
    async fn round_trips_one_frame() {
        let (mut left, mut right) = duplex(1024);
        let send = Fixture {
            value: "synthetic".into(),
        };
        let writer = tokio::spawn(async move { write_frame(&mut left, &send).await });
        let received: Fixture = read_frame(&mut right).await.expect("frame should decode");
        writer.await.expect("writer task").expect("write succeeds");
        assert_eq!(received.value, "synthetic");
    }

    #[tokio::test]
    async fn rejects_oversized_length_before_allocating_body() {
        let (mut left, mut right) = duplex(16);
        left.write_u32_le((MAX_FRAME_BYTES + 1) as u32)
            .await
            .expect("length write");
        let result = read_frame::<_, Fixture>(&mut right).await;
        assert_eq!(
            result.expect_err("oversize must fail").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn rejects_zero_length_and_malformed_json() {
        let (mut left, mut right) = duplex(32);
        left.write_u32_le(0).await.expect("length write");
        assert_eq!(
            read_frame::<_, Fixture>(&mut right)
                .await
                .expect_err("zero must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (mut left, mut right) = duplex(32);
        left.write_u32_le(4).await.expect("length write");
        left.write_all(b"nope").await.expect("body write");
        assert_eq!(
            read_frame::<_, Fixture>(&mut right)
                .await
                .expect_err("malformed must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
