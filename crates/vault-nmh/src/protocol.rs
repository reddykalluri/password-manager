//! Browser native-messaging framing: a 4-byte native-endian length prefix
//! followed by a UTF-8 JSON message (Chrome/Firefox spec).

use std::io::{self, Read, Write};

use serde_json::Value;

/// Browsers reject messages larger than 1 MB (host→browser) / 4 GB
/// (browser→host); we cap reads defensively well below that.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Read one framed message. Returns `Ok(None)` at clean end of stream (the
/// browser closed the port).
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    if let Err(err) = reader.read_exact(&mut len_buf) {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(err);
    }
    // Native byte order, per the native-messaging spec.
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native-messaging message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    let value = serde_json::from_slice(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(value))
}

/// Write one framed message.
pub fn write_message<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(message)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frames_round_trip() {
        let mut buf: Vec<u8> = Vec::new();
        let msg = json!({"type": "unlock_state", "n": 42});
        write_message(&mut buf, &msg).unwrap();
        // 4-byte prefix + payload.
        assert_eq!(&buf[..4], &(buf.len() as u32 - 4).to_ne_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let got = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(got, msg);
        // Clean EOF afterwards.
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_length() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(u32::MAX).to_ne_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_message(&mut cursor).is_err());
    }
}
