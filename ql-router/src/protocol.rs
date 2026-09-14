//! framing for the encrypted router transport

use std::io;

use ql_codec::{codec, Decode, Encode};
use ql_wire::{
    Nonce, QlAead, QlHandshakeRecord, RecordHeader, SessionKey, ENCRYPTED_MESSAGE_AUTH_SIZE,
};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{invalid_data, MAX_RECORD_SIZE};

const FRAME_HEADER_SIZE: usize = 4;
const PACKET_HEADER_SIZE: usize = FRAME_HEADER_SIZE + 1;
const PACKET_OVERHEAD: usize = 1 + ENCRYPTED_MESSAGE_AUTH_SIZE;
const MAX_FRAME_SIZE: usize = MAX_RECORD_SIZE + PACKET_OVERHEAD;

codec! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PacketKind {
        Confirm = 1,
        Attach = 2,
        Record = 3,
    }
}

codec! {
    pub struct TransportResponse {
        pub header: RecordHeader,
        pub handshake: QlHandshakeRecord,
    }
}

#[cfg(feature = "tokio")]
pub struct Frame(Vec<u8>);

#[cfg(feature = "tokio")]
impl Frame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[FRAME_HEADER_SIZE..]
    }
}

pub struct Packet<'a> {
    pub kind: PacketKind,
    pub payload: &'a [u8],
}

#[inline]
pub fn take_counter(next: &mut u64) -> Option<u64> {
    let number = *next;
    *next = number.checked_add(1)?;
    Some(number)
}

pub fn seal_packet(
    crypto: &impl QlAead,
    key: &SessionKey,
    kind: PacketKind,
    nonce: u64,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(FRAME_HEADER_SIZE + PACKET_OVERHEAD + payload.len());
    seal_packet_into(crypto, &mut packet, key, kind, nonce, payload)?;
    Ok(packet)
}

pub fn seal_packet_into(
    crypto: &impl QlAead,
    packet: &mut Vec<u8>,
    key: &SessionKey,
    kind: PacketKind,
    nonce: u64,
    payload: &[u8],
) -> io::Result<()> {
    let length = PACKET_OVERHEAD
        .checked_add(payload.len())
        .filter(|length| *length <= MAX_FRAME_SIZE)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds transport limit")
        })?;
    packet.clear();
    packet.reserve(FRAME_HEADER_SIZE + length);
    (length as u32).encode(packet);
    kind.encode(packet);
    packet.extend_from_slice(payload);
    let tag = crypto.aes256_gcm_encrypt(key, &Nonce::from_counter(nonce), packet, &mut []);
    packet.extend_from_slice(&tag);
    Ok(())
}

pub fn open_packet<'a>(
    crypto: &impl QlAead,
    key: &SessionKey,
    nonce: u64,
    packet: &'a [u8],
) -> io::Result<Packet<'a>> {
    if packet.len() < FRAME_HEADER_SIZE + PACKET_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid authenticated frame",
        ));
    }
    let length = u32::decode_bytes(&packet[..FRAME_HEADER_SIZE]).map_err(invalid_data)?;
    if length as usize != packet.len() - FRAME_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid authenticated frame length",
        ));
    }
    let kind = PacketKind::decode_bytes(&packet[FRAME_HEADER_SIZE..]).map_err(invalid_data)?;
    let tag_at = packet.len() - ENCRYPTED_MESSAGE_AUTH_SIZE;
    let tag = <[u8; ENCRYPTED_MESSAGE_AUTH_SIZE]>::decode_bytes(&packet[tag_at..])
        .map_err(invalid_data)?;
    if !crypto.aes256_gcm_decrypt(
        key,
        &Nonce::from_counter(nonce),
        &packet[..tag_at],
        &mut [],
        &tag,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated packet tag mismatch",
        ));
    }
    Ok(Packet {
        kind,
        payload: &packet[PACKET_HEADER_SIZE..tag_at],
    })
}

#[cfg(feature = "tokio")]
pub fn open_packet_owned(
    crypto: &impl QlAead,
    key: &SessionKey,
    nonce: u64,
    frame: Frame,
) -> io::Result<(PacketKind, Vec<u8>)> {
    let mut packet = frame.0;
    let opened = open_packet(crypto, key, nonce, &packet)?;
    let kind = opened.kind;
    let payload_len = opened.payload.len();
    packet.copy_within(PACKET_HEADER_SIZE..PACKET_HEADER_SIZE + payload_len, 0);
    packet.truncate(payload_len);
    Ok((kind, packet))
}

#[cfg(feature = "tokio")]
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Frame>> {
    let mut header = [0; FRAME_HEADER_SIZE];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u32::decode_bytes(header.as_slice()).map_err(invalid_data)? as usize;
    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds transport limit",
        ));
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + length);
    frame.extend_from_slice(&header);
    frame.resize(FRAME_HEADER_SIZE + length, 0);
    reader.read_exact(&mut frame[FRAME_HEADER_SIZE..]).await?;
    Ok(Some(Frame(frame)))
}

#[cfg(feature = "tokio")]
pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds transport limit",
        ));
    }
    let mut header = [0; FRAME_HEADER_SIZE];
    (payload.len() as u32).encode(&mut header.as_mut_slice());
    writer.write_all(&header).await?;
    writer.write_all(payload).await
}

#[cfg(feature = "tokio")]
pub async fn write_packet(writer: &mut (impl AsyncWrite + Unpin), packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet).await
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use ql_wire::{SessionKey, SoftwareCrypto};

    use super::{
        open_packet, open_packet_owned, seal_packet, Frame, PacketKind, FRAME_HEADER_SIZE,
        PACKET_HEADER_SIZE,
    };

    #[test]
    fn packet_authentication_covers_the_entire_frame_and_counter() {
        let key = SessionKey([7; SessionKey::SIZE]);
        let packet = seal_packet(&SoftwareCrypto, &key, PacketKind::Record, 4, b"record").unwrap();
        let (kind, payload) =
            open_packet_owned(&SoftwareCrypto, &key, 4, Frame(packet.clone())).unwrap();
        assert_eq!(kind, PacketKind::Record);
        assert_eq!(payload, b"record");
        assert!(open_packet(&SoftwareCrypto, &key, 5, &packet).is_err());

        for index in [0, FRAME_HEADER_SIZE, PACKET_HEADER_SIZE] {
            let mut changed = packet.clone();
            changed[index] ^= 1;
            assert!(open_packet(&SoftwareCrypto, &key, 4, &changed).is_err());
        }
    }
}
