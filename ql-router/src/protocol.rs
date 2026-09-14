//! attachment and framing for the encrypted router transport

use std::{fmt, io};

use ql_codec::{codec, Decode, Encode, Reader};
use ql_common::QID;
use ql_wire::{
    Ik1, Ik2, Nonce, QlAead, QlHandshakeRecord, QlHash, QlRandom, RecordHeader, SessionKey,
    ENCRYPTED_MESSAGE_AUTH_SIZE,
};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "tokio")]
use crate::invalid_data;
use crate::MAX_RECORD_SIZE;

const FRAME_HEADER_SIZE: usize = 4;
const PACKET_HEADER_SIZE: usize = FRAME_HEADER_SIZE + 1;
const PACKET_OVERHEAD: usize = 1 + ENCRYPTED_MESSAGE_AUTH_SIZE;
const MAX_FRAME_SIZE: usize = MAX_RECORD_SIZE + PACKET_OVERHEAD;
const COOKIE_STATE_SIZE: usize = QID::SIZE + SessionKey::SIZE + size_of::<u64>() * 2;
const COOKIE_DOMAIN: &[u8] = b"ql-router-cookie-v1";
const CONFIRM_DOMAIN: &[u8] = b"ql-router-confirm-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Codec(ql_codec::Error),
    InvalidFrame,
    FrameTooLarge,
    AuthenticationFailed,
    ExpiredCookie,
    WrongConnection,
    TrailingData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::InvalidFrame => f.write_str("invalid frame"),
            Self::FrameTooLarge => f.write_str("frame exceeds transport limit"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::ExpiredCookie => f.write_str("expired attachment cookie"),
            Self::WrongConnection => f.write_str("attachment cookie belongs to another connection"),
            Self::TrailingData => f.write_str("trailing attachment data"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ql_codec::Error> for Error {
    fn from(error: ql_codec::Error) -> Self {
        Self::Codec(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        let kind = match error {
            Error::FrameTooLarge => io::ErrorKind::InvalidInput,
            Error::AuthenticationFailed | Error::ExpiredCookie | Error::WrongConnection => {
                io::ErrorKind::PermissionDenied
            }
            Error::Codec(_) | Error::InvalidFrame | Error::TrailingData => {
                io::ErrorKind::InvalidData
            }
        };
        Self::new(kind, error)
    }
}

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

codec! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AttachRecord as AttachKind {
        Initiate(Ik1) = 1,
        Challenge(AttachChallenge) = 2,
        Confirm(AttachConfirm) = 3,
    }
}

codec! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AttachChallenge {
        pub handshake: Ik2,
        pub cookie: AttachCookie,
    }
}

codec! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AttachConfirm {
        pub cookie: AttachCookie,
        pub tag: [u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    }
}

codec! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AttachCookie {
        pub nonce: Nonce,
        pub ciphertext: [u8; COOKIE_STATE_SIZE],
        pub tag: [u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    }
}

ql_codec::codec! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CookieState {
        qid: QID,
        key: SessionKey,
        connection_id: u64,
        expires_at: u64,
    }
}

pub fn seal_cookie(
    crypto: &(impl QlAead + QlRandom),
    key: &SessionKey,
    qid: QID,
    confirmation_key: SessionKey,
    connection_id: u64,
    expires_at: u64,
) -> AttachCookie {
    let mut nonce = Nonce([0; Nonce::SIZE]);
    crypto.fill_random_bytes(&mut nonce.0);
    let mut encoded = [0; COOKIE_STATE_SIZE];
    CookieState {
        qid,
        key: confirmation_key,
        connection_id,
        expires_at,
    }
    .encode(&mut encoded.as_mut_slice());
    let tag = crypto.aes256_gcm_encrypt(key, &nonce, COOKIE_DOMAIN, &mut encoded);
    AttachCookie {
        nonce,
        ciphertext: encoded,
        tag,
    }
}

pub fn confirm_cookie(
    crypto: &(impl QlAead + QlHash),
    key: &SessionKey,
    cookie: AttachCookie,
) -> AttachConfirm {
    let aad = crypto.sha256(&[
        CONFIRM_DOMAIN,
        &cookie.nonce.0,
        &cookie.ciphertext,
        &cookie.tag,
    ]);
    let tag = crypto.aes256_gcm_encrypt(key, &Nonce::from_counter(0), &aad, &mut []);
    AttachConfirm { cookie, tag }
}

pub fn open_confirmation(
    crypto: &(impl QlAead + QlHash),
    key: &SessionKey,
    connection_id: u64,
    now: u64,
    confirmation: &AttachConfirm,
) -> Result<QID, Error> {
    let mut state = confirmation.cookie.ciphertext;
    if !crypto.aes256_gcm_decrypt(
        key,
        &confirmation.cookie.nonce,
        COOKIE_DOMAIN,
        &mut state,
        &confirmation.cookie.tag,
    ) {
        return Err(Error::AuthenticationFailed);
    }
    let state = CookieState::decode_bytes(state.as_slice())?;
    if state.connection_id != connection_id {
        return Err(Error::WrongConnection);
    }
    if state.expires_at <= now {
        return Err(Error::ExpiredCookie);
    }
    let aad = crypto.sha256(&[
        CONFIRM_DOMAIN,
        &confirmation.cookie.nonce.0,
        &confirmation.cookie.ciphertext,
        &confirmation.cookie.tag,
    ]);
    if !crypto.aes256_gcm_decrypt(
        &state.key,
        &Nonce::from_counter(0),
        &aad,
        &mut [],
        &confirmation.tag,
    ) {
        return Err(Error::AuthenticationFailed);
    }
    Ok(state.qid)
}

pub fn decode_attach(bytes: &[u8]) -> Result<(RecordHeader, AttachRecord), Error> {
    let mut reader = Reader::new(bytes);
    let decoded = (reader.decode()?, reader.decode()?);
    if !reader.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(decoded)
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
) -> Result<Vec<u8>, Error> {
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
) -> Result<(), Error> {
    let length = PACKET_OVERHEAD
        .checked_add(payload.len())
        .filter(|length| *length <= MAX_FRAME_SIZE)
        .ok_or(Error::FrameTooLarge)?;
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
) -> Result<Packet<'a>, Error> {
    if packet.len() < FRAME_HEADER_SIZE + PACKET_OVERHEAD {
        return Err(Error::InvalidFrame);
    }
    let length = u32::decode_bytes(&packet[..FRAME_HEADER_SIZE])?;
    if length as usize != packet.len() - FRAME_HEADER_SIZE {
        return Err(Error::InvalidFrame);
    }
    let kind = PacketKind::decode_bytes(&packet[FRAME_HEADER_SIZE..])?;
    let tag_at = packet.len() - ENCRYPTED_MESSAGE_AUTH_SIZE;
    let tag = <[u8; ENCRYPTED_MESSAGE_AUTH_SIZE]>::decode_bytes(&packet[tag_at..])?;
    if !crypto.aes256_gcm_decrypt(
        key,
        &Nonce::from_counter(nonce),
        &packet[..tag_at],
        &mut [],
        &tag,
    ) {
        return Err(Error::AuthenticationFailed);
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
) -> Result<(PacketKind, Vec<u8>), Error> {
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
        return Err(Error::FrameTooLarge.into());
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
        return Err(Error::FrameTooLarge.into());
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

#[cfg(test)]
mod tests {
    use ql_common::QID;
    use ql_wire::{SessionKey, SoftwareCrypto};

    use super::{confirm_cookie, open_confirmation, seal_cookie};
    #[cfg(feature = "tokio")]
    use super::{
        open_packet, open_packet_owned, seal_packet, Frame, PacketKind, FRAME_HEADER_SIZE,
        PACKET_HEADER_SIZE,
    };

    #[cfg(feature = "tokio")]
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

    #[test]
    fn attachment_cookie_confirms_private_key_possession() {
        let cookie_key = SessionKey([1; SessionKey::SIZE]);
        let qid = QID([2; QID::SIZE]);
        let confirmation_key = SessionKey([3; SessionKey::SIZE]);
        let cookie = seal_cookie(
            &SoftwareCrypto,
            &cookie_key,
            qid,
            confirmation_key.clone(),
            4,
            6,
        );
        let forged = confirm_cookie(
            &SoftwareCrypto,
            &SessionKey([4; SessionKey::SIZE]),
            cookie.clone(),
        );
        assert!(open_confirmation(&SoftwareCrypto, &cookie_key, 4, 5, &forged).is_err());

        let confirmation = confirm_cookie(&SoftwareCrypto, &confirmation_key, cookie);
        assert_eq!(
            open_confirmation(&SoftwareCrypto, &cookie_key, 4, 5, &confirmation).unwrap(),
            qid
        );
        assert!(open_confirmation(&SoftwareCrypto, &cookie_key, 5, 5, &confirmation).is_err());
        assert!(open_confirmation(&SoftwareCrypto, &cookie_key, 4, 6, &confirmation).is_err());

        let mut changed = confirmation;
        changed.tag[0] ^= 1;
        assert!(open_confirmation(&SoftwareCrypto, &cookie_key, 4, 5, &changed).is_err());
    }
}
