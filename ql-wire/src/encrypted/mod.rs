use crate::{
    codec, encrypted_message::EncryptedMessage, BufView, ByteSlice, Nonce, QlCrypto, Reader,
    SessionHeader, SessionKey, WireDecode, WireEncode, WireError,
};

mod ack;
mod builder;
mod close;
mod route_id;
mod stream_close;
mod stream_data;
mod stream_id;
mod stream_window;

pub use ack::*;
pub use builder::*;
pub use close::*;
pub use route_id::*;
pub use stream_close::*;
pub use stream_data::*;
pub use stream_id::*;
pub use stream_window::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFrame<B> {
    // todo: do we need ping as explicit frame?
    Ping,
    Unpair,
    Ack(RecordAck),
    StreamData(StreamData<B>),
    StreamWindow(StreamWindow),
    StreamClose(StreamClose),
    Close(SessionClose),
}

impl<B: ByteSlice> WireDecode<B> for SessionFrame<B> {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        let kind = reader.decode::<SessionFrameKind>()?;
        let frame = match kind {
            SessionFrameKind::Ping => Self::Ping,
            SessionFrameKind::Unpair => Self::Unpair,
            SessionFrameKind::Ack => Self::Ack(reader.decode::<RecordAck>()?),
            SessionFrameKind::StreamData => Self::StreamData(reader.decode::<StreamData<B>>()?),
            SessionFrameKind::StreamWindow => Self::StreamWindow(reader.decode::<StreamWindow>()?),
            SessionFrameKind::StreamClose => Self::StreamClose(reader.decode::<StreamClose>()?),
            SessionFrameKind::Close => Self::Close(reader.decode::<SessionClose>()?),
        };
        Ok(frame)
    }
}

impl<B> SessionFrame<B> {
    fn kind(&self) -> SessionFrameKind {
        match self {
            Self::Ping => SessionFrameKind::Ping,
            Self::Unpair => SessionFrameKind::Unpair,
            Self::Ack(_) => SessionFrameKind::Ack,
            Self::StreamData(_) => SessionFrameKind::StreamData,
            Self::StreamWindow(_) => SessionFrameKind::StreamWindow,
            Self::StreamClose(_) => SessionFrameKind::StreamClose,
            Self::Close(_) => SessionFrameKind::Close,
        }
    }
}

impl<B: ByteSlice> SessionFrame<B> {
    pub fn into_owned(self) -> SessionFrame<Vec<u8>> {
        match self {
            Self::Ping => SessionFrame::Ping,
            Self::Unpair => SessionFrame::Unpair,
            Self::Ack(frame) => SessionFrame::Ack(frame),
            Self::StreamData(frame) => SessionFrame::StreamData(frame.into_owned()),
            Self::StreamWindow(frame) => SessionFrame::StreamWindow(frame),
            Self::StreamClose(frame) => SessionFrame::StreamClose(frame),
            Self::Close(frame) => SessionFrame::Close(frame),
        }
    }
}

impl<B: BufView> WireEncode for SessionFrame<B> {
    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Ping | Self::Unpair => 0,
            Self::Ack(frame) => frame.encoded_len(),
            Self::StreamData(frame) => frame.encoded_len(),
            Self::StreamWindow(frame) => frame.encoded_len(),
            Self::StreamClose(frame) => frame.encoded_len(),
            Self::Close(frame) => frame.encoded_len(),
        }
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(self.kind() as u8);
        match self {
            Self::Ping | Self::Unpair => {}
            Self::Ack(frame) => frame.encode(out),
            Self::StreamData(frame) => frame.encode(out),
            Self::StreamWindow(frame) => frame.encode(out),
            Self::StreamClose(frame) => frame.encode(out),
            Self::Close(frame) => frame.encode(out),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionFrameKind {
    Ping = 1,
    Ack = 2,
    StreamData = 3,
    StreamWindow = 4,
    StreamClose = 5,
    Close = 6,
    Unpair = 7,
}

impl TryFrom<u8> for SessionFrameKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::Ack),
            3 => Ok(Self::StreamData),
            4 => Ok(Self::StreamWindow),
            5 => Ok(Self::StreamClose),
            6 => Ok(Self::Close),
            7 => Ok(Self::Unpair),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for SessionFrameKind {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        reader.decode::<u8>()?.try_into()
    }
}

pub fn parse_session_frames<B: ByteSlice>(bytes: B) -> SessionFrameIter<B> {
    SessionFrameIter {
        reader: Reader::new(bytes),
    }
}

pub fn decode_session_frames(bytes: &[u8]) -> Result<Vec<SessionFrame<Vec<u8>>>, WireError> {
    parse_session_frames(bytes)
        .map(|frame| frame.map(SessionFrame::into_owned))
        .collect()
}

#[derive(Clone)]
pub struct SessionFrameIter<B> {
    reader: Reader<B>,
}

impl<B: ByteSlice> Iterator for SessionFrameIter<B> {
    type Item = Result<SessionFrame<B>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            None
        } else {
            Some(self.reader.decode::<SessionFrame<B>>())
        }
    }
}

pub fn decrypt_record<B: AsMut<[u8]>>(
    crypto: &impl QlCrypto,
    header: &SessionHeader,
    encrypted: EncryptedMessage<B>,
    session_key: &SessionKey,
) -> Result<B, WireError> {
    let aad = header.aad();
    let nonce = Nonce::from_counter(header.seq.into_inner());
    encrypted.decrypt_in_place(crypto, session_key, &nonce, &aad)
}
