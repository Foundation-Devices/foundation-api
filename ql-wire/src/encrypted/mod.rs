use ql_codec::{ByteSlice, Reader};
use ql_common::StreamId;

use crate::{
    encrypted_message::EncryptedMessage, Error, Nonce, QlCrypto, SessionHeader, SessionKey,
};

mod ack;
mod builder;
mod close;
mod stream_data;
mod stream_reset;
mod stream_window;

pub use ack::*;
pub use builder::*;
pub use close::*;
pub use stream_data::*;
pub use stream_reset::*;
pub use stream_window::*;

ql_codec::codec_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SessionFrame<B> as SessionFrameKind {
        // todo: do we need ping as explicit frame?
        Ping = 1,
        Ack(RecordAck) = 2,
        StreamData(StreamData<B>) = 3,
        StreamWindow(StreamWindow) = 4,
        StreamReset(StreamReset) = 5,
        Close(SessionClose) = 6,
        Unpair = 7,
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
            Self::StreamReset(frame) => SessionFrame::StreamReset(frame),
            Self::Close(frame) => SessionFrame::Close(frame),
        }
    }
}

pub fn parse_session_frames<B: ByteSlice>(bytes: B) -> SessionFrameIter<B> {
    SessionFrameIter {
        reader: Reader::new(bytes),
    }
}

pub fn decode_session_frames(bytes: &[u8]) -> Result<Vec<SessionFrame<Vec<u8>>>, Error> {
    parse_session_frames(bytes)
        .map(|frame| frame.map(SessionFrame::into_owned))
        .collect()
}

#[derive(Clone)]
pub struct SessionFrameIter<B> {
    reader: Reader<B>,
}

impl<B: ByteSlice> Iterator for SessionFrameIter<B> {
    type Item = Result<SessionFrame<B>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            None
        } else {
            Some(self.reader.decode::<SessionFrame<B>>().map_err(Into::into))
        }
    }
}

pub fn decrypt_record<B: AsMut<[u8]>>(
    crypto: &impl QlCrypto,
    record_header: &crate::RecordHeader,
    header: &SessionHeader,
    encrypted: EncryptedMessage<B>,
    session_key: &SessionKey,
) -> Result<B, Error> {
    let aad = header.aad(record_header.route);
    let nonce = Nonce::from_counter(header.seq.0);
    let mut ciphertext = encrypted.ciphertext;
    if !crypto.aes256_gcm_decrypt(
        session_key,
        &nonce,
        &aad,
        ciphertext.as_mut(),
        &encrypted.auth,
    ) {
        return Err(Error::DecryptFailed);
    }
    Ok(ciphertext)
}
