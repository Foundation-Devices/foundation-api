use std::borrow::Borrow;

use ql_codec::Reader;
use ql_common::QID;

use super::{HandshakeId, IkHandshake, TransportParams};
use crate::{
    decrypt_record, encode_record_vec, parse_session_frames, Error, PeerBundle, QlCrypto,
    QlHandshakeRecord, QlIdentity, QlSessionRecord, RecordHeader, RecordSeq, RecordType,
    RouteHeader, SessionFrame, SessionKey, SessionRecordBuilder, QL_WIRE_VERSION,
};

pub struct PeerChallenge<I> {
    handshake: IkHandshake<I>,
}

impl<I: Borrow<QlIdentity>> PeerChallenge<I> {
    pub fn new(
        crypto: &impl QlCrypto,
        local: I,
        remote: PeerBundle,
        handshake_id: HandshakeId,
    ) -> Result<(Self, Vec<u8>), Error> {
        let route = RouteHeader {
            sender: local.borrow().qid,
            recipient: remote.qid,
        };
        let mut handshake =
            IkHandshake::new_kk_initiator(crypto, local, remote, TransportParams::default());
        let request = handshake.write_1(crypto, handshake_id)?;
        let request = encode_record_vec(
            RecordHeader::new(route, RecordType::Handshake),
            &QlHandshakeRecord::Kk1(request),
        );
        Ok((Self { handshake }, request))
    }

    pub fn verify(
        mut self,
        crypto: &impl QlCrypto,
        response: &[u8],
    ) -> Result<(QID, Vec<u8>), Error> {
        let (header, response) = decode_handshake(response)?;
        let QlHandshakeRecord::Kk2(response) = response else {
            return Err(Error::InvalidPayload);
        };
        self.handshake.read_2(crypto, header.route, &response)?;
        let session = self.handshake.finalize(crypto)?;
        let qid = session.remote_bundle.qid;
        let route = RouteHeader {
            sender: header.route.recipient,
            recipient: qid,
        };
        let mut confirmation =
            SessionRecordBuilder::new(RecordSeq(0), SessionRecordBuilder::MIN_CAPACITY + 1);
        confirmation.push_ping();
        Ok((qid, confirmation.encrypt(crypto, route, &session.tx_key)))
    }
}

pub struct PendingChallengeConfirmation {
    route: RouteHeader,
    rx_key: SessionKey,
}

impl PendingChallengeConfirmation {
    pub fn verify(self, crypto: &impl QlCrypto, confirmation: &mut [u8]) -> Result<(), Error> {
        let mut reader = Reader::new(confirmation);
        let header = reader.decode::<RecordHeader>()?;
        if header.version != QL_WIRE_VERSION
            || header.route != self.route
            || header.record_type != RecordType::Session
        {
            return Err(Error::InvalidPayload);
        }
        let record = reader.decode::<QlSessionRecord<_>>()?;
        if record.header.seq != RecordSeq(0) {
            return Err(Error::InvalidPayload);
        }
        let payload = decrypt_record(
            crypto,
            &header,
            &record.header,
            record.payload,
            &self.rx_key,
        )?;
        let mut frames = parse_session_frames(payload);
        if !matches!(frames.next().transpose()?, Some(SessionFrame::Ping))
            || frames.next().is_some()
        {
            return Err(Error::InvalidPayload);
        }
        Ok(())
    }
}

pub fn answer_peer_challenge<I: Borrow<QlIdentity>>(
    crypto: &impl QlCrypto,
    local: I,
    challenger: PeerBundle,
    request: &[u8],
) -> Result<(Vec<u8>, PendingChallengeConfirmation), Error> {
    let (header, request) = decode_handshake(request)?;
    let QlHandshakeRecord::Kk1(request) = request else {
        return Err(Error::InvalidPayload);
    };
    let mut handshake =
        IkHandshake::new_kk_responder(crypto, local, challenger, TransportParams::default());
    handshake.read_1(crypto, header.route, &request)?;
    let response = handshake.write_2(crypto, request.handshake_id)?;
    let session = handshake.finalize(crypto)?;
    let response = encode_record_vec(
        RecordHeader::new(
            RouteHeader {
                sender: header.route.recipient,
                recipient: header.route.sender,
            },
            RecordType::Handshake,
        ),
        &QlHandshakeRecord::Kk2(response),
    );
    Ok((
        response,
        PendingChallengeConfirmation {
            route: header.route,
            rx_key: session.rx_key,
        },
    ))
}

fn decode_handshake(bytes: &[u8]) -> Result<(RecordHeader, QlHandshakeRecord), Error> {
    let mut reader = Reader::new(bytes);
    let header = reader.decode::<RecordHeader>()?;
    if header.version != QL_WIRE_VERSION || header.record_type != RecordType::Handshake {
        return Err(Error::InvalidPayload);
    }
    let record = reader.decode()?;
    if !reader.is_empty() {
        return Err(Error::InvalidPayload);
    }
    Ok((header, record))
}
