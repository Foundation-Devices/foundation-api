use std::{collections::VecDeque, time::Instant};

use bytes::Bytes;
use ql_codec::{Decode, Reader};
use ql_common::StreamId;
use ql_wire::{self as wire, QlCrypto, SessionCloseCode};

use crate::{
    handshake,
    session::{self, SessionEvent, TerminalFrame},
    state::LinkState,
    Event, NoPeerError, NoSessionError, OutboundWrite, QlFsm, ReceiveError, ReceiveStage,
    StreamError, StreamMeta, WriteId,
};

pub struct EventSink<'a> {
    events: &'a mut VecDeque<Event>,
    termination: Option<TerminalFrame>,
}

impl<'a> EventSink<'a> {
    fn new(events: &'a mut VecDeque<Event>) -> Self {
        Self {
            events,
            termination: None,
        }
    }
}

impl session::EventSink for EventSink<'_> {
    fn emit(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Unpaired => {
                self.termination = Some(TerminalFrame::Unpair);
            }
            SessionEvent::Opened(stream_id) => {
                self.events.push_back(Event::Opened(stream_id));
            }
            SessionEvent::SessionClosed(close) => {
                self.termination = Some(TerminalFrame::Close(close.clone()));
                self.events.push_back(Event::SessionClosed(close));
            }
        }
    }
}

pub fn handle_bind_peer<M: StreamMeta>(fsm: &mut QlFsm<M>, peer: ql_wire::PeerBundle) {
    fsm.state.handshake = None;
    fsm.state.link = LinkState::Idle;
    fsm.state.peer = Some(peer);
}

pub fn unpair<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    let had_peer = fsm.state.peer.is_some();
    fsm.state.handshake = None;
    fsm.state.armed_pairing_token = None;

    if let Some(conn) = fsm.state.link.connected_mut() {
        let mut emit = EventSink::new(&mut fsm.events);
        conn.session.unpair(&mut emit);
    } else {
        fsm.state.link = LinkState::Idle;
    }

    if had_peer {
        emit_peer_status(fsm, crate::PeerStatus::Unpaired);
    }
    fsm.state.peer = None;
}

pub fn handle_disarm_pairing<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    fsm.state.armed_pairing_token = None;
    handshake::handle_disarm_pairing(fsm);
}

pub fn handle_connect_xx<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    invite: crate::PairingInvite,
    crypto: &impl QlCrypto,
) {
    handshake::handle_connect_xx(fsm, invite, crypto);
}

pub fn handle_connect_ik<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
) -> Result<(), NoPeerError> {
    handshake::handle_connect_ik(fsm, crypto)
}

pub fn handle_connect_kk<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
) -> Result<(), NoPeerError> {
    handshake::handle_connect_kk(fsm, crypto)
}

pub fn receive<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    mut bytes: Vec<u8>,
    crypto: &impl QlCrypto,
) -> Result<(), ReceiveError> {
    let mut reader = Reader::new(bytes.as_mut_slice());
    let header = wire::RecordHeader::decode(&mut reader)
        .map_err(|error| ReceiveError::wire(ReceiveStage::RecordHeader, error))?;

    if header.version != wire::QL_WIRE_VERSION {
        return Err(ReceiveError::InvalidRecordVersion);
    }
    if header.route.recipient != fsm.identity.qid {
        return Err(ReceiveError::InvalidQid);
    }

    match header.record_type {
        wire::RecordType::Handshake => {
            let record = wire::QlHandshakeRecord::decode(&mut reader)
                .map_err(|error| ReceiveError::wire(ReceiveStage::HandshakeRecord, error))?;
            handshake::handle_handshake_record(fsm, crypto, header.route, &record)
        }
        wire::RecordType::Session => {
            let termination = {
                let QlFsm { state, events, .. } = fsm;
                let conn = state.link.connected_mut_or_err()?;
                if header.route.sender != conn.transport.remote_qid {
                    return Err(ReceiveError::InvalidQid);
                }
                let (decrypt_len, seq) = {
                    let record = wire::QlSessionRecord::decode(&mut reader)
                        .map_err(|error| ReceiveError::wire(ReceiveStage::SessionRecord, error))?;
                    if conn.session.is_replay(record.header.seq) {
                        return Ok(());
                    }
                    let payload = wire::decrypt_record(
                        crypto,
                        &header,
                        &record.header,
                        record.payload,
                        &conn.transport.rx_key,
                    )
                    .map_err(|error| ReceiveError::wire(ReceiveStage::SessionPayload, error))?;
                    (payload.len(), record.header.seq)
                };

                let len = bytes.len();
                let plaintext = Bytes::from(bytes).slice(len - decrypt_len..);
                let frames = wire::parse_session_frames(plaintext);

                let mut emit = EventSink::new(events);
                conn.session.receive(state.now, seq, frames, &mut emit);
                emit.termination
            };

            if matches!(termination, Some(TerminalFrame::Unpair)) {
                if fsm.state.peer.is_some() {
                    emit_peer_status(fsm, crate::PeerStatus::Unpaired);
                }
                fsm.state.handshake = None;
                fsm.state.armed_pairing_token = None;
                fsm.state.peer = None;
            }
            Ok(())
        }
    }
}

pub fn on_timer<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    handshake::handle_timer(fsm);

    let QlFsm { state, events, .. } = fsm;
    let Some(conn) = state.link.connected_mut() else {
        return;
    };

    let mut emit = EventSink::new(events);
    conn.session.on_timer(state.now, &mut emit);
}

pub fn next_deadline<M: StreamMeta>(fsm: &QlFsm<M>) -> Option<Instant> {
    [
        handshake::next_handshake_deadline(fsm),
        fsm.state
            .link
            .connected()
            .and_then(|state| state.session.next_deadline()),
    ]
    .into_iter()
    .flatten()
    .min()
}

pub fn take_next_write<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
) -> Option<OutboundWrite> {
    if let Some((route, record)) = fsm.state.handshake.take() {
        let record = wire::encode_record_vec(
            wire::RecordHeader::new(route, ql_wire::RecordType::Handshake),
            &record,
        );
        return Some(OutboundWrite {
            record,
            write_id: None,
        });
    }

    let QlFsm { state, .. } = fsm;
    let conn = state.link.connected_mut()?;
    let route = wire::RouteHeader {
        sender: fsm.identity.qid,
        recipient: conn.transport.remote_qid,
    };

    let (write_id, builder) = conn.session.take_next_write(state.now)?;
    let record = builder.encrypt(crypto, route, &conn.transport.tx_key);
    if conn.session.is_closed() && matches!(fsm.state.link, LinkState::Connected(_)) {
        fsm.state.link = LinkState::Idle;
        emit_peer_status(fsm, fsm.state.link.status());
    }
    Some(OutboundWrite {
        record,
        write_id: write_id.map(WriteId),
    })
}

pub fn complete_write<M: StreamMeta>(fsm: &mut QlFsm<M>, write_id: WriteId, success: bool) {
    let QlFsm { state, .. } = fsm;
    if let Some(conn) = state.link.connected_mut() {
        conn.session.complete_write(state.now, write_id.0, success);
    }
}

pub fn close_session<M: StreamMeta>(fsm: &mut QlFsm<M>, code: SessionCloseCode) {
    let QlFsm { state, events, .. } = fsm;
    let Some(conn) = state.link.connected_mut() else {
        return;
    };
    let mut emit = EventSink::new(events);
    conn.session.close(code, &mut emit);
}

pub fn open_stream<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    header: Box<[u8]>,
) -> Result<crate::StreamOps<'_, M>, NoSessionError> {
    let QlFsm { state, .. } = fsm;
    let conn = state.link.connected_mut_or_err()?;
    conn.session.open_stream(header)
}

pub fn stream<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    stream_id: StreamId,
) -> Result<crate::StreamOps<'_, M>, StreamError> {
    let QlFsm { state, .. } = fsm;
    let conn = state.link.connected_mut_or_err()?;
    conn.session.stream(stream_id)
}

pub fn queue_ping<M: StreamMeta>(fsm: &mut QlFsm<M>) -> Result<(), NoSessionError> {
    let conn = fsm.state.link.connected_mut_or_err()?;
    conn.session.queue_ping()
}

pub fn poll_event<M: StreamMeta>(fsm: &mut QlFsm<M>) -> Option<Event> {
    fsm.events.pop_front()
}

pub fn emit_peer_status<M: StreamMeta>(fsm: &mut QlFsm<M>, status: crate::PeerStatus) {
    fsm.events.push_back(Event::PeerStatusChanged(status));
}
