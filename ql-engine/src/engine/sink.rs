use bc_components::XID;

use crate::{engine::PeerSession, wire::stream::BodyChunk, Peer, QlError, StreamId};

pub trait EngineEventSink {
    fn peer_status_changed(&mut self, peer: XID, session: PeerSession);

    fn persist_peer(&mut self, peer: Peer);

    fn clear_peer(&mut self);

    fn inbound_stream_opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    );

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>);

    fn inbound_finished(&mut self, stream_id: StreamId);

    fn inbound_failed(&mut self, stream_id: StreamId, error: QlError);

    fn outbound_closed(&mut self, stream_id: StreamId);

    fn outbound_failed(&mut self, stream_id: StreamId, error: QlError);

    fn stream_reaped(&mut self, stream_id: StreamId);
}

impl EngineEventSink for () {
    fn peer_status_changed(&mut self, _peer: XID, _session: PeerSession) {}

    fn persist_peer(&mut self, _peer: Peer) {}

    fn clear_peer(&mut self) {}

    fn inbound_stream_opened(
        &mut self,
        _stream_id: StreamId,
        _request_head: Vec<u8>,
        _request_prefix: Option<BodyChunk>,
    ) {
    }

    fn inbound_data(&mut self, _stream_id: StreamId, _bytes: Vec<u8>) {}

    fn inbound_finished(&mut self, _stream_id: StreamId) {}

    fn inbound_failed(&mut self, _stream_id: StreamId, _error: QlError) {}

    fn outbound_closed(&mut self, _stream_id: StreamId) {}

    fn outbound_failed(&mut self, _stream_id: StreamId, _error: QlError) {}

    fn stream_reaped(&mut self, _stream_id: StreamId) {}
}
