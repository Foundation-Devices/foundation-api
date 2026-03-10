use std::time::Duration;

use dcbor::CBOR;

use super::*;
use crate::{
    rpc::{MethodId, RequestResponse, RpcHandle, RpcRequestHead, RpcResponseHead},
    runtime::StreamConfig,
    wire::stream::RejectCode,
    QlError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct AddOne(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
struct AddOneResponse(u64);

impl From<AddOne> for CBOR {
    fn from(value: AddOne) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for AddOne {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<AddOneResponse> for CBOR {
    fn from(value: AddOneResponse) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for AddOneResponse {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl RequestResponse for AddOne {
    const METHOD: MethodId = MethodId(1);
    type Response = AddOneResponse;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_response_round_trip() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);
        let rpc_a = RpcHandle::new(handle_a.clone());

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let request_body = CBOR::from(AddOne(41)).to_cbor_data();
            let response_body = CBOR::from(AddOneResponse(42)).to_cbor_data();
            let request_head = RpcRequestHead::try_from(CBOR::try_from_data(&stream.request_head).unwrap())
                .unwrap();
            assert_eq!(request_head.method, AddOne::METHOD);
            assert_eq!(request_head.content_length, Some(request_body.len() as u64));

            let mut response = stream
                .respond_to
                .accept(CBOR::from(RpcResponseHead::new(Some(response_body.len() as u64))).to_cbor_data())
                .unwrap();

            let request_body = read_body(stream.request).await.unwrap();
            let request = AddOne::try_from(CBOR::try_from_data(&request_body).unwrap()).unwrap();

            response
                .write_all(&CBOR::from(AddOneResponse(request.0 + 1)).to_cbor_data())
                .await
                .unwrap();
            response.finish().await.unwrap();
        });

        let response = rpc_a
            .request(AddOne(41), StreamConfig::default())
            .await
            .unwrap();
        assert_eq!(response, AddOneResponse(42));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_response_reject_propagates() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);
        let rpc_a = RpcHandle::new(handle_a.clone());

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let request_head = RpcRequestHead::try_from(CBOR::try_from_data(&stream.request_head).unwrap())
                .unwrap();
            assert_eq!(request_head.method, AddOne::METHOD);
            stream.respond_to.reject(RejectCode::UnknownRoute).unwrap();
        });

        let err = rpc_a
            .request(AddOne(1), StreamConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::rpc::RpcError::Transport(QlError::StreamRejected {
                code: RejectCode::UnknownRoute,
                ..
            })
        ));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_response_content_length_mismatch_errors() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);
        let rpc_a = RpcHandle::new(handle_a.clone());

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut response = stream
                .respond_to
                .accept(CBOR::from(RpcResponseHead::new(Some(99))).to_cbor_data())
                .unwrap();
            let _request_body = read_body(stream.request).await.unwrap();
            response
                .write_all(&CBOR::from(AddOneResponse(2)).to_cbor_data())
                .await
                .unwrap();
            response.finish().await.unwrap();
        });

        let err = rpc_a
            .request(AddOne(1), StreamConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::rpc::RpcError::ContentLengthMismatch {
                expected: 99,
                actual: 1,
            }
        ));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

async fn read_body(mut stream: crate::runtime::InboundByteStream) -> Result<Vec<u8>, QlError> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.next_chunk().await? {
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
