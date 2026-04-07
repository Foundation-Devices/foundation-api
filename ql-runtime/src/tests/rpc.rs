use std::time::Duration;

use bytes::{Buf, BufMut, Bytes};
use futures_lite::StreamExt;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BytesValue(Vec<u8>);

impl ql_rpc::RpcCodec for BytesValue {
    type Error = core::convert::Infallible;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) -> Result<(), Self::Error> {
        out.put_slice(&self.0);
        Ok(())
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        Ok(Self(bytes.copy_to_bytes(bytes.remaining()).to_vec()))
    }
}

struct Echo;

impl ql_rpc::request::Request for Echo {
    const METHOD: ql_rpc::MethodId = ql_rpc::MethodId(51);
    type Error = core::convert::Infallible;
    type Request = BytesValue;
    type Response = BytesValue;
}

struct Feed;

impl ql_rpc::subscription::Subscription for Feed {
    const METHOD: ql_rpc::MethodId = ql_rpc::MethodId(52);
    type Error = core::convert::Infallible;
    type Request = BytesValue;
    type Event = BytesValue;
}

struct Download;

impl ql_rpc::request_with_progress::RequestWithProgress for Download {
    const METHOD: ql_rpc::MethodId = ql_rpc::MethodId(53);
    type Error = core::convert::Infallible;
    type Request = BytesValue;
    type Progress = BytesValue;
    type Response = BytesValue;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_round_trips() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request = read_all(inbound.reader).await.unwrap();
            let mut body = request.as_slice();
            let header =
                <ql_rpc::header::RpcHeader as ql_rpc::RpcCodec>::decode_value(&mut body).unwrap();
            assert_eq!(header.method, <Echo as ql_rpc::request::Request>::METHOD);
            assert_eq!(
                ql_rpc::request::decode_request::<Echo>(body).unwrap(),
                BytesValue(b"hello".to_vec())
            );

            let mut encoded = Vec::new();
            ql_rpc::request::encode_response::<Echo>(&BytesValue(b"world".to_vec()), &mut encoded)
                .unwrap();
            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish().await.unwrap();
        });

        let rpc = handle_a.rpc();
        let response = rpc
            .request::<Echo>(&BytesValue(b"hello".to_vec()))
            .await
            .unwrap();
        assert_eq!(response, BytesValue(b"world".to_vec()));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_subscription_streams_events() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request = read_all(inbound.reader).await.unwrap();
            let mut body = request.as_slice();
            let header =
                <ql_rpc::header::RpcHeader as ql_rpc::RpcCodec>::decode_value(&mut body).unwrap();
            assert_eq!(
                header.method,
                <Feed as ql_rpc::subscription::Subscription>::METHOD
            );
            assert_eq!(
                ql_rpc::subscription::decode_request::<Feed>(body).unwrap(),
                BytesValue(b"watch".to_vec())
            );

            let mut encoded = Vec::new();
            ql_rpc::subscription::encode_item::<Feed>(&BytesValue(b"one".to_vec()), &mut encoded)
                .unwrap();
            ql_rpc::subscription::encode_item::<Feed>(&BytesValue(b"two".to_vec()), &mut encoded)
                .unwrap();
            ql_rpc::subscription::encode_end(&mut encoded);

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish().await.unwrap();
        });

        let rpc = handle_a.rpc();
        let mut subscription = rpc
            .subscribe::<Feed>(&BytesValue(b"watch".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            subscription.next().await.unwrap().unwrap(),
            BytesValue(b"one".to_vec())
        );
        assert_eq!(
            subscription.next().await.unwrap().unwrap(),
            BytesValue(b"two".to_vec())
        );
        assert!(subscription.next().await.is_none());

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_with_progress_supports_progress_then_await() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request = read_all(inbound.reader).await.unwrap();
            let mut body = request.as_slice();
            let header =
                <ql_rpc::header::RpcHeader as ql_rpc::RpcCodec>::decode_value(&mut body).unwrap();
            assert_eq!(
                header.method,
                <Download as ql_rpc::request_with_progress::RequestWithProgress>::METHOD
            );
            assert_eq!(
                ql_rpc::request_with_progress::decode_request::<Download>(body).unwrap(),
                BytesValue(b"logo".to_vec())
            );

            let mut encoded = Vec::new();
            ql_rpc::request_with_progress::encode_progress::<Download>(
                &BytesValue(b"10".to_vec()),
                &mut encoded,
            )
            .unwrap();
            ql_rpc::request_with_progress::encode_progress::<Download>(
                &BytesValue(b"90".to_vec()),
                &mut encoded,
            )
            .unwrap();
            ql_rpc::request_with_progress::encode_response::<Download>(
                &BytesValue(b"done".to_vec()),
                &mut encoded,
            )
            .unwrap();

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish().await.unwrap();
        });

        let rpc = handle_a.rpc();
        let mut download = rpc
            .request_with_progress::<Download>(&BytesValue(b"logo".to_vec()))
            .await
            .unwrap();

        assert_eq!(download.progress().await, Some(BytesValue(b"10".to_vec())));
        assert_eq!(download.progress().await, Some(BytesValue(b"90".to_vec())));
        assert_eq!(download.progress().await, None);
        assert_eq!(download.await.unwrap(), BytesValue(b"done".to_vec()));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
