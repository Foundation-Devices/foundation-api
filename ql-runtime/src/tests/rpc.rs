use std::time::Duration;

use bytes::{Buf, BufMut, Bytes};
use futures_lite::StreamExt;
use ql_wire::RouteId;

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
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: BytesValue = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                route_id(<Echo as ql_rpc::request::Request>::METHOD)
            );
            assert_eq!(request, BytesValue(b"hello".to_vec()));

            let mut encoded = Vec::new();
            ql_rpc::request::encode_response::<Echo>(&BytesValue(b"world".to_vec()), &mut encoded)
                .unwrap();
            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish();
        });

        let rpc = pair.handle(Side::A).rpc();
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
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: BytesValue = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                route_id(<Feed as ql_rpc::subscription::Subscription>::METHOD)
            );
            assert_eq!(request, BytesValue(b"watch".to_vec()));

            let mut encoded = Vec::new();
            ql_rpc::subscription::encode_item::<Feed>(&BytesValue(b"one".to_vec()), &mut encoded)
                .unwrap();
            ql_rpc::subscription::encode_item::<Feed>(&BytesValue(b"two".to_vec()), &mut encoded)
                .unwrap();
            ql_rpc::subscription::encode_end(&mut encoded);

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish();
        });

        let rpc = pair.handle(Side::A).rpc();
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
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: BytesValue = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                route_id(<Download as ql_rpc::request_with_progress::RequestWithProgress>::METHOD)
            );
            assert_eq!(request, BytesValue(b"logo".to_vec()));

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
            writer.finish();
        });

        let rpc = pair.handle(Side::A).rpc();
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

fn route_id(method: ql_rpc::MethodId) -> RouteId {
    RouteId(ql_wire::VarInt::from_u32(method.0))
}

async fn read_rpc_value<T>(mut reader: crate::ByteReader) -> T
where
    T: ql_rpc::RpcCodec,
    T::Error: std::fmt::Debug,
{
    let mut value_reader = ql_rpc::ValueReader::<T>::new();

    loop {
        match value_reader.advance().unwrap() {
            ql_rpc::ReadValueStep::Value(value) => return value,
            ql_rpc::ReadValueStep::NeedMore(next) => value_reader = next,
        }

        match reader.read_chunk().await.unwrap() {
            Some(chunk) => value_reader = value_reader.push(chunk),
            None => panic!("truncated rpc value"),
        }
    }
}
