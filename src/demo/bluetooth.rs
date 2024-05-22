use std::sync::Arc;
use bytes::Bytes;
use foundation_api::BluetoothEndpoint;
use tokio::{
    sync::{Mutex, mpsc::{self, Sender, Receiver}},
    time::{self, Duration}
};
use bc_envelope::prelude::*;
use anyhow::Result;

#[derive(Debug)]
pub struct BluetoothChannel {
    endpoint: BluetoothEndpoint,
    sender: Mutex<Sender<Bytes>>,
    receiver: Mutex<Receiver<Bytes>>,
}

impl BluetoothChannel {
    pub fn new(endpoint: BluetoothEndpoint, sender: Sender<Bytes>, receiver: Receiver<Bytes>) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver),
        })
    }

    pub fn endpoint(&self) -> &BluetoothEndpoint {
        &self.endpoint
    }

    pub async fn send_envelope(&self, envelope: &Envelope) -> Result<()> {
        self.send(envelope.to_cbor_data()).await
    }

    pub async fn send(&self, message: impl Into<Bytes>) -> Result<()> {
        let sender = self.sender.lock().await;
        sender.send(message.into()).await.map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn receive_envelope(&self, timeout: Duration) -> Result<Envelope> {
        let bytes = self.receive(timeout).await?;
        Envelope::try_from_cbor_data(bytes)
    }

    pub async fn receive(&self, timeout: Duration) -> Result<Bytes> {
        let mut receiver = self.receiver.lock().await;
        Ok(
            time::timeout(timeout, receiver.recv())
            .await?
            .unwrap()
        )
    }
}

#[derive(Debug)]
pub struct BluetoothPeers {
    peer1: Arc<BluetoothChannel>,
    peer2: Arc<BluetoothChannel>,
}

impl BluetoothPeers {
    pub fn new() -> Self {
        let endpoint1 = BluetoothEndpoint::new();
        let endpoint2 = endpoint1.clone();
        let (sender1, receiver1) = mpsc::channel(100);
        let (sender2, receiver2) = mpsc::channel(100);
        Self {
            peer1: BluetoothChannel::new(endpoint1, sender1, receiver2),
            peer2: BluetoothChannel::new(endpoint2, sender2, receiver1),
        }
    }

    pub fn peer1(&self) -> &Arc<BluetoothChannel> {
        &self.peer1
    }

    pub fn peer2(&self) -> &Arc<BluetoothChannel> {
        &self.peer2
    }
}

impl Default for BluetoothPeers {
    fn default() -> Self {
        Self::new()
    }
}
