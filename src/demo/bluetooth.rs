use {
    anyhow::Result,
    async_trait::async_trait,
    foundation_api::{AbstractBluetoothChannel, BluetoothEndpoint},
    std::sync::Arc,
    tokio::{
        sync::{
            mpsc::{self, Receiver, Sender},
            Mutex,
        },
        time::{self, Duration},
    },
};

#[derive(Debug)]
pub struct BluetoothChannel {
    endpoint: BluetoothEndpoint,
    sender: Mutex<Sender<Vec<u8>>>,
    receiver: Mutex<Receiver<Vec<u8>>>,
}

impl BluetoothChannel {
    pub fn new(
        endpoint: BluetoothEndpoint,
        sender: Sender<Vec<u8>>,
        receiver: Receiver<Vec<u8>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver),
        })
    }
}

#[async_trait]
impl AbstractBluetoothChannel for BluetoothChannel {
    fn endpoint(&self) -> &BluetoothEndpoint {
        &self.endpoint
    }

    async fn send(&self, message: impl Into<Vec<u8>> + std::marker::Send) -> Result<()> {
        let sender = self.sender.lock().await;
        sender
            .send(message.into())
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
        let mut receiver = self.receiver.lock().await;
        Ok(time::timeout(timeout, receiver.recv()).await?.unwrap())
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
