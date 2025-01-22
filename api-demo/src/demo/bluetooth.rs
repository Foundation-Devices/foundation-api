use {
    anyhow::Result,
    async_trait::async_trait,
    foundation_abstracted::AbstractBluetoothChannel,
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
    address: [u8; 6],
    sender: Mutex<Sender<Vec<u8>>>,
    receiver: Mutex<Receiver<Vec<u8>>>,
}

impl BluetoothChannel {
    pub fn new(
        address: [u8; 6],
        sender: Sender<Vec<u8>>,
        receiver: Receiver<Vec<u8>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            address,
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver),
        })
    }
}

#[async_trait]
impl AbstractBluetoothChannel for BluetoothChannel {
    fn address(&self) -> [u8; 6] {
        self.address
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
        let address1 = [1, 2, 3, 4, 5, 6];
        let address2 = [6, 5, 4, 3, 2, 1];
        let (sender1, receiver1) = mpsc::channel(100);
        let (sender2, receiver2) = mpsc::channel(100);
        Self {
            peer1: BluetoothChannel::new(address1, sender1, receiver2),
            peer2: BluetoothChannel::new(address2, sender2, receiver1),
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
