use bc_xid::XIDDocument;
use foundation_api::api::discovery::Discovery;
use foundation_api::api::quantum_link::QUANTUM_LINK;
use foundation_api::quantum_link::QuantumLink;

use foundation_api::api::message::QuantumLinkMessage;
use foundation_api::fx::ExchangeRate;
use foundation_api::message::{EnvoyMessage, PassportMessage};
use foundation_api::pairing::PairingRequest;
use gstp::{SealedResponse, SealedResponseBehavior};
use {
    crate::{
        chapter_title, latency, paint_broadcast, paint_response, sleep, BluetoothChannel, Camera,
        Enclave,
    },
    anyhow::{anyhow, bail, Ok, Result},
    bc_envelope::prelude::*,
    foundation_abstracted::AbstractBluetoothChannel,
    foundation_abstracted::SecureTryFrom,
    std::sync::Arc,
    tokio::{sync::Mutex, task::JoinHandle, time::Duration},
};

pub const ENVOY_PREFIX: &str = "🔶 Envoy   ";

macro_rules! log {
    ($($arg:tt)*) => {
        println!("{} {}", ENVOY_PREFIX, format_args!($($arg)*));
        latency().await;
    };
}

#[derive(Debug)]
pub struct Envoy {
    bluetooth: Arc<BluetoothChannel>,
    camera: Arc<Camera>,
    enclave: Enclave,
    paired_devices: Mutex<Vec<XIDDocument>>,
}

impl Envoy {
    pub fn new(camera: Arc<Camera>, bluetooth: Arc<BluetoothChannel>) -> Arc<Self> {
        Arc::new(Envoy {
            camera,
            bluetooth,
            enclave: Enclave::new(),
            paired_devices: Mutex::new(Vec::new()),
        })
    }

    pub fn boot(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.main().await;
        })
    }
}

impl Envoy {
    async fn main(self: Arc<Self>) {
        if let Err(e) = self._main().await {
            log!("❌ Error in main: {:?}", e);
        }
        log!("🏁 Finished.");
    }

    async fn _main(self: Arc<Self>) -> Result<()> {
        self.run_pairing_mode().await?;

        chapter_title("📡 Envoy enters main loop, waiting for responses via Bluetooth.");
        self.clone().run_event_loop();

        sleep(5.0).await;

        loop {
            chapter_title("💸 Envoy tells Passport the USD exchange rate.");
            let msg = EnvoyMessage::new(
                QuantumLinkMessage::ExchangeRate(ExchangeRate::new("USD", 65432.21)),
                12345,
            );

            let body: Expression = msg.encode();
            let recipient = self.first_paired_device().await;
            let state: Option<Expression> = None;
            self.bluetooth
                .send_request(&recipient, &self.enclave, body.clone(), state)
                .await?;

            sleep(5.0).await;
        }
    }

    fn run_event_loop(self: Arc<Self>) -> JoinHandle<()> {
        let stop = Arc::new(Mutex::new(false));
        tokio::spawn(async move {
            loop {
                let received_envelope = self
                    .bluetooth
                    .receive_envelope(Duration::from_secs(1))
                    .await
                    .ok();
                if let Some(envelope) = received_envelope {
                    let handle_event_result = self.handle_event(envelope, stop.clone()).await;
                    if let Err(e) = handle_event_result {
                        log!("❌ Error in event: {:?}", e);
                    }
                } else {
                    log!("🧡");
                }

                if *stop.lock().await {
                    break;
                }
            }
        })
    }

    async fn handle_event(
        self: &Arc<Self>,
        envelope: Envelope,
        _stop: Arc<Mutex<bool>>,
    ) -> Result<()> {

        // TODO: Need code here to determine if it's a SealedResponse, SealedRequest or Event
        let response = SealedResponse::secure_try_from(envelope, &self.enclave)?;
        log!("📡 Received: {}", paint_response!(response));

        // Verify the sender is one of the paired devices
        self.check_paired_device(response.sender()).await?;

        let _result = response.result()?.clone();
        let state = response
            .state()
            .cloned()
            .ok_or_else(|| anyhow!("No state found in response."))?;
        let expression = Expression::try_from(state)?;
        let function = expression.function().clone();

        if function != QUANTUM_LINK {
            bail!("Unknown function: {}", function);
        }

        let decoded = PassportMessage::decode(&expression)?;

        match decoded.message() {
            QuantumLinkMessage::ExchangeRate(_) => {
                println!("Received ExchangeRate message");
            }
            QuantumLinkMessage::FirmwareUpdate(_) => {}
            QuantumLinkMessage::DeviceStatus(_) => {}
            QuantumLinkMessage::EnvoyStatus(_) => {}
            QuantumLinkMessage::PairingResponse(_) => {}
            QuantumLinkMessage::PairingRequest(_) => {}
            QuantumLinkMessage::OnboardingState(_) => {},
            &QuantumLinkMessage::SignPsbt(_) | &QuantumLinkMessage::SyncUpdate(_) => todo!()
        }

        Ok(())
    }
}

impl Envoy {
    async fn check_paired_device(self: &Arc<Self>, sender: &XIDDocument) -> Result<()> {
        if self.paired_devices.lock().await.contains(&sender) {
            Ok(())
        } else {
            bail!("Unknown device.")
        }
    }

    async fn run_pairing_mode(self: &Arc<Self>) -> Result<()> {
        log!("📷 Scanning for discovery QR code");
        let scanned_envelope = self.camera.scan_envelope(Duration::from_secs(10)).await?;
        log!(
            "📷 Scanned discovery QR code: {}",
            paint_broadcast!(scanned_envelope.format_flat())
        );
        let inner = scanned_envelope.unwrap_envelope()?;
        register_tags();
        let expression = Expression::try_from(inner)?;

        let discovery = Discovery::try_from(expression)?;
        let sender = discovery.sender();
        scanned_envelope.verify(sender.inception_signing_key().unwrap())?;

        // We're using the public key from the disovery to send the pairing request, as
        // we're not paired yet. The other commands use the first paired device.
        let body = QuantumLinkMessage::PairingRequest(PairingRequest { xid_document: vec![] }).encode();
        let response = self
            .bluetooth
            .call(sender, &self.enclave, body.clone(), Some(body))
            .await?;
        let bluetooth_sender = response.sender();

        self.add_paired_device(&bluetooth_sender).await;

        Ok(())
    }

    async fn add_paired_device(self: &Arc<Self>, paired_device_xid: &XIDDocument) {
        // If `paired_devices` contains the key, do nothing (idempotent operation)
        if self.paired_devices.lock().await.contains(paired_device_xid) {
            log!("🤝 Already paired to that device.");
        } else {
            // If the key is different, store it.
            self.paired_devices
                .lock()
                .await
                .push(paired_device_xid.clone());
            log!("🤝 Successfully paired.");
        }
    }
}

// Internal methods
impl Envoy {
    async fn first_paired_device(&self) -> XIDDocument {
        self.paired_devices
            .lock()
            .await
            .iter()
            .next()
            .unwrap()
            .clone()
    }

    async fn _passport_xid_document(&self) -> XIDDocument {
        self.first_paired_device().await
    }
}
