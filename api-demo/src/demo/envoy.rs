use bc_components::{XIDProvider, XID};
use bc_xid::XIDDocument;
use gstp::{SealedResponse, SealedResponseBehavior};
use {
    crate::{
        chapter_title,
        latency,
        paint_broadcast,
        paint_response,
        sleep,
        BluetoothChannel,
        Camera,
        Enclave,
    },
    anyhow::{anyhow, bail, Ok, Result},
    bc_components::{PublicKeyBase, Seed},
    bc_envelope::prelude::*,
    foundation_abstracted::AbstractBluetoothChannel,
    foundation_abstracted::SecureTryFrom,
    foundation_api::{
        Discovery,
        ExchangeRate,
        Sign,
        GENERATE_SEED_FUNCTION,
        PAIRING_FUNCTION,
        SHUTDOWN_FUNCTION,
        SIGN_FUNCTION,
    },
    std::{collections::HashSet, sync::Arc},
    tokio::{sync::Mutex, task::JoinHandle, time::Duration},
};
use foundation_api::QuantumLinkMessage;

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
        if let Err(e) = self._nashville().await {
            log!("❌ Error in main: {:?}", e);
        }
        log!("🏁 Finished.");
    }

    async fn _main(self: Arc<Self>) -> Result<()> {
        self.run_pairing_mode().await?;

        chapter_title("📡 Envoy enters main loop, waiting for responses via Bluetooth.");
        let event_loop = self.clone().run_event_loop();

        sleep(5.0).await;

        chapter_title("🌱 Envoy tells Passport to generate a seed.");
        let body = Expression::new(GENERATE_SEED_FUNCTION);
        let recipient = self.first_paired_device().await;
        self.bluetooth
            .send_request(&recipient, &self.enclave, body.clone(), Some(body))
            .await?;

        sleep(5.0).await;

        chapter_title("🔏 Envoy tells Passport to sign an envelope.");
        let envelope_to_sign = Envelope::new("Signed by Passport");
        let body = Expression::from(Sign::new(envelope_to_sign));
        self.bluetooth
            .send_request(&recipient, &self.enclave, body.clone(), Some(body))
            .await?;

        sleep(5.0).await;

        chapter_title("🚪 Envoy tells Passport to shut down");
        let body = Expression::new(SHUTDOWN_FUNCTION);
        self.bluetooth
            .send_request(&recipient, &self.enclave, body.clone(), Some(body))
            .await?;

        event_loop.await?;

        Ok(())
    }

    async fn _nashville(self: Arc<Self>) -> Result<()> {
        self.run_pairing_mode().await?;

        chapter_title("📡 Envoy enters main loop, waiting for responses via Bluetooth.");
        self.clone().run_event_loop();

        sleep(5.0).await;

        loop {
            chapter_title("💸 Envoy tells Passport the USD exchange rate.");
            let body: Expression = ExchangeRate::new("USD", 65432.21).encode();
            let recipient = self.first_paired_device().await;
            self.bluetooth
                .send_request(&recipient, &self.enclave, body.clone(), Some(body))
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
        stop: Arc<Mutex<bool>>,
    ) -> Result<()> {
        let response = SealedResponse::secure_try_from(envelope, &self.enclave)?;
        log!("📡 Received: {}", paint_response!(response));

        // Verify the sender is one of the paired devices
        self.check_paired_device(response.sender()).await?;

        let result = response.result()?.clone();
        let state = response
            .state()
            .cloned()
            .ok_or_else(|| anyhow!("No state found in response."))?;
        let expression = Expression::try_from(state)?;
        let function = expression.function().clone();

        if function == GENERATE_SEED_FUNCTION {
            let seed: Seed = result.extract_subject()?;
            log!("🌱 Got seed: {}", hex::encode(seed.data()));
        } else if function == SIGN_FUNCTION {
            log!("🔏 Verifying signature");
            let verified_envelope = result.verify(self.passport_xid_document().await.inception_signing_key().unwrap())?;
            let sign = Sign::try_from(expression)?;
            if verified_envelope.is_identical_to(sign.signing_subject()) {
                log!("🔏 Signature verified and contents match.");
            } else {
                bail!("Signature verification succeeded, but contents do not match.");
            }
        } else if function == SHUTDOWN_FUNCTION {
            log!("🚪 Shutting down.");
            *stop.lock().await = true;
        } else {
            bail!("Unknown function: {}", function);
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
        let discovery = Discovery::try_from(Expression::try_from(inner)?)?;
        let sender = discovery.sender();
        scanned_envelope.verify(sender.inception_signing_key().unwrap())?;

        // This is here for pairing, but we're not actually using it in this api-demo.
        // Presumably the call below would be sent to this endpoint.
        let _endpoint = discovery.bluetooth_endpoint();

        // We're using the public key from the disovery to send the pairing request, as
        // we're not paired yet. The other commands use the first paired device.
        let body = Expression::new(PAIRING_FUNCTION);
        let response = self.bluetooth
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

    async fn passport_xid_document(&self) -> XIDDocument {
        self.first_paired_device().await
    }
}
