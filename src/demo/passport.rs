use {
    super::{BluetoothChannel, Screen},
    crate::{chapter_title, latency, paint_broadcast, paint_request, Enclave},
    anyhow::{bail, Result},
    bc_components::{PublicKeyBase, Seed},
    bc_envelope::prelude::*,
    foundation_api::{
        AbstractBluetoothChannel,
        AbstractEnclave,
        Discovery,
        PairingResponse,
        PassportFirmwareVersion,
        PassportModel,
        PassportSerial,
        SecureTryFrom,
        Sign,
        GENERATE_SEED_FUNCTION,
        SHUTDOWN_FUNCTION,
        SIGN_FUNCTION,
    },
    foundation_ur::Encoder,
    std::{collections::HashSet, sync::Arc},
    tokio::{sync::Mutex, task::JoinHandle, time::Duration},
};

pub const PASSPORT_PREFIX: &str = "🛂 Passport";

macro_rules! log {
    ($($arg:tt)*) => {
        println!("{} {}", PASSPORT_PREFIX, format_args!($($arg)*));
        latency().await;
    };
}

#[derive(Debug)]
pub struct Passport {
    screen: Arc<Screen>,
    bluetooth: Arc<BluetoothChannel>,
    enclave: Enclave,
    paired_devices: Mutex<HashSet<PublicKeyBase>>,
}

impl Passport {
    pub fn new(screen: Arc<Screen>, bluetooth: Arc<BluetoothChannel>) -> Arc<Self> {
        Arc::new(Passport {
            screen,
            bluetooth,
            enclave: Enclave::new(),
            paired_devices: Mutex::new(HashSet::new()),
        })
    }

    pub fn boot(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.main().await;
        })
    }
}

impl Passport {
    async fn main(self: Arc<Self>) {
        if let Err(e) = self._main().await {
            log!("❌ Error: {:?}", e);
        }
        log!("🏁 Finished.");
    }

    async fn _main(self: Arc<Self>) -> Result<()> {
        self.run_pairing_mode().await?;

        chapter_title("📡 Passport enters main loop, waiting for requests via Bluetooth.");
        let event_loop = self.clone().run_event_loop();

        event_loop.await?;

        Ok(())
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
                    log!("💙");
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
        let request = SealedRequest::secure_try_from(envelope, &self.enclave)?;
        log!("📡 Received: {}", paint_request!(request));

        // Verify the sender is one of the paired devices
        self.check_paired_device(request.sender()).await?;

        let id = request.id().clone();
        let function = request.function().clone();
        let body = request.body().clone();
        let sender = request.sender().clone();

        if function == GENERATE_SEED_FUNCTION {
            let seed = &Seed::new();
            log!("🌱 Generated seed: {}", hex::encode(seed.data()));
            let result = Envelope::new(seed.to_cbor());
            self.bluetooth
                .send_ok_response(
                    &sender,
                    &self.enclave,
                    &id,
                    Some(result),
                    request.peer_continuation(),
                )
                .await?;
        } else if function == SIGN_FUNCTION {
            let sign = Sign::try_from(body)?;
            let signing_subject = sign.signing_subject();
            log!("🔏 Signing envelope: {}", signing_subject.format_flat());
            let result = self.enclave.sign(signing_subject);
            self.bluetooth
                .send_ok_response(
                    &sender,
                    &self.enclave,
                    &id,
                    Some(result),
                    request.peer_continuation(),
                )
                .await?;
        } else if function == SHUTDOWN_FUNCTION {
            log!("🚪 Shutdown signal received");
            self.bluetooth
                .send_ok_response(
                    &sender,
                    &self.enclave,
                    &id,
                    None,
                    request.peer_continuation(),
                )
                .await?;
            *stop.lock().await = true;
        } else {
            bail!("Unknown function: {}", function);
        }

        Ok(())
    }

    async fn check_paired_device(self: &Arc<Self>, sender: &PublicKeyBase) -> Result<()> {
        if self.paired_devices.lock().await.contains(sender) {
            Ok(())
        } else {
            bail!("Unknown device.")
        }
    }

    async fn run_pairing_mode(self: &Arc<Self>) -> Result<()> {
        let discovery =
            Discovery::new(self.public_key().clone(), self.bluetooth.endpoint().clone());
        let envelope = self
            .enclave
            .sign(&discovery.into_expression().into_envelope());

        // Show the QR code, but clear the screen no matter how we exit this function
        let _screen_guard = self.screen().show_envelope(&envelope);
        log!(
            "📺 Discovery envelope: {}",
            paint_broadcast!(envelope.format_flat())
        );

        let mut encoder = Encoder::new();
        let envelope_data = envelope.tagged_cbor_data();
        encoder.start("discovery", &*envelope_data, 50);

        for _ in 0..10 {
            let part = encoder.next_part();
            let qr = part.to_string();
            log!(
                "📺 Displaying discovery QR code(s): {}",
                paint_broadcast!(qr)
            );
        }

        log!("🤝 Waiting for pairing request");
        let received_envelope = self
            .bluetooth
            .receive_envelope(Duration::from_secs(10))
            .await?;
        let request = SealedRequest::secure_try_from(received_envelope, &self.enclave)?;
        log!("🤝 Received: {}", paint_request!(request));
        match self.add_paired_device(request.sender()).await {
            Ok(_) => {
                let response = Envelope::new(
                    PairingResponse {
                        passport_model: PassportModel::Prime,
                        passport_serial: PassportSerial("1234-5678".to_owned()),
                        passport_firmware_version: PassportFirmwareVersion("1.0.0".to_owned()),
                    }
                    .tagged_cbor(),
                );

                self.bluetooth
                    .send_ok_response(
                        request.sender(),
                        &self.enclave,
                        request.id(),
                        Some(response.into()),
                        request.peer_continuation(),
                    )
                    .await?;
            }
            Err(e) => {
                self.bluetooth
                    .send_error_response(
                        request.sender(),
                        &self.enclave,
                        request.id(),
                        &e.to_string(),
                        request.peer_continuation(),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    async fn add_paired_device(self: &Arc<Self>, paired_device_key: &PublicKeyBase) -> Result<()> {
        // If `paired_devices` contains the key, do nothing (idempotent operation)
        if self.paired_devices.lock().await.contains(paired_device_key) {
            log!("🤝 Already paired to that device.");
        } else {
            // If the key is different, store it.
            self.paired_devices
                .lock()
                .await
                .insert(paired_device_key.clone());
            log!("🤝 Successfully paired.");
        }

        Ok(())
    }
}

// Internal methods
impl Passport {
    fn screen(&self) -> Arc<Screen> {
        self.screen.clone()
    }

    fn public_key(&self) -> &PublicKeyBase {
        self.enclave.public_key()
    }
}
