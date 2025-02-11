use bc_xid::XIDDocument;
use foundation_api::api::passport::{PassportFirmwareVersion, PassportSerial};
use foundation_api::pairing::PairingResponse;
use foundation_api::passport::PassportModel;
use foundation_api::QuantumLinkMessage;
use foundation_api::QUANTUM_LINK;
use gstp::SealedRequest;
use gstp::SealedRequestBehavior;
use {
    super::{BluetoothChannel, Screen},
    crate::{chapter_title, latency, paint_broadcast, paint_request, Enclave},
    anyhow::{bail, Result},
    bc_envelope::prelude::*,
    foundation_abstracted::AbstractBluetoothChannel,
    foundation_abstracted::AbstractEnclave,
    foundation_abstracted::SecureTryFrom,
    foundation_api::api::discovery::Discovery,
    foundation_ur::Encoder,
    std::sync::Arc,
    tokio::{sync::Mutex, task::JoinHandle, time::Duration},
};
use foundation_api::messages::QuantumLinkMessages;

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
    paired_devices: Mutex<Vec<XIDDocument>>,
}

impl Passport {
    pub fn new(screen: Arc<Screen>, bluetooth: Arc<BluetoothChannel>) -> Arc<Self> {
        Arc::new(Passport {
            screen,
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
        _stop: Arc<Mutex<bool>>,
    ) -> Result<()> {
        let request = SealedRequest::secure_try_from(envelope, &self.enclave)?;
        log!("📡 Received: {}", paint_request!(request));

        // Verify the sender is one of the paired devices
        self.check_paired_device(&request.sender()).await?;

        let _id = request.id().clone();
        let function = request.function().clone();
        let _body = request.body().clone();
        let _sender = request.sender().clone();

        if function != QUANTUM_LINK {
            bail!("Unknown function: {}", function);
        }

        let message = QuantumLinkMessages::decode(&request.body())?;

        match message {
            QuantumLinkMessages::ExchangeRate(_) => {
                println!("Received ExchangeRate message");
            }
            QuantumLinkMessages::FirmwareUpdate(_) => {}
            QuantumLinkMessages::DeviceStatus(_) => {}
            QuantumLinkMessages::EnvoyStatus(_) => {}
            QuantumLinkMessages::PairingResponse(_) => {}
            QuantumLinkMessages::PairingRequest(_) => {}
        }

        Ok(())
    }

    async fn check_paired_device(self: &Arc<Self>, sender: &XIDDocument) -> Result<()> {
        if self.paired_devices.lock().await.contains(sender) {
            Ok(())
        } else {
            bail!("Unknown device.")
        }
    }

    async fn run_pairing_mode(self: &Arc<Self>) -> Result<()> {
        let xid_document = self.xid_document().clone();
        let discovery = Discovery::new(xid_document, self.bluetooth.address().clone());

        let envelope = self
            .enclave
            .sign(&discovery.into_expression().into_envelope());

        register_tags();

        // Show the QR code, but clear the screen no matter how we exit this function
        let _screen_guard = self.screen().show_envelope(&envelope);
        log!(
            "📺 Discovery envelope: {}",
            paint_broadcast!(envelope.format_flat())
        );

        let mut encoder = Encoder::new();
        let envelope_data = envelope.tagged_cbor_data();
        encoder.start("discovery", &*envelope_data, 300);

        // for _ in 0..10 {
        //     let part = encoder.next_part();
        //     let qr = part.to_string();
        //     log!(
        //         "📺 Displaying discovery QR code(s): {}",
        //         paint_broadcast!(qr)
        //     );
        // }

        log!("🤝 Waiting for pairing request");

        let received_envelope = self
            .bluetooth
            .receive_envelope(Duration::from_secs(10))
            .await?;

        let request = SealedRequest::secure_try_from(received_envelope, &self.enclave)?;
        log!("🤝 Received: {}", paint_request!(request));
        match self.add_paired_device(&request.sender()).await {
            Ok(_) => {
                let response = Envelope::new(
                    QuantumLinkMessages::PairingResponse(
                    PairingResponse {
                        passport_model: PassportModel::Prime,
                        passport_serial: PassportSerial("1234-5678".to_owned()),
                        passport_firmware_version: PassportFirmwareVersion("1.0.0".to_owned()),
                        descriptor: "bv12312321".to_owned(),
                    })
                    .encode(),
                );

                self.bluetooth
                    .send_ok_response(
                        request.sender(),
                        &self.enclave,
                        request.id(),
                        Some(response),
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

    async fn add_paired_device(
        self: &Arc<Self>,
        paired_device_xid_document: &XIDDocument,
    ) -> Result<()> {
        // If `paired_devices` contains the key, do nothing (idempotent operation)
        if self
            .paired_devices
            .lock()
            .await
            .contains(paired_device_xid_document)
        {
            log!("🤝 Already paired to that device.");
        } else {
            // If the key is different, store it.
            self.paired_devices
                .lock()
                .await
                .push(paired_device_xid_document.clone());
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

    fn xid_document(&self) -> &XIDDocument {
        self.enclave.xid_document()
    }
}
