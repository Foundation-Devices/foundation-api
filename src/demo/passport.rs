use std::{collections::HashSet, sync::Arc};

use anyhow::{bail, Result};
use bc_components::{PublicKeyBase, Seed, ARID};
use bc_envelope::prelude::*;
use tokio::{sync::Mutex, task::JoinHandle, time::Duration};

use foundation_api::{
    Discovery, Sign, GENERATE_SEED_FUNCTION,
    SHUTDOWN_FUNCTION, SIGN_FUNCTION,
};

use crate::{chapter_title, latency, paint_broadcast, paint_request, paint_response, Enclave, SecureTryFrom};

use super::{BluetoothChannel, Screen};

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
                let received_envelope = self.bluetooth.receive_envelope(Duration::from_secs(1)).await.ok();
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

    async fn handle_event(self: &Arc<Self>, envelope: Envelope, stop: Arc<Mutex<bool>>) -> Result<()> {
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
            self.send_ok_response("🌱", &id, Some(result), request.peer_continuation(), &sender).await?;
        } else if function == SIGN_FUNCTION {
            let sign = Sign::try_from(body)?;
            let signing_subject = sign.signing_subject();
            log!("🔏 Signing envelope: {}", signing_subject.format_flat());
            let result = self.enclave.sign(signing_subject);
            self.send_ok_response("🔏", &id, Some(result), request.peer_continuation(), &sender).await?;
        } else if function == SHUTDOWN_FUNCTION {
            log!("🚪 Shutdown signal received");
            self.send_ok_response("🚪", &id, None, request.peer_continuation(), &sender).await?;
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
        let discovery = Discovery::new(self.public_key().clone(), self.bluetooth.endpoint().clone());
        let envelope = self.enclave.sign(&discovery.into_expression().into_envelope());

        // Show the QR code, but clear the screen no matter how we exit this function
        let _screen_guard = self.screen().show_envelope(&envelope);
        log!("📺 Displaying discovery QR code: {}", paint_broadcast!(envelope.format_flat()));

        log!("🤝 Waiting for pairing request");
        let received_envelope = self.bluetooth.receive_envelope(Duration::from_secs(10)).await?;
        let request = SealedRequest::secure_try_from(received_envelope, &self.enclave)?;
        log!("🤝 Received: {}", paint_request!(request));
        match self.add_paired_device(request.sender()).await {
            Ok(_) => {
                self.send_ok_response("🤝", request.id(), Some(Envelope::ok()), request.peer_continuation(), request.sender()).await?;
            }
            Err(e) => {
                self.send_error_response("🤝", request.id(), &e.to_string(), request.peer_continuation(), request.sender()).await?;
            }
        }

        Ok(())
    }

    async fn add_paired_device(
        self: &Arc<Self>,
        paired_device_key: &PublicKeyBase,
    ) -> Result<()> {
        // If `paired_devices` contains the key, do nothing (idempotent operation)
        if self.paired_devices.lock().await.contains(paired_device_key) {
            log!("🤝 Already paired to that device.");
        } else {
            // If the key is different, store it.
            self.paired_devices.lock().await
                .insert(paired_device_key.clone());
            log!("🤝 Successfully paired.");
        }

        Ok(())
    }

    async fn send_ok_response(
        self: &Arc<Self>,
        log_prefix: &str,
        id: &ARID,
        result: Option<Envelope>,
        peer_continuation: Option<&Envelope>,
        recipient: &PublicKeyBase,
    ) -> Result<()> {
        let response = SealedResponse::new_success(id, self.public_key())
            .with_optional_result(result)
            .with_peer_continuation(peer_continuation);
        self.send_response(log_prefix, response, recipient).await
    }

    async fn send_error_response(
        self: &Arc<Self>,
        log_prefix: &str,
        id: &ARID,
        error: &str,
        peer_continuation: Option<&Envelope>,
        recipient: &PublicKeyBase,
    ) -> Result<()> {
        let response = SealedResponse::new_failure(id, self.public_key())
            .with_error(error)
            .with_peer_continuation(peer_continuation);
        self.send_response(log_prefix, response, recipient).await
    }

    async fn send_response(
        self: &Arc<Self>,
        log_prefix: &str,
        response: SealedResponse,
        recipient: &PublicKeyBase,
    ) -> Result<()> {
        log!("{} Sending: {}", log_prefix, paint_response!(response));
        let envelope = self.enclave.seal(&Envelope::from(response), recipient);
        self.bluetooth.send_envelope(&envelope).await
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
