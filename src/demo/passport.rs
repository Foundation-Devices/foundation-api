use std::{collections::HashSet, sync::Arc};

use bc_components::{PublicKeyBase, Seed, ARID};
use bc_envelope::prelude::*;
use tokio::{sync::Mutex, task::JoinHandle, time::Duration};

use foundation_api::{
    Discovery, Pairing, Sign, GENERATE_SEED_FUNCTION,
    SHUTDOWN_FUNCTION, SIGN_FUNCTION,
};

use crate::{
    chapter_title, latency, DemoEnclave, Enclave, EnclaveEnvelope
};

use super::{sleep, BluetoothChannel, Screen};

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
    enclave: DemoEnclave,
    paired_devices: Mutex<HashSet<PublicKeyBase>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PassportError {
    #[error("Unexpected request ID")]
    UnexpectedRequestID,
    #[error("Unknown device")]
    UnknownDevice,
    #[error("Unknown function")]
    UnknownFunction,
    #[error("Shutdown signal received")]
    ShutdownSignal,
}

impl Passport {
    pub fn new(screen: Arc<Screen>, bluetooth: Arc<BluetoothChannel>) -> Arc<Self> {
        Arc::new(Passport {
            screen,
            bluetooth,
            enclave: DemoEnclave::new(),
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

    async fn _main(self: Arc<Self>) -> anyhow::Result<()> {
        self.run_pairing_mode().await?;
        self.run_main_loop().await?;
        Ok(())
    }

    async fn run_main_loop(self: &Arc<Self>) -> anyhow::Result<()> {
        chapter_title("📡 Passport enters main loop, waiting for requests via Bluetooth.");
        loop {
            match self.handle_next_request().await {
                Ok(_) => {}
                Err(e) => {
                    if e.downcast_ref::<PassportError>()
                        .map_or(false, |e| e == &PassportError::ShutdownSignal)
                    {
                        log!("🚪 Shutting down…");
                        return Ok(());
                    } else {
                        log!("❌ Error: {:?}", e);
                        let error_message = e.to_string();
                        let response =
                            error_message.to_envelope()
                            .into_failure_response(None)
                            .sign_with_enclave(&self.enclave);
                        // If error within error, just log a message
                        if let Err(e) = self.bluetooth.send_envelope(&response).await {
                            log!("❌ Error sending error response: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    async fn handle_next_request(self: &Arc<Self>) -> anyhow::Result<()> {
        log!("📡 Waiting for next request…");

        let (id, sender, body, function) =
            self.bluetooth.receive_envelope(Duration::from_secs(10)).await?
            .decrypt_with_enclave(&self.enclave)?
            .parse_signed_transaction_request(None)?;

        // Verify the sender is one of the paired devices
        self.check_paired_device(&sender).await?;

        log!("📡 Received request: {}", function);

        let mut shutdown = false;

        if function == SIGN_FUNCTION {
            let request = Sign::from_body(&id, &sender, &body)?;
            let signing_subject = request.signing_subject();
            log!("🔏 Signing…");
            let result = self.enclave.sign(signing_subject);
            log!("🔏 Sending response…");
            self.send_ok_response(&id, Some(result), &sender).await?;
        } else if function == GENERATE_SEED_FUNCTION {
            log!("🌱 Generating seed…");
            let seed = &Seed::new();
            log!("🌱 Sending seed: {}…", hex::encode(seed.data()));
            let result = Envelope::new(seed.to_cbor());
            self.send_ok_response(&id, Some(result), &sender).await?;
        } else if function == SHUTDOWN_FUNCTION {
            log!("🚪 Shutdown signal received, sending response…");
            self.send_ok_response(&id, None, &sender).await?;
            shutdown = true;
        } else {
            return Err(PassportError::UnknownFunction.into());
        }

        if shutdown {
            Err(PassportError::ShutdownSignal.into())
        } else {
            Ok(())
        }
    }

    async fn check_paired_device(self: &Arc<Self>, sender: &PublicKeyBase) -> anyhow::Result<()> {
        if self.paired_devices.lock().await.contains(sender) {
            Ok(())
        } else {
            Err(PassportError::UnknownDevice.into())
        }
    }

    async fn run_pairing_mode(self: &Arc<Self>) -> anyhow::Result<()> {
        let pairing = self.receive_pairing_request().await?;
        match self.add_paired_device(pairing.key()).await {
            Ok(_) => {
                self.send_ok_response(pairing.id(), Some(pairing.to_envelope()), pairing.key()).await?;
            }
            Err(e) => {
                self.send_error_response(pairing.id(), &e.to_string(), pairing.key()).await?;
            }
        }

        Ok(())
    }

    async fn receive_pairing_request(self: &Arc<Self>) -> anyhow::Result<Pairing> {
        let discovery_id = ARID::new();
        let discovery = Discovery::new(&discovery_id, self.public_key(), self.bluetooth.endpoint())
            .into_envelope()
            .sign_with_enclave(&self.enclave);

        // Show the QR code, but clear the screen no matter how we exit this function
        let _screen_guard = self.screen().show_envelope(&discovery).await;
        log!("📺 Displaying discovery QR code…");

        log!("🤝 Waiting for pairing request…");
        let pairing: Pairing = self.bluetooth
            .receive_envelope(Duration::from_secs(10)).await?
            .decrypt_with_enclave(&self.enclave)?
            .try_into()?;

        // Ensure the request ID matches the discovery ID
        if pairing.id() != &discovery_id {
            return Err(PassportError::UnexpectedRequestID.into());
        }

        Ok(pairing)
    }

    async fn add_paired_device(
        self: &Arc<Self>,
        paired_device_key: &PublicKeyBase,
    ) -> anyhow::Result<()> {
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
        id: &ARID,
        result: Option<Envelope>,
        recipient: &PublicKeyBase,
    ) -> anyhow::Result<()> {
        let response = Envelope::new_success_response(id, result);
        self.send_response(response, recipient).await
    }

    async fn send_error_response(
        self: &Arc<Self>,
        id: &ARID,
        error: &str,
        recipient: &PublicKeyBase,
    ) -> anyhow::Result<()> {
        let response = error.to_envelope().into_failure_response(Some(id));
        self.send_response(response, recipient).await
    }

    async fn send_response(
        self: &Arc<Self>,
        response: Envelope,
        recipient: &PublicKeyBase,
    ) -> anyhow::Result<()> {
        let sealed_response = response.seal_with_enclave(&self.enclave, recipient);
        self.bluetooth.send_envelope(&sealed_response).await
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

    #[allow(dead_code)]
    async fn pause_for_seconds(&self, message: &str, seconds: i32) {
        for t in (1..=seconds).rev() {
            log!("{} {}…", message, t);
            sleep(1.0).await;
        }
    }
}
