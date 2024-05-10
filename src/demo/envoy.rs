use std::{sync::Arc, collections::HashSet};

use anyhow::bail;
use bc_components::{PublicKeyBase, Seed, ARID};
use bc_envelope::prelude::*;
use tokio::{sync::Mutex, task::JoinHandle, time::Duration};

use foundation_api::{Discovery, Pairing, Sign, GENERATE_SEED_FUNCTION, SHUTDOWN_FUNCTION};
use crate::{chapter_title, latency, sleep, BluetoothChannel, Camera, DemoEnclave, Enclave, EnclaveEnvelope};

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
    enclave: DemoEnclave,
    paired_devices: Mutex<HashSet<PublicKeyBase>>,
}

impl Envoy {
    pub fn new(camera: Arc<Camera>, bluetooth: Arc<BluetoothChannel>) -> Arc<Self> {
        Arc::new(Envoy {
            camera,
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

impl Envoy {
    async fn main(self: Arc<Self>) {
        if let Err(e) = self._main().await {
            log!("❌ Error: {:?}", e);
        }
        log!("🏁 Finished.");
    }

    async fn _main(self: Arc<Self>) -> anyhow::Result<()> {
        self.run_pairing_mode().await?;

        chapter_title("🌱 Envoy tells Passport to generate a seed.");
        let seed = self.generate_seed().await?;
        log!("🌱 Got seed: {}", hex::encode(seed.data()));

        chapter_title("🔏 Envoy tells Passport to sign an envelope.");
        let envelope_to_sign = Envelope::new("Signed by Passport");
        let signed_envelope = self.sign_envelope(&envelope_to_sign).await?;
        log!("🔏 Verifying signature…");
        let passport_key = self.first_paired_device().await;
        let verified_envelope = signed_envelope.verify(&passport_key)?;
        if verified_envelope.is_identical_to(&envelope_to_sign) {
            log!("🔏 Signature verified and contents match.");
        } else {
            bail!("Signature verification succeeded, but contents do not match.");
        }

        chapter_title("🚪 Envoy tells Passport to shut down");
        self.shutdown_passport().await?;

        Ok(())
    }
}

impl Envoy {
    async fn sign_envelope(self: &Arc<Self>, envelope: &Envelope) -> anyhow::Result<Envelope> {
        let passport_key = self.first_paired_device().await;

        log!("🔏 Sending envelope to sign…");
        let request_id = ARID::new();
        let request = Sign::new(&request_id, self.public_key(), envelope);
        let sealed_request = request
            .into_envelope()
            .seal_with_enclave(&self.enclave, &passport_key);
        self.bluetooth.send_envelope(&sealed_request).await?;

        log!("🔏 Waiting for response…");
        let (signed_envelope, _) = self.bluetooth.receive_envelope(Duration::from_secs(10)).await?
            .unseal_with_enclave(&self.enclave, &passport_key)?
            .parse_success_response(Some(&request_id))?;

        Ok(signed_envelope)
    }

    async fn run_pairing_mode(self: &Arc<Self>) -> anyhow::Result<()> {
        let discovery = self.scan_discovery().await?;
        let paired_device_key = self.send_pairing_request(&discovery).await?;
        self.add_paired_device(&paired_device_key).await;

        Ok(())
    }

    async fn generate_seed(self: &Arc<Self>) -> anyhow::Result<Seed> {
        let passport_key = self.first_paired_device().await;

        log!("🌱 Sending seed generation request…");
        let request_id = ARID::new();
        let sealed_request = Envelope::new_function(GENERATE_SEED_FUNCTION)
            .into_transaction_request(&request_id, self.public_key())
            .seal_with_enclave(&self.enclave, &passport_key);
        self.bluetooth.send_envelope(&sealed_request).await?;

        log!("🌱 Waiting for response…");
        let (seed_envelope, _) =
            self.bluetooth.receive_envelope(Duration::from_secs(10)).await?
            .unseal_with_enclave(&self.enclave, &passport_key)?
            .parse_success_response(Some(&request_id))?;
        let seed: Seed = seed_envelope.extract_subject()?;

        Ok(seed)
    }

    async fn shutdown_passport(self: &Arc<Self>) -> anyhow::Result<()> {
        let passport_key = self.first_paired_device().await;

        log!("🚪 Sending shutdown signal…");
        let request_id = ARID::new();
        let sealed_shutdown = Envelope::new_function(SHUTDOWN_FUNCTION)
            .into_transaction_request(&request_id, self.public_key())
            .seal_with_enclave(&self.enclave, &passport_key);
        self.bluetooth.send_envelope(&sealed_shutdown).await?;

        log!("🚪 Waiting for response…");
        self.bluetooth.receive_envelope(Duration::from_secs(10)).await?
            .unseal_with_enclave(&self.enclave, &passport_key)?
            .parse_success_response(Some(&request_id))?;

        Ok(())
    }

    async fn scan_discovery(self: &Arc<Self>) -> anyhow::Result<Discovery> {
        log!("📷 Scanning for discovery QR code…");
        let discovery: Discovery =
            self.camera.scan_envelope(Duration::from_secs(10)).await?
            .try_into()?;
        log!("📷 Scanned discovery QR code…");

        Ok(discovery)
    }

    async fn send_pairing_request(self: &Arc<Self>, discovery: &Discovery) -> anyhow::Result<PublicKeyBase> {
        log!("🤝 Sending pairing request…");
        let _endpoint = discovery.bluetooth_endpoint();
        let passport_key = discovery.key();
        let sealed_pairing =
            Pairing::new(discovery, self.public_key())
            .into_envelope()
            .seal_with_enclave(&self.enclave, passport_key);
        self.bluetooth.send_envelope(&sealed_pairing).await?;

        log!("🤝 Waiting for response…");
        self.bluetooth.receive_envelope(Duration::from_secs(10)).await?
            .unseal_with_enclave(&self.enclave, passport_key)?
            .parse_success_response(Some(discovery.id()))?;

        Ok(passport_key.clone())
    }

    async fn add_paired_device(self: &Arc<Self>, paired_device_key: &PublicKeyBase) {
        // If `paired_devices` contains the key, do nothing (idempotent operation)
        if self.paired_devices.lock().await.contains(paired_device_key) {
            log!("🤝 Already paired to that device.");
        } else {
            // If the key is different, store it.
            self.paired_devices.lock().await.insert(paired_device_key.clone());
            log!("🤝 Successfully paired.");
        }
    }
}

// Internal methods
impl Envoy {
    async fn first_paired_device(&self) -> PublicKeyBase {
        self.paired_devices.lock().await.iter().next().unwrap().clone()
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
