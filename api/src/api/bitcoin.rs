use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct SignPsbt {
    #[n(0)]
    pub account_id: String,
    #[n(1)]
    pub psbt: Vec<u8>,
}

#[quantum_link]
pub struct AccountUpdate {
    #[n(0)]
    pub account_id: String,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub update: Vec<u8>,
}

#[quantum_link]
pub struct BroadcastTransaction {
    #[n(0)]
    pub account_id: String,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub psbt: Vec<u8>,
}

// If None, there's no passphrase, hide passphrased accounts
#[quantum_link]
pub struct ApplyPassphrase {
    #[n(0)]
    pub fingerprint: Option<String>,
}
