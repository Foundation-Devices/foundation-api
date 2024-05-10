use bc_components::{PublicKeyBase, ARID};
use bc_envelope::prelude::*;

use super::{Discovery, PAIRING_FUNCTION};

#[derive(Debug, Clone)]
pub struct Pairing {
    id: ARID,
    key: PublicKeyBase,
}

impl Pairing {
    pub fn from_fields(
        id: ARID,
        key: PublicKeyBase,
    ) -> Self {
        Self {
            id,
            key,
        }
    }

    pub fn new(
        discovery: &Discovery,
        key: &PublicKeyBase
    ) -> Self {
        Self::from_fields(
            discovery.id().clone(),
            key.clone(),
        )
    }
}

impl Pairing {
    pub fn id(&self) -> &ARID {
        &self.id
    }

    pub fn key(&self) -> &PublicKeyBase {
        &self.key
    }
}

impl From<Pairing> for Envelope {
    fn from(pairing: Pairing) -> Self {
        Envelope::new_function(PAIRING_FUNCTION)
            .into_transaction_request(&pairing.id, &pairing.key)
    }
}

impl TryFrom<Envelope> for Pairing {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let (id, key, _, _) = envelope.parse_signed_transaction_request(Some(&PAIRING_FUNCTION))?;
        Ok(Self::from_fields(id, key))
    }
}
