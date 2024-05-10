use bc_components::{PublicKeyBase, ARID};
use bc_envelope::prelude::*;

use super::{SIGN_FUNCTION, SIGNING_SUBJECT_PARAM};

#[derive(Debug, Clone)]
pub struct Sign {
    id: ARID,
    key: PublicKeyBase,
    signing_subject: Envelope,
}

impl Sign {
    pub fn from_fields(
        id: ARID,
        key: PublicKeyBase,
        signing_subject: Envelope,
    ) -> Self {
        Self {
            id,
            key,
            signing_subject,
        }
    }

    pub fn new(
        id: &ARID,
        key: &PublicKeyBase,
        signing_subject: &Envelope,
    ) -> Self {
        Self::from_fields(
            id.clone(),
            key.clone(),
            signing_subject.clone(),
        )
    }

    pub fn from_body(
        id: &ARID,
        key: &PublicKeyBase,
        body: &Envelope,
    ) -> anyhow::Result<Self> {
        let signing_subject = body.object_for_parameter(SIGNING_SUBJECT_PARAM)?;
        Ok(Self::from_fields(id.clone(), key.clone(), signing_subject))
    }
}

impl Sign {
    pub fn id(&self) -> &ARID {
        &self.id
    }

    pub fn key(&self) -> &PublicKeyBase {
        &self.key
    }

    pub fn signing_subject(&self) -> &Envelope {
        &self.signing_subject
    }
}

impl From<Sign> for Envelope {
    fn from(request: Sign) -> Self {
        Envelope::new_function(SIGN_FUNCTION)
            .add_parameter(SIGNING_SUBJECT_PARAM, &request.signing_subject)
            .into_transaction_request(&request.id, &request.key)
    }
}

impl TryFrom<Envelope> for Sign {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let (id, key, body, _) = envelope.parse_signed_transaction_request(Some(&SIGN_FUNCTION))?;
        Self::from_body(&id, &key, &body)
    }
}
