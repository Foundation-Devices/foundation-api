use {
    anyhow::{anyhow, Context, Result},
    bc_components::{PrivateKeyBase, PublicKeyBase, ARID},
    bc_envelope::{
        Envelope,
        Expression,
        ExpressionBehavior,
        Function,
        Parameter,
        RequestBehavior,
        ResponseBehavior,
        SealedRequest,
        SealedRequestBehavior,
        SealedResponse,
        SealedResponseBehavior,
    },
};

/// Message sent from KeyOS to Envoy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyOsMessage {
    Pair { pubkey: PublicKeyBase },
    // TODO: Placeholders for now
    Onboarding1,
    Onboarding2,
}

/// Message sent from Envoy to KeyOS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EnvoyMessage {
    // TODO: Placeholders for now
    Onboarding3,
    Onboarding4,
}

impl KeyOsMessage {
    pub fn into_sealed_request(
        self,
        privkey: &PrivateKeyBase,
        recipient: &PublicKeyBase,
    ) -> Envelope {
        let body = self.into_expression();
        let request = SealedRequest::new_with_body(
            body.clone(),
            ARID::new(),
            privkey.schnorr_public_key_base(),
        )
        .with_optional_state(Some(body));
        (request, privkey, recipient).into()
    }

    pub fn to_sealed_request(
        &self,
        privkey: &PrivateKeyBase,
        recipient: &PublicKeyBase,
    ) -> Envelope {
        self.clone().into_sealed_request(privkey, recipient)
    }

    pub fn try_from_sealed_request(
        envelope: Envelope,
        privkey: &PrivateKeyBase,
    ) -> Result<(ARID, PublicKeyBase, Self)> {
        let request =
            SealedRequest::try_from((envelope, privkey)).context("Decoding sealed request")?;
        let request_id = request.id().clone();
        let body = request.body().clone();
        let sender = request.sender().clone();
        let msg = Self::from_expression(body)?;
        Ok((request_id, sender, msg))
    }

    fn into_expression(self) -> Expression {
        match self {
            Self::Pair { pubkey } => {
                Expression::new(PAIR_FUNCTION).with_parameter(PUBKEY_PARAM, pubkey)
            }
            Self::Onboarding1 => Expression::new(ONBOARDING1_FUNCTION),
            Self::Onboarding2 => Expression::new(ONBOARDING2_FUNCTION),
        }
    }

    fn from_expression(expression: Expression) -> Result<Self> {
        let function = expression.function();
        if function == &PAIR_FUNCTION {
            let pubkey = expression
                .extract_object_for_parameter(PUBKEY_PARAM)
                .context("Expected a pubkey")?;
            Ok(Self::Pair { pubkey })
        } else if function == &ONBOARDING1_FUNCTION {
            Ok(Self::Onboarding1)
        } else if function == &ONBOARDING2_FUNCTION {
            Ok(Self::Onboarding2)
        } else {
            Err(anyhow!("Unknown function"))
        }
    }
}

impl EnvoyMessage {
    pub fn into_sealed_response(
        self,
        request_id: &ARID,
        privkey: &PrivateKeyBase,
        recipient: &PublicKeyBase,
    ) -> Envelope {
        let result = self.into_expression();
        let response = SealedResponse::new_success(request_id, privkey.schnorr_public_key_base())
            .with_optional_result(result.into());
        Envelope::from(response).seal(privkey, recipient)
    }

    pub fn to_sealed_response(
        &self,
        request_id: &ARID,
        privkey: &PrivateKeyBase,
        recipient: &PublicKeyBase,
    ) -> Envelope {
        self.clone()
            .into_sealed_response(request_id, privkey, recipient)
    }

    pub fn try_from_sealed_response(
        envelope: Envelope,
        privkey: &PrivateKeyBase,
    ) -> Result<(ARID, PublicKeyBase, Self)> {
        let response = SealedResponse::try_from((envelope, None, None, privkey))
            .context("Decoding sealed response")?;
        let result = response.result().cloned().context("Decoding result")?;
        let expression = Expression::try_from(result)?;
        let request_id = response
            .id()
            .cloned()
            .ok_or_else(|| anyhow!("No request ID found"))?;
        let sender = response.sender().clone();
        let msg = Self::from_expression(expression)?;
        Ok((request_id, sender, msg))
    }

    fn into_expression(self) -> Expression {
        match self {
            Self::Onboarding3 => Expression::new(ONBOARDING3_FUNCTION),
            Self::Onboarding4 => Expression::new(ONBOARDING4_FUNCTION),
        }
    }

    fn from_expression(expression: Expression) -> Result<Self> {
        let function = expression.function();
        if function == &ONBOARDING3_FUNCTION {
            Ok(Self::Onboarding3)
        } else if function == &ONBOARDING4_FUNCTION {
            Ok(Self::Onboarding4)
        } else {
            Err(anyhow!("Unknown function"))
        }
    }
}

const PAIR_FUNCTION: Function = Function::new_static_named("pair");
const ONBOARDING1_FUNCTION: Function = Function::new_static_named("onboarding1");
const ONBOARDING2_FUNCTION: Function = Function::new_static_named("onboarding2");
const ONBOARDING3_FUNCTION: Function = Function::new_static_named("onboarding3");
const ONBOARDING4_FUNCTION: Function = Function::new_static_named("onboarding4");

const PUBKEY_PARAM: Parameter = Parameter::new_static_named("pubkey");

#[cfg(test)]
mod tests {
    use {super::*, bc_components::PrivateKeyBase};

    #[test]
    fn test_keyos_message() {
        let sender_privkey = PrivateKeyBase::new();
        let sender_pubkey = sender_privkey.schnorr_public_key_base();
        let recipient_privkey = PrivateKeyBase::new();
        let recipient_pubkey = recipient_privkey.schnorr_public_key_base();
        for msg in [
            KeyOsMessage::Pair {
                pubkey: sender_pubkey.clone(),
            },
            KeyOsMessage::Onboarding1,
            KeyOsMessage::Onboarding2,
        ] {
            let envelope = msg.to_sealed_request(&sender_privkey, &recipient_pubkey);
            let (_, sender, decoded_msg) =
                KeyOsMessage::try_from_sealed_request(envelope, &recipient_privkey).unwrap();
            assert_eq!(decoded_msg, msg);
            assert_eq!(sender, sender_pubkey);
        }
    }

    #[test]
    fn test_envoy_message() {
        let sender_privkey = PrivateKeyBase::new();
        let sender_pubkey = sender_privkey.schnorr_public_key_base();
        let recipient_privkey = PrivateKeyBase::new();
        let recipient_pubkey = recipient_privkey.schnorr_public_key_base();
        let request_id = ARID::new();
        for msg in [EnvoyMessage::Onboarding3, EnvoyMessage::Onboarding4] {
            let envelope = msg.to_sealed_response(&request_id, &sender_privkey, &recipient_pubkey);
            let (decoded_request_id, sender, decoded_msg) =
                EnvoyMessage::try_from_sealed_response(envelope, &recipient_privkey).unwrap();
            assert_eq!(decoded_msg, msg);
            assert_eq!(sender, sender_pubkey);
            assert_eq!(decoded_request_id, request_id);
        }
    }
}
