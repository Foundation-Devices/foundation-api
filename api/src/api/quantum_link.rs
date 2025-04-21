use anyhow::bail;
use bc_components::{EncapsulationScheme, PrivateKeys, PublicKeys, SignatureScheme, ARID};
use bc_envelope::prelude::CBOR;
use bc_envelope::{Envelope, EventBehavior, Expression, ExpressionBehavior, Function};
use bc_xid::XIDDocument;
use gstp::{SealedEvent, SealedEventBehavior};
use crate::message::{EnvoyMessage, PassportMessage};
use flutter_rust_bridge::frb;

pub const QUANTUM_LINK: Function = Function::new_static_named("quantumLink");
pub trait QuantumLink<C>: minicbor::Encode<C> {
    fn encode(&self) -> Expression
        where
            Self: minicbor::Encode<()>,
    {
        let mut buffer: Vec<u8> = Vec::new();

        minicbor::encode(self, &mut buffer).unwrap();
        let dcbor = CBOR::try_from_data(buffer).unwrap();

        let envelope = Envelope::new(dcbor);
        Expression::new(QUANTUM_LINK).with_parameter("ql", envelope)
    }

    fn decode(expression: &Expression) -> anyhow::Result<Self>
        where
            Self: for<'a> minicbor::Decode<'a, ()>,
    {
        if expression.function().clone() != QUANTUM_LINK {
            bail!("Expected QuantumLink function");
        }
        let envelope = expression.object_for_parameter("ql")?;
        let raw_data = envelope
            .as_leaf()
            .expect("there should be a leaf")
            .to_cbor_data();

        let message = minicbor::decode(&raw_data).map_err(|e| anyhow::anyhow!(e))?;
        Ok(message)
    }

    fn seal(
        &self,
        sender: QuantumLinkIdentity,
        recipient: QuantumLinkIdentity,
    ) -> Envelope where Self: minicbor::Encode<()> {
        let event: SealedEvent<Expression> = SealedEvent::new(QuantumLink::encode(self), ARID::new(), sender.xid_document.unwrap());
        event
            .to_envelope(None, Some(&sender.private_keys.unwrap()), Some(&recipient.xid_document.unwrap()))
            .unwrap()
    }

    fn unseal(envelope: &Envelope, private_keys: &PrivateKeys) -> anyhow::Result<(Expression, XIDDocument)>
        where Self: for<'a> minicbor::Decode<'a, ()> {
        let event: SealedEvent<Expression> = SealedEvent::try_from_envelope(envelope, None, None, private_keys)?;
        let expression = event.content().clone();
        Ok((expression, event.sender().clone()))
    }

    fn unseal_passport_message(envelope: &Envelope, private_keys: &PrivateKeys) -> anyhow::Result<(PassportMessage, XIDDocument)> {
        let (expression, sender) = PassportMessage::unseal(envelope, private_keys)?;
        Ok((PassportMessage::decode(&expression)?, sender))
    }

    fn unseal_envoy_message(envelope: &Envelope, private_keys: &PrivateKeys) -> anyhow::Result<(EnvoyMessage, XIDDocument)> {
        let (expression, sender) = EnvoyMessage::unseal(envelope, private_keys)?;
        Ok((EnvoyMessage::decode(&expression)?, sender))
    }
}

#[derive(Debug, Clone)]
#[frb(opaque)]
pub struct QuantumLinkIdentity {
    pub private_keys: Option<PrivateKeys>,
    pub public_keys: Option<PublicKeys>,
    pub xid_document: Option<XIDDocument>,
}

pub fn generate_identity() -> QuantumLinkIdentity {
    let (signing_private_key, signing_public_key) = SignatureScheme::MLDSA44.keypair();
    let (encapsulation_private_key, encapsulation_public_key) = EncapsulationScheme::MLKEM512.keypair();

    let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
    let public_keys = PublicKeys::new(signing_public_key, encapsulation_public_key);

    let xid_document = XIDDocument::new(public_keys.clone());

    QuantumLinkIdentity {
        private_keys: Some(private_keys),
        public_keys: Some(public_keys),
        xid_document: Some(xid_document),
    }
}

#[cfg(test)]
mod tests {
    use crate::api::message::QuantumLinkMessage;
    use crate::api::quantum_link::QuantumLink;
    use crate::fx::ExchangeRate;
    use crate::message::EnvoyMessage;
    use crate::quantum_link::generate_identity;

    #[test]
    fn test_encode_decode_quantumlink_message() {
        let fx_rate = ExchangeRate::new("USD", 0.85);
        let original_message = QuantumLinkMessage::ExchangeRate(fx_rate.clone());

        // Encode the message
        let expression = QuantumLink::encode(&original_message);

        // Decode the message
        let decoded_message = QuantumLink::decode(&expression).unwrap();

        let fx_rate_decoded: ExchangeRate = match decoded_message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        // Assert that the original and decoded messages are the same
        assert_eq!(fx_rate.rate(), fx_rate_decoded.rate());
    }

    #[test]
    fn test_seal_unseal_quantumlink_message() {
        let envoy = generate_identity();
        let passport = generate_identity();

        let fx_rate = ExchangeRate::new("USD", 0.85);
        let original_message = EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate.clone()),
            timestamp: 123456,
        };

        // Seal the message
        let envelope = QuantumLink::seal(&original_message, envoy.clone(), passport.clone());

        // Decode the message
        let decoded_message = EnvoyMessage::unseal_envoy_message(&envelope, &passport.private_keys.unwrap()).unwrap();

        let fx_rate_decoded: ExchangeRate = match decoded_message.0.message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        // Assert that the original and decoded messages are the same
        assert_eq!(fx_rate.rate(), fx_rate_decoded.rate());
    }
}
