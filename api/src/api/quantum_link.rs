use {
    crate::message::{EnvoyMessage, PassportMessage},
    anyhow::bail,
    bc_components::{EncapsulationScheme, PrivateKeys, PublicKeys, SignatureScheme, ARID},
    bc_envelope::{
        prelude::{CBORCase, CBOR},
        Envelope,
        EventBehavior,
        Expression,
        ExpressionBehavior,
        Function,
    },
    bc_xid::XIDDocument,
    flutter_rust_bridge::frb,
    gstp::{SealedEvent, SealedEventBehavior},
};

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

    fn seal(&self, sender: QuantumLinkIdentity, recipient: QuantumLinkIdentity) -> Envelope
    where
        Self: minicbor::Encode<()>,
    {
        let event: SealedEvent<Expression> =
            SealedEvent::new(QuantumLink::encode(self), ARID::new(), sender.xid_document);
        event
            .to_envelope(
                None,
                Some(&sender.private_keys.unwrap()),
                Some(&recipient.xid_document),
            )
            .unwrap()
    }

    fn unseal(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
    ) -> anyhow::Result<(Expression, XIDDocument)>
    where
        Self: for<'a> minicbor::Decode<'a, ()>,
    {
        let event: SealedEvent<Expression> =
            SealedEvent::try_from_envelope(envelope, None, None, private_keys)?;
        let expression = event.content().clone();
        Ok((expression, event.sender().clone()))
    }

    fn unseal_passport_message(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
    ) -> anyhow::Result<(PassportMessage, XIDDocument)> {
        let (expression, sender) = PassportMessage::unseal(envelope, private_keys)?;
        Ok((PassportMessage::decode(&expression)?, sender))
    }

    fn unseal_envoy_message(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
    ) -> anyhow::Result<(EnvoyMessage, XIDDocument)> {
        let (expression, sender) = EnvoyMessage::unseal(envelope, private_keys)?;
        Ok((EnvoyMessage::decode(&expression)?, sender))
    }
}

#[derive(Debug, Clone)]
#[frb(opaque)]
pub struct QuantumLinkIdentity {
    pub private_keys: Option<PrivateKeys>,
    pub xid_document: XIDDocument,
}

impl QuantumLinkIdentity {
    pub fn generate() -> Self {
        let (signing_private_key, signing_public_key) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private_key, encapsulation_public_key) =
            EncapsulationScheme::MLKEM512.keypair();

        let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
        let public_keys = PublicKeys::new(signing_public_key, encapsulation_public_key);

        let xid_document = XIDDocument::new(public_keys.clone());

        QuantumLinkIdentity {
            private_keys: Some(private_keys),
            xid_document,
        }
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut map = bc_envelope::prelude::Map::new();
        map.insert(CBOR::from("xid_document"), self.clone().xid_document);
        if self.private_keys.is_some() {
            map.insert(
                CBOR::from("private_keys"),
                self.clone().private_keys.unwrap(),
            );
        }

        Ok(CBOR::from(map).to_cbor_data())
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let cbor = CBOR::try_from_data(bytes)
            .ok()
            .ok_or_else(|| anyhow::anyhow!("Invalid CBOR"))?;
        let case = cbor.into_case();

        let CBORCase::Map(map) = case else {
            return Err(anyhow::anyhow!("Invalid CBOR case"));
        };

        Ok(QuantumLinkIdentity {
            xid_document: map
                .get("xid_document")
                .ok_or_else(|| anyhow::anyhow!("xid_document not found"))?,
            private_keys: map.get("private_keys"),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api::{message::QuantumLinkMessage, quantum_link::QuantumLink},
        fx::ExchangeRate,
        message::EnvoyMessage,
        quantum_link::QuantumLinkIdentity,
    };

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
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();

        let fx_rate = ExchangeRate::new("USD", 0.85);
        let original_message = EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate.clone()),
            timestamp: 123456,
        };

        // Seal the message
        let envelope = QuantumLink::seal(&original_message, envoy.clone(), passport.clone());

        // Decode the message
        let decoded_message =
            EnvoyMessage::unseal_envoy_message(&envelope, &passport.private_keys.unwrap()).unwrap();

        let fx_rate_decoded: ExchangeRate = match decoded_message.0.message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        // Assert that the original and decoded messages are the same
        assert_eq!(fx_rate.rate(), fx_rate_decoded.rate());
    }

    #[test]
    fn test_serialize_ql_identity() {
        let identity = QuantumLinkIdentity::generate();
        let bytes = identity.to_bytes().unwrap();

        let deserialized_identity = QuantumLinkIdentity::from_bytes(bytes.as_slice()).unwrap();

        // Assert that the original and decoded messages are the same
        assert_eq!(
            identity.private_keys.unwrap(),
            deserialized_identity.private_keys.unwrap()
        );
    }
}
