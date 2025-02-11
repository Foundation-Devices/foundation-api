pub mod discovery;
pub mod firmware;
pub mod fx;
pub mod onboarding;
pub mod pairing;
pub mod passport;
pub mod scv;
pub mod settings;
pub mod status;
pub mod messages;

use anyhow::bail;
use minicbor::Decode;
use {bc_envelope::prelude::*, minicbor::Encode};

// Functions
pub const DISCOVERY_FUNCTION: Function = Function::new_static_named("discovery");
pub const PAIRING_FUNCTION: Function = Function::new_static_named("pairing");
pub const QUANTUM_LINK: Function = Function::new_static_named("quantumLink");

// Parameters

const SENDER_PARAM: Parameter = Parameter::new_static_named("sender");
const SENDER_BLE_ADDRESS_PARAM: Parameter = Parameter::new_static_named("senderBleAddress");

pub trait QuantumLinkMessage<C>: Encode<C> {
    fn encode(&self) -> Expression
    where
        Self: Encode<()>,
    {
        let mut buffer: Vec<u8> = Vec::new();

        minicbor::encode(self, &mut buffer).unwrap();
        let dcbor = CBOR::try_from_data(buffer).unwrap();

        let envelope = Envelope::new(dcbor);
        Expression::new(QUANTUM_LINK).with_parameter("ql", envelope)
    }

    fn decode(expression: &Expression) -> anyhow::Result<Self>
    where
        Self: for<'a> Decode<'a, ()>,
    {
        if expression.function().clone() != QUANTUM_LINK {
            bail!("Expected QuantumLink function");
        }
        let envelope = expression.object_for_parameter("ql")?;
        let raw_data = envelope.as_leaf().expect("there should be a leaf").to_cbor_data();

        let message = minicbor::decode(&raw_data)?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fx::ExchangeRate;
    use crate::messages::QuantumLinkMessages;

    #[test]
    fn test_encode_decode_quantumlink_message() {
        let fx_rate = ExchangeRate::new("USD",  0.85);
        let original_message = QuantumLinkMessages::ExchangeRate(fx_rate.clone());

        // Encode the message
        let expression = QuantumLinkMessage::encode(&original_message);

        // Decode the message
        let decoded_message = QuantumLinkMessage::decode(&expression).unwrap();

        let fx_rate_decoded: ExchangeRate = match decoded_message {
            QuantumLinkMessages::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        // Assert that the original and decoded messages are the same
        assert_eq!(fx_rate.rate(), fx_rate_decoded.rate());
    }
}