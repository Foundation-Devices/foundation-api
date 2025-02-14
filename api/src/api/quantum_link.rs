use minicbor_derive::{Decode, Encode};
use minicbor::{Decode, Encode};
use bc_envelope::{Envelope, Expression, ExpressionBehavior, Function};
use bc_envelope::prelude::CBOR;
use anyhow::bail;
use quantum_link_macros::QuantumLinkMessage;
use crate::firmware::FirmwareUpdate;
use crate::fx::ExchangeRate;
use crate::pairing::{PairingRequest, PairingResponse};
use crate::status::{DeviceStatus, EnvoyStatus};

#[derive(Debug, Encode, Decode, QuantumLinkMessage)]
pub enum QuantumLinkMessages {
    #[n(0)]
    ExchangeRate(#[n(0)] ExchangeRate),
    #[n(1)]
    FirmwareUpdate(#[n(0)] FirmwareUpdate),
    #[n(2)]
    DeviceStatus(#[n(0)] DeviceStatus),
    #[n(3)]
    EnvoyStatus(#[n(0)] EnvoyStatus),
    #[n(4)]
    PairingResponse(#[n(0)] PairingResponse),
    #[n(5)]
    PairingRequest(#[n(0)] PairingRequest),
}

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

        let message = minicbor::decode(&raw_data).map_err(|e| anyhow::anyhow!(e))?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::quantum_link::QuantumLinkMessage;
    use crate::fx::ExchangeRate;
    use crate::api::quantum_link::QuantumLinkMessages;

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

pub const QUANTUM_LINK: Function = Function::new_static_named("quantumLink");