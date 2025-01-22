pub mod discovery;
pub mod firmware;
pub mod fx;
pub mod onboarding;
pub mod pairing;
pub mod passport;
pub mod scv;
pub mod settings;
pub mod status;

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
        // Convert raw data to DCBOR

        let dcbor = CBOR::try_from_data(buffer).unwrap();

        let envelope = Envelope::new(dcbor);
        Expression::new(QUANTUM_LINK).with_parameter("message", envelope)
    }
}
