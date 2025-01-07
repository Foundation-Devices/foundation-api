mod discovery;
pub use discovery::Discovery;
mod fx;
mod pairing;
mod passport;
mod sign;
pub mod bluetooth_endpoint;

use bc_envelope::prelude::*;
pub use {
    fx::ExchangeRate,
    pairing::{PairingResponse, PairingRequest},
    passport::PassportModel,
    passport::{PassportFirmwareVersion, PassportSerial},
    sign::Sign,
};

use minicbor::Encode;

// Functions

pub const DISCOVERY_FUNCTION: Function = Function::new_static_named("discovery");
pub const PAIRING_FUNCTION: Function = Function::new_static_named("pairing");

pub const SIGN_FUNCTION_NAME: &str = "sign";
pub const GENERATE_SEED_FUNCTION_NAME: &str = "generateSeed";
pub const SHUTDOWN_FUNCTION_NAME: &str = "shutdown";
pub const SIGN_FUNCTION: Function = Function::new_static_named(SIGN_FUNCTION_NAME);
pub const GENERATE_SEED_FUNCTION: Function =
    Function::new_static_named(GENERATE_SEED_FUNCTION_NAME);
pub const SHUTDOWN_FUNCTION: Function = Function::new_static_named(SHUTDOWN_FUNCTION_NAME);

pub const QUANTUM_LINK: Function = Function::new_static_named("quantumLink");

// Parameters

const SENDER_PARAM: Parameter = Parameter::new_static_named("sender");
const SERVICE_PARAM: Parameter = Parameter::new_static_named("bluetoothService");
const CHARACTERISTIC_PARAM: Parameter = Parameter::new_static_named("bluetoothCharacteristic");
const SIGNING_SUBJECT_PARAM: Parameter = Parameter::new_static_named("signingSubject");


pub trait QuantumLinkMessage<C>: Encode<C> {
    fn encode(&self) -> Expression where Self: Encode<()> {
        let mut buffer: Vec<u8> = Vec::new();

        minicbor::encode(self, &mut buffer).unwrap();
        // Convert raw data to DCBOR

        let dcbor = CBOR::try_from_data(buffer).unwrap();

        let envelope = Envelope::new(dcbor);
        Expression::new(QUANTUM_LINK).with_parameter("message", envelope)
    }
}
