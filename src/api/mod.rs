mod bluetooth_endpoint;
pub use bluetooth_endpoint::BluetoothEndpoint;
mod discovery;
pub use discovery::Discovery;
mod sign;
pub use sign::Sign;

use bc_envelope::prelude::*;

// Functions

pub const DISCOVERY_FUNCTION: Function = Function::new_static_named("discovery");
pub const PAIRING_FUNCTION: Function = Function::new_static_named("pairing");

pub const SIGN_FUNCTION_NAME: &str = "sign";
pub const GENERATE_SEED_FUNCTION_NAME: &str = "generateSeed";
pub const SHUTDOWN_FUNCTION_NAME: &str = "shutdown";
pub const SIGN_FUNCTION: Function = Function::new_static_named(SIGN_FUNCTION_NAME);
pub const GENERATE_SEED_FUNCTION: Function = Function::new_static_named(GENERATE_SEED_FUNCTION_NAME);
pub const SHUTDOWN_FUNCTION: Function = Function::new_static_named(SHUTDOWN_FUNCTION_NAME);

// Parameters

const SERVICE_PARAM: Parameter = Parameter::new_static_named("bluetoothService");
const CHARACTERISTIC_PARAM: Parameter = Parameter::new_static_named("bluetoothCharacteristic");
const SIGNING_SUBJECT_PARAM: Parameter = Parameter::new_static_named("signingSubject");
