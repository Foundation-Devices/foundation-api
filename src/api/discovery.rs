use anyhow::Result;
use bc_components::UUID;
use bc_envelope::prelude::*;

use super::{BluetoothEndpoint, CHARACTERISTIC_PARAM, DISCOVERY_FUNCTION, SERVICE_PARAM};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery(BluetoothEndpoint);

impl Discovery {
    pub fn new(endpoint: BluetoothEndpoint) -> Self {
        Self(endpoint)
    }
}

impl From<Discovery> for Expression {
    fn from(value: Discovery) -> Self {
        Expression::new(DISCOVERY_FUNCTION)
            .with_parameter(SERVICE_PARAM, value.0.service().clone())
            .with_parameter(CHARACTERISTIC_PARAM, value.0.characteristic().clone())
    }
}

impl TryFrom<Expression> for Discovery {
    type Error = anyhow::Error;

    fn try_from(expression: Expression) -> Result<Self> {
        let service: UUID = expression.extract_object_for_parameter(SERVICE_PARAM)?;
        let characteristic: UUID = expression.extract_object_for_parameter(CHARACTERISTIC_PARAM)?;
        let endpoint = BluetoothEndpoint::from_fields(service, characteristic);
        Ok(Self(endpoint))
    }
}

impl Discovery {
    pub fn bluetooth_endpoint(&self) -> &BluetoothEndpoint {
        &self.0
    }
}
