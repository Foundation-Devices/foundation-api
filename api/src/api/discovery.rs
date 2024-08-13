use {
    super::{CHARACTERISTIC_PARAM, DISCOVERY_FUNCTION, SENDER_PARAM, SERVICE_PARAM},
    anyhow::Result,
    bc_components::{PublicKeyBase, UUID},
    bc_envelope::prelude::*,
};
use crate::bluetooth_endpoint::BluetoothEndpoint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    sender: PublicKeyBase,
    endpoint: BluetoothEndpoint,
}

impl Discovery {
    pub fn new(sender: PublicKeyBase, endpoint: BluetoothEndpoint) -> Self {
        Self { sender, endpoint }
    }
}

impl From<Discovery> for Expression {
    fn from(value: Discovery) -> Self {
        Expression::new(DISCOVERY_FUNCTION)
            .with_parameter(SENDER_PARAM, value.sender)
            .with_parameter(SERVICE_PARAM, value.endpoint.service().clone())
            .with_parameter(
                CHARACTERISTIC_PARAM,
                value.endpoint.characteristic().clone(),
            )
    }
}

impl TryFrom<Expression> for Discovery {
    type Error = anyhow::Error;

    fn try_from(expression: Expression) -> Result<Self> {
        let sender: PublicKeyBase = expression.extract_object_for_parameter(SENDER_PARAM)?;
        let service: UUID = expression.extract_object_for_parameter(SERVICE_PARAM)?;
        let characteristic: UUID = expression.extract_object_for_parameter(CHARACTERISTIC_PARAM)?;
        let endpoint = BluetoothEndpoint::from_fields(service, characteristic);
        Ok(Self::new(sender, endpoint))
    }
}

impl Discovery {
    pub fn sender(&self) -> &PublicKeyBase {
        &self.sender
    }
    pub fn bluetooth_endpoint(&self) -> &BluetoothEndpoint {
        &self.endpoint
    }
}
