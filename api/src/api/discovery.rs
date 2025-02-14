use {
    anyhow::Result,
    bc_envelope::prelude::*,
    bc_xid::XIDDocument,
};

// Functions
pub const DISCOVERY_FUNCTION: Function = Function::new_static_named("discovery");

// Parameters
const SENDER_PARAM: Parameter = Parameter::new_static_named("sender");
const SENDER_BLE_ADDRESS_PARAM: Parameter = Parameter::new_static_named("senderBleAddress");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    sender: XIDDocument,
    ble_address: [u8; 6],
}

impl Discovery {
    pub fn new(sender: XIDDocument, ble_address: [u8; 6]) -> Self {
        Self {
            sender,
            ble_address,
        }
    }
}

impl From<Discovery> for Expression {
    fn from(value: Discovery) -> Self {
        Expression::new(DISCOVERY_FUNCTION)
            .with_parameter(SENDER_PARAM, value.sender)
            .with_parameter(SENDER_BLE_ADDRESS_PARAM, value.ble_address.to_cbor())
    }
}

impl TryFrom<Expression> for Discovery {
    type Error = anyhow::Error;

    fn try_from(expression: Expression) -> Result<Self> {
        let envelope = expression.object_for_parameter(SENDER_PARAM)?;
        let sender: XIDDocument = XIDDocument::try_from(envelope)?;
        //let sender_ble_address: [u8; 6] =
        // expression.object_for_parameter(SENDER_BLE_ADDRESS_PARAM)?.to_cbor().into();
        // TODO: fix this
        Ok(Self::new(
            XIDDocument::try_from(sender)?,
            [0, 0, 0, 0, 0, 0],
        ))
    }
}

impl Discovery {
    pub fn sender(&self) -> &XIDDocument {
        &self.sender
    }
    pub fn sender_ble_address(&self) -> [u8; 6] {
        self.ble_address
    }
}