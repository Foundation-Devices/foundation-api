use bc_components::{PublicKeyBase, ARID, UUID};
use bc_envelope::prelude::*;

use super::{BluetoothEndpoint, CHARACTERISTIC_PARAM, DISCOVERY_FUNCTION, SERVICE_PARAM};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    id: ARID,
    key: PublicKeyBase,
    endpoint: BluetoothEndpoint,
}

impl Discovery {
    pub fn from_fields(
        id: ARID,
        key: PublicKeyBase,
        endpoint: BluetoothEndpoint,
    ) -> Self {
        Self {
            id,
            key,
            endpoint,
        }
    }

    pub fn new(
        id: &ARID,
        key: &PublicKeyBase,
        endpoint: &BluetoothEndpoint,
    ) -> Self {
        Self::from_fields(
            id.clone(),
            key.clone(),
            endpoint.clone(),
        )
    }
}

impl From<Discovery> for Envelope {
    fn from(request: Discovery) -> Self {
        Envelope::new_function(DISCOVERY_FUNCTION)
            .add_parameter(SERVICE_PARAM, request.endpoint.service().clone())
            .add_parameter(CHARACTERISTIC_PARAM, request.endpoint.characteristic().clone())
            .into_transaction_request(&request.id, &request.key)
    }
}

impl TryFrom<Envelope> for Discovery {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let (id, key, body, _) = envelope.parse_signed_transaction_request(Some(&DISCOVERY_FUNCTION))?;
        let service: UUID = body.extract_object_for_parameter(SERVICE_PARAM)?;
        let characteristic: UUID = body.extract_object_for_parameter(CHARACTERISTIC_PARAM)?;
        let endpoint = BluetoothEndpoint::from_fields(service, characteristic);
        Ok(Self::from_fields(id, key, endpoint))
    }
}

impl Discovery {
    pub fn id(&self) -> &ARID {
        &self.id
    }

    pub fn key(&self) -> &PublicKeyBase {
        &self.key
    }

    pub fn bluetooth_endpoint(&self) -> &BluetoothEndpoint {
        &self.endpoint
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use bc_components::PrivateKeyBase;

    #[test]
    fn test_pairing_request() {
        let endpoint = BluetoothEndpoint::new();
        let private_key = &PrivateKeyBase::new();
        let public_key = private_key.public_key();
        let request = Discovery::new(&ARID::new(), &public_key, &endpoint);
        let envelope = request.to_envelope();
        let signed_envelope = envelope.sign(private_key);
        //println!("{}", signed_envelope.format());
        let decoded_request = Discovery::try_from(signed_envelope).unwrap();
        assert_eq!(request, decoded_request);
    }
}
