use bc_components::UUID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BluetoothEndpoint {
    service: UUID,
    characteristic: UUID,
}

impl BluetoothEndpoint {
    pub fn from_fields(service: UUID, characteristic: UUID) -> Self {
        Self {
            service,
            characteristic,
        }
    }

    pub fn new() -> Self {
        Self::from_fields(UUID::new(), UUID::new())
    }

    pub fn service(&self) -> &UUID {
        &self.service
    }

    pub fn characteristic(&self) -> &UUID {
        &self.characteristic
    }
}

impl Default for BluetoothEndpoint {
    fn default() -> Self {
        Self::new()
    }
}
