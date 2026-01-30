use bc_components::{EncapsulationPrivateKey, Signer};

pub trait QlPlatform {
    fn signer(&self) -> &dyn Signer;
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn fill_bytes(&self, data: &mut [u8]);
}
