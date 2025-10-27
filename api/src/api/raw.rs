use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct RawData {
    #[n(0)]
    pub payload: Vec<u8>,
}
