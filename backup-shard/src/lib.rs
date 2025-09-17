#[derive(
    Debug, Default, Clone, PartialEq, minicbor::Encode, minicbor::Decode, zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Shard {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub device_id: [u8; 32],
    #[cbor(n(1), with = "minicbor::bytes")]
    pub seed_fingerprint: [u8; 32],
    #[n(2)]
    pub seed_shamir_share: Vec<u8>,
    #[n(3)]
    pub seed_shamir_share_index: usize,
    #[n(4)]
    pub part_of_magic_backup: bool,
    // make sure it stay the last field in the struct for `data()` method below
    #[cbor(n(5), with = "minicbor::bytes")]
    pub hmac: [u8; 32],
}

impl Shard {
    const FOUNDATION_KEYCARD_PREFIX: &[u8] = b"Foundation KeyCard";

    /// Returns the data of the shard without the hmac
    pub fn data(&self) -> Vec<u8> {
        let full_data = minicbor::to_vec(self).unwrap();
        full_data[..full_data.len() - 34].to_vec()
    }

    /// Returns the hash input for the hmac
    pub fn hmac_input(&self, uid: &[u8]) -> Vec<u8> {
        // Create the hash input: "Foundation KeyCard" || UID || data
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(Self::FOUNDATION_KEYCARD_PREFIX);
        hash_input.extend_from_slice(uid);
        hash_input.extend_from_slice(self.data().as_slice());
        hash_input
    }

    /// Returns the encoded shard (official encoding is minicbor)
    pub fn encode(&self) -> Vec<u8> {
        minicbor::to_vec(self).unwrap()
    }

    /// Returns the decoded shard (official encoding is minicbor)
    pub fn decode(data: &[u8]) -> Result<Shard, minicbor::decode::Error> {
        minicbor::decode(data)
    }
}
