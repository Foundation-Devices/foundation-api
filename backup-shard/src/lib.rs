use minicbor::{Decode, Decoder, Encode, Encoder};

#[derive(Debug, Default, Clone, PartialEq, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Shard {
    pub shard: ShardVersion,
    pub hmac: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum ShardVersion {
    V0(ShardV0),
}

impl Default for ShardVersion {
    fn default() -> Self {
        ShardVersion::V0(ShardV0::default())
    }
}

impl<C> Encode<C> for ShardVersion {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            ShardVersion::V0(shard) => {
                e.u8(ShardV0::VERSION)?;
                shard.encode(e, ctx)?;
            }
        }
        Ok(())
    }

    fn is_nil(&self) -> bool {
        false
    }
}

impl<'b, C> Decode<'b, C> for ShardVersion {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let version = d.u8()?;
        match version {
            ShardV0::VERSION => Ok(ShardVersion::V0(ShardV0::decode(d, ctx)?)),
            _ => Err(minicbor::decode::Error::message("Invalid Version")),
        }
    }
}

impl Shard {
    const FOUNDATION_KEYCARD_PREFIX: &[u8] = b"Foundation KeyCard";

    /// Returns the hash input for the hmac
    pub fn hmac_input(&self, uid: &[u8]) -> Vec<u8> {
        // Create the hash input: "Foundation KeyCard" || UID || data
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(Self::FOUNDATION_KEYCARD_PREFIX);
        hash_input.extend_from_slice(uid);
        hash_input.extend(minicbor::to_vec(&self.shard).unwrap());
        hash_input
    }

    /// Returns the encoded shard (official encoding is minicbor)
    pub fn encode(&self) -> Vec<u8> {
        let mut v = minicbor::to_vec(&self.shard).unwrap();
        v.extend_from_slice(&self.hmac);
        v
    }

    /// Returns the decoded shard (official encoding is minicbor)
    pub fn decode(data: &[u8]) -> Result<Shard, minicbor::decode::Error> {
        if data.len() < 32 {
            return Err(minicbor::decode::Error::message("invalid length"));
        }
        let (data, hmac) = data.split_at(data.len() - 32);
        let shard: ShardVersion = minicbor::decode(data)?;
        let hmac: [u8; 32] = hmac.try_into().unwrap();
        Ok(Shard { shard, hmac })
    }
}

#[derive(
    Debug, Default, Clone, PartialEq, minicbor::Encode, minicbor::Decode, zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct ShardV0 {
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
}

impl ShardV0 {
    pub const VERSION: u8 = 0;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let shard = Shard {
            shard: ShardVersion::V0(ShardV0 {
                device_id: [0xAA; 32],
                seed_fingerprint: [0xBB; 32],
                seed_shamir_share: vec![1, 2, 3, 4, 5],
                seed_shamir_share_index: 2,
                part_of_magic_backup: true,
            }),
            hmac: [0xCC; 32],
        };

        let encoded = shard.encode();
        println!("Encoded length: {} bytes", encoded.len());
        let decoded = Shard::decode(&encoded).unwrap();
        assert_eq!(shard, decoded);
    }
}
