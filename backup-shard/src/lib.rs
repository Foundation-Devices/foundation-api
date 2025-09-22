use minicbor::{Decode, Decoder, Encode, Encoder};

#[derive(Debug, Clone, PartialEq)]
pub enum Shard {
    V0(ShardV0),
}

impl<C> Encode<C> for Shard {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Shard::V0(shard) => {
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

impl<'b, C> Decode<'b, C> for Shard {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let version = d.u8()?;
        match version {
            ShardV0::VERSION => Ok(Shard::V0(ShardV0::decode(d, ctx)?)),
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
        hash_input.extend(self.data());
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

impl Shard {
    // Returns the data of the shard without the hmac
    fn data(&self) -> Vec<u8> {
        let mut data = self.encode();
        let data_len = data.len() - 34;
        data.truncate(data_len);
        data
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
    // make sure it stay the last field in the struct for `data()` method below
    #[cbor(n(5), with = "minicbor::bytes")]
    pub hmac: [u8; 32],
}

impl ShardV0 {
    pub const VERSION: u8 = 0;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn shard_v0() {
        let shard = Shard::V0(ShardV0 {
            device_id: [1; 32],
            seed_fingerprint: [2; 32],
            seed_shamir_share: vec![3, 3, 3],
            seed_shamir_share_index: 0,
            part_of_magic_backup: false,
            hmac: [4; 32],
        });
        let encoded = shard.encode();
        assert_eq!(
            encoded,
            vec![
                0, 134, 88, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 88, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 131, 3, 3, 3, 0, 244, 88, 32, 4,
                4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
                4, 4, 4
            ]
        );
        assert_eq!(Shard::decode(&encoded).unwrap(), shard);
    }
}
