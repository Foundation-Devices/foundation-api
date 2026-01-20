// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use dcbor::{CBOR, CBOREncodable, Map};

#[derive(Debug, Default, Clone, PartialEq, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Shard {
    pub shard: ShardVersion,
    pub hmac: [u8; 32],
}

impl Shard {
    pub const FOUNDATION_KEYCARD_PREFIX: &[u8] = b"Foundation KeyCard";

    /// Return a new instance of Shard
    pub fn new(
        device_id: [u8; 32],
        seed_fingerprint: [u8; 32],
        seed_shamir_share: Vec<u8>,
        seed_shamir_share_index: usize,
        part_of_magic_backup: bool,
    ) -> Self {
        Self {
            shard: ShardVersion::V1(ShardV1 {
                device_id,
                seed_fingerprint,
                seed_shamir_share,
                seed_shamir_share_index,
                part_of_magic_backup,
                timestamp: 0,
                scheme_threshold: 2,
                scheme_share_count: 3,
            }),
            hmac: [0; 32],
        }
    }

    pub fn new_v0(
        device_id: [u8; 32],
        seed_fingerprint: [u8; 32],
        seed_shamir_share: Vec<u8>,
        seed_shamir_share_index: usize,
        part_of_magic_backup: bool,
    ) -> Self {
        Self {
            shard: ShardVersion::V0(ShardV0 {
                device_id,
                seed_fingerprint,
                seed_shamir_share,
                seed_shamir_share_index,
                part_of_magic_backup,
            }),
            hmac: [0; 32],
        }
    }

    /// Get the Device ID from the Shard
    pub fn device_id(&self) -> &[u8; 32] {
        match &self.shard {
            ShardVersion::V0(shard) => &shard.device_id,
            ShardVersion::V1(shard) => &shard.device_id,
        }
    }

    /// Get the Seed Fingerprint from the Shard
    pub fn seed_fingerprint(&self) -> &[u8; 32] {
        match &self.shard {
            ShardVersion::V0(shard) => &shard.seed_fingerprint,
            ShardVersion::V1(shard) => &shard.seed_fingerprint,
        }
    }

    /// Get the Seed Shamir Share from the Shard
    pub fn seed_shamir_share(&self) -> &[u8] {
        match &self.shard {
            ShardVersion::V0(shard) => &shard.seed_shamir_share,
            ShardVersion::V1(shard) => &shard.seed_shamir_share,
        }
    }

    /// Get the Seed Shamir Share Index from the Shard
    pub fn seed_shamir_share_index(&self) -> usize {
        match &self.shard {
            ShardVersion::V0(shard) => shard.seed_shamir_share_index,
            ShardVersion::V1(shard) => shard.seed_shamir_share_index,
        }
    }

    /// Is the Shard part of a Magic Backup
    pub fn part_of_magic_backup(&self) -> bool {
        match &self.shard {
            ShardVersion::V0(shard) => shard.part_of_magic_backup,
            ShardVersion::V1(shard) => shard.part_of_magic_backup,
        }
    }

    /// Get the Timestamp from the Shard
    pub fn timestamp(&self) -> u32 {
        match &self.shard {
            ShardVersion::V1(shard) => shard.timestamp,
            ShardVersion::V0(_) => 0,
        }
    }

    /// Get the Scheme Threshold from the Shard
    pub fn scheme_threshold(&self) -> usize {
        match &self.shard {
            ShardVersion::V1(shard) => shard.scheme_threshold,
            ShardVersion::V0(_) => 2,
        }
    }

    /// Get the Scheme Share Count from the Shard
    pub fn scheme_share_count(&self) -> usize {
        match &self.shard {
            ShardVersion::V1(shard) => shard.scheme_share_count,
            ShardVersion::V0(_) => 3,
        }
    }

    /// Set the Timestamp of the Shard
    pub fn set_timestamp(&mut self, timestamp: u32) {
        match &mut self.shard {
            ShardVersion::V1(shard) => shard.timestamp = timestamp,
            ShardVersion::V0(_) => {
                self.shard = self.shard.clone().update();
                if let ShardVersion::V1(shard) = &mut self.shard {
                    shard.timestamp = timestamp;
                }
            }
        }
    }

    /// Set the Scheme Threshold of the Shard
    pub fn set_scheme_threshold(&mut self, scheme_threshold: usize) {
        match &mut self.shard {
            ShardVersion::V1(shard) => shard.scheme_threshold = scheme_threshold,
            ShardVersion::V0(_) => {
                self.shard = self.shard.clone().update();
                if let ShardVersion::V1(shard) = &mut self.shard {
                    shard.scheme_threshold = scheme_threshold;
                }
            }
        }
    }

    /// Set the Scheme Share Count of the Shard
    pub fn set_scheme_share_count(&mut self, scheme_share_count: usize) {
        match &mut self.shard {
            ShardVersion::V1(shard) => shard.scheme_share_count = scheme_share_count,
            ShardVersion::V0(_) => {
                self.shard = self.shard.clone().update();
                if let ShardVersion::V1(shard) = &mut self.shard {
                    shard.scheme_share_count = scheme_share_count;
                }
            }
        }
    }

    /// Get the HMAC from the Shard
    pub fn hmac(&self) -> &[u8; 32] {
        &self.hmac
    }

    /// Set the HMAC of a Shard
    pub fn set_hmac(&mut self, hmac: [u8; 32]) {
        self.hmac = hmac;
    }

    /// Returns the hash input for the hmac
    pub fn hmac_input(&self, uid: &[u8]) -> Vec<u8> {
        // Create the hash input: "Foundation KeyCard" || UID || data
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(Self::FOUNDATION_KEYCARD_PREFIX);
        hash_input.extend_from_slice(uid);
        hash_input.extend_from_slice(&self.shard.to_cbor_data());
        hash_input
    }

    /// Returns the encoded shard (official encoding is dcbor)
    pub fn encode(&self) -> Vec<u8> {
        self.to_cbor_data()
    }

    /// Returns the decoded shard (official encoding is dcbor)
    pub fn decode(data: &[u8]) -> Result<Shard, dcbor::Error> {
        let cbor = CBOR::try_from_data(data)?;
        cbor.try_into()
    }
}

// Conversion traits for Shard
impl From<Shard> for CBOR {
    fn from(shard: Shard) -> Self {
        let mut map = Map::new();
        map.insert(0u64, CBOR::from(shard.shard.clone()));
        map.insert(1u64, CBOR::to_byte_string(shard.hmac));
        map.into()
    }
}

impl TryFrom<CBOR> for Shard {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let case = cbor.into_case();
        let dcbor::CBORCase::Map(map) = case else {
            return Err(dcbor::Error::WrongType);
        };

        // Manually iterate through map entries to find values
        let mut shard: Option<ShardVersion> = None;
        let mut hmac: Option<[u8; 32]> = None;

        for (key, value) in map.iter() {
            let key_num: u64 = key.clone().try_into()?;
            match key_num {
                0 => shard = Some(value.clone().try_into()?),
                1 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        let mut hmac_array = [0u8; 32];
                        if b.len() == 32 {
                            hmac_array.copy_from_slice(&b);
                            hmac = Some(hmac_array);
                        } else {
                            return Err("HMAC must be 32 bytes".into());
                        }
                    }
                    _ => {
                        let hmac_bytes: Vec<u8> = value.clone().try_into()?;
                        let mut hmac_array = [0u8; 32];
                        hmac_array.copy_from_slice(&hmac_bytes);
                        hmac = Some(hmac_array);
                    }
                },
                _ => {}
            }
        }

        let shard = shard.ok_or(dcbor::Error::MissingMapKey)?;
        let hmac = hmac.ok_or(dcbor::Error::MissingMapKey)?;

        Ok(Shard { shard, hmac })
    }
}

#[derive(Debug, Clone, PartialEq, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum ShardVersion {
    V0(ShardV0),
    V1(ShardV1),
}

impl Default for ShardVersion {
    fn default() -> Self {
        ShardVersion::V1(ShardV1::default())
    }
}

impl ShardVersion {
    pub fn update(self) -> Self {
        match self {
            ShardVersion::V0(ref v0) => ShardVersion::V1(ShardV1 {
                device_id: v0.device_id,
                seed_fingerprint: v0.seed_fingerprint,
                seed_shamir_share: v0.seed_shamir_share.clone(),
                seed_shamir_share_index: v0.seed_shamir_share_index,
                part_of_magic_backup: v0.part_of_magic_backup,
                timestamp: 0,
                scheme_threshold: 2,
                scheme_share_count: 3,
            }),
            ShardVersion::V1(_) => self,
        }
    }
}

// Conversion traits for ShardVersion
impl From<ShardVersion> for CBOR {
    fn from(version: ShardVersion) -> Self {
        match version {
            ShardVersion::V0(ref shard) => {
                let array = vec![CBOR::from(ShardV0::VERSION), CBOR::from(shard.clone())];
                CBOR::from(array)
            }
            ShardVersion::V1(ref shard) => {
                let array = vec![CBOR::from(ShardV1::VERSION), CBOR::from(shard.clone())];
                CBOR::from(array)
            }
        }
    }
}

impl TryFrom<CBOR> for ShardVersion {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let array = cbor.try_into_array()?;
        if array.len() != 2 {
            return Err("Expected array of length 2".into());
        }

        let version: u8 = array[0].clone().try_into()?;
        let shard_cbor = array[1].clone();

        match version {
            ShardV0::VERSION => {
                let shard: ShardV0 = shard_cbor.try_into()?;
                Ok(ShardVersion::V0(shard))
            }
            ShardV1::VERSION => {
                let shard: ShardV1 = shard_cbor.try_into()?;
                Ok(ShardVersion::V1(shard))
            }
            _ => Err("Invalid Version".into()),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct ShardV0 {
    pub device_id: [u8; 32],
    pub seed_fingerprint: [u8; 32],
    pub seed_shamir_share: Vec<u8>,
    pub seed_shamir_share_index: usize,
    pub part_of_magic_backup: bool,
}

impl ShardV0 {
    pub const VERSION: u8 = 0;
}

// Conversion traits for ShardV0
impl From<ShardV0> for CBOR {
    fn from(shard: ShardV0) -> Self {
        let mut map = Map::new();
        map.insert(0u64, CBOR::to_byte_string(shard.device_id));
        map.insert(1u64, CBOR::to_byte_string(shard.seed_fingerprint));
        map.insert(2u64, CBOR::to_byte_string(shard.seed_shamir_share.clone()));
        map.insert(3u64, CBOR::from(shard.seed_shamir_share_index));
        map.insert(4u64, CBOR::from(shard.part_of_magic_backup));
        map.into()
    }
}

impl TryFrom<CBOR> for ShardV0 {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let map = cbor.try_into_map()?;

        let mut device_id_bytes: Option<Vec<u8>> = None;
        let mut seed_fingerprint_bytes: Option<Vec<u8>> = None;
        let mut seed_shamir_share: Option<Vec<u8>> = None;
        let mut seed_shamir_share_index: Option<usize> = None;
        let mut part_of_magic_backup: Option<bool> = None;

        for (key, value) in map.iter() {
            let key_num: u64 = key.clone().try_into()?;
            match key_num {
                0 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        device_id_bytes = Some(b.to_vec());
                    }
                    _ => {
                        device_id_bytes = Some(value.clone().try_into()?);
                    }
                },
                1 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        seed_fingerprint_bytes = Some(b.to_vec());
                    }
                    _ => {
                        seed_fingerprint_bytes = Some(value.clone().try_into()?);
                    }
                },
                2 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        seed_shamir_share = Some(b.to_vec());
                    }
                    _ => {
                        seed_shamir_share = Some(value.clone().try_into()?);
                    }
                },
                3 => {
                    seed_shamir_share_index = Some(value.clone().try_into()?);
                }
                4 => {
                    part_of_magic_backup = Some(value.clone().try_into()?);
                }
                _ => {}
            }
        }

        let device_id_bytes = device_id_bytes.ok_or(dcbor::Error::MissingMapKey)?;
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&device_id_bytes);

        let seed_fingerprint_bytes = seed_fingerprint_bytes.ok_or(dcbor::Error::MissingMapKey)?;
        let mut seed_fingerprint = [0u8; 32];
        seed_fingerprint.copy_from_slice(&seed_fingerprint_bytes);

        let seed_shamir_share = seed_shamir_share.ok_or(dcbor::Error::MissingMapKey)?;
        let seed_shamir_share_index = seed_shamir_share_index.ok_or(dcbor::Error::MissingMapKey)?;
        let part_of_magic_backup = part_of_magic_backup.ok_or(dcbor::Error::MissingMapKey)?;

        Ok(ShardV0 {
            device_id,
            seed_fingerprint,
            seed_shamir_share,
            seed_shamir_share_index,
            part_of_magic_backup,
        })
    }
}

#[derive(Debug, Clone, PartialEq, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "keyos",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct ShardV1 {
    pub device_id: [u8; 32],
    pub seed_fingerprint: [u8; 32],
    pub seed_shamir_share: Vec<u8>,
    pub seed_shamir_share_index: usize,
    pub part_of_magic_backup: bool,
    pub timestamp: u32,
    pub scheme_threshold: usize,
    pub scheme_share_count: usize,
}

impl ShardV1 {
    pub const VERSION: u8 = 1;
}

impl Default for ShardV1 {
    fn default() -> Self {
        Self {
            device_id: [0; 32],
            seed_fingerprint: [0; 32],
            seed_shamir_share: vec![],
            seed_shamir_share_index: 0,
            part_of_magic_backup: false,
            timestamp: 0,
            scheme_threshold: 2,
            scheme_share_count: 3,
        }
    }
}

// Conversion traits for ShardV1
impl From<ShardV1> for CBOR {
    fn from(shard: ShardV1) -> Self {
        let mut map = Map::new();
        map.insert(0u64, CBOR::to_byte_string(shard.device_id));
        map.insert(1u64, CBOR::to_byte_string(shard.seed_fingerprint));
        map.insert(2u64, CBOR::to_byte_string(shard.seed_shamir_share.clone()));
        map.insert(3u64, CBOR::from(shard.seed_shamir_share_index));
        map.insert(4u64, CBOR::from(shard.part_of_magic_backup));
        map.insert(5u64, CBOR::from(shard.timestamp));
        map.insert(6u64, CBOR::from(shard.scheme_threshold));
        map.insert(7u64, CBOR::from(shard.scheme_share_count));
        map.into()
    }
}

impl TryFrom<CBOR> for ShardV1 {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let map = cbor.try_into_map()?;

        let mut device_id_bytes: Option<Vec<u8>> = None;
        let mut seed_fingerprint_bytes: Option<Vec<u8>> = None;
        let mut seed_shamir_share: Option<Vec<u8>> = None;
        let mut seed_shamir_share_index: Option<usize> = None;
        let mut part_of_magic_backup: Option<bool> = None;
        let mut timestamp: Option<u32> = None;
        let mut scheme_threshold: Option<usize> = None;
        let mut scheme_share_count: Option<usize> = None;

        for (key, value) in map.iter() {
            let key_num: u64 = key.clone().try_into()?;
            match key_num {
                0 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        device_id_bytes = Some(b.to_vec());
                    }
                    _ => {
                        device_id_bytes = Some(value.clone().try_into()?);
                    }
                },
                1 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        seed_fingerprint_bytes = Some(b.to_vec());
                    }
                    _ => {
                        seed_fingerprint_bytes = Some(value.clone().try_into()?);
                    }
                },
                2 => match value.clone().into_case() {
                    dcbor::CBORCase::ByteString(b) => {
                        seed_shamir_share = Some(b.to_vec());
                    }
                    _ => {
                        seed_shamir_share = Some(value.clone().try_into()?);
                    }
                },
                3 => {
                    seed_shamir_share_index = Some(value.clone().try_into()?);
                }
                4 => {
                    part_of_magic_backup = Some(value.clone().try_into()?);
                }
                5 => {
                    timestamp = Some(value.clone().try_into()?);
                }
                6 => {
                    scheme_threshold = Some(value.clone().try_into()?);
                }
                7 => {
                    scheme_share_count = Some(value.clone().try_into()?);
                }
                _ => {}
            }
        }

        let device_id_bytes = device_id_bytes.ok_or(dcbor::Error::MissingMapKey)?;
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&device_id_bytes);

        let seed_fingerprint_bytes = seed_fingerprint_bytes.ok_or(dcbor::Error::MissingMapKey)?;
        let mut seed_fingerprint = [0u8; 32];
        seed_fingerprint.copy_from_slice(&seed_fingerprint_bytes);

        let seed_shamir_share = seed_shamir_share.ok_or(dcbor::Error::MissingMapKey)?;
        let seed_shamir_share_index = seed_shamir_share_index.ok_or(dcbor::Error::MissingMapKey)?;
        let part_of_magic_backup = part_of_magic_backup.ok_or(dcbor::Error::MissingMapKey)?;
        let timestamp = timestamp.ok_or(dcbor::Error::MissingMapKey)?;
        let scheme_threshold = scheme_threshold.ok_or(dcbor::Error::MissingMapKey)?;
        let scheme_share_count = scheme_share_count.ok_or(dcbor::Error::MissingMapKey)?;

        Ok(ShardV1 {
            device_id,
            seed_fingerprint,
            seed_shamir_share,
            seed_shamir_share_index,
            part_of_magic_backup,
            timestamp,
            scheme_threshold,
            scheme_share_count,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn v0_round_trip() {
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
        assert_eq!(encoded.len(), 121);
        let decoded = Shard::decode(&encoded);

        match decoded {
            Ok(decoded_shard) => {
                assert_eq!(shard, decoded_shard);
            }
            Err(e) => {
                panic!("Decoding failed: {e:?}");
            }
        }
    }

    #[test]
    fn v1_round_trip() {
        let shard = Shard {
            shard: ShardVersion::V1(ShardV1 {
                device_id: [0xAA; 32],
                seed_fingerprint: [0xBB; 32],
                seed_shamir_share: vec![1, 2, 3, 4, 5],
                seed_shamir_share_index: 2,
                part_of_magic_backup: true,
                timestamp: 1234567890,
                scheme_threshold: 3,
                scheme_share_count: 5,
            }),
            hmac: [0xCC; 32],
        };

        let encoded = shard.encode();
        assert_eq!(encoded.len(), 131); // Updated length for V1
        let decoded = Shard::decode(&encoded);

        match decoded {
            Ok(decoded_shard) => {
                assert_eq!(shard, decoded_shard);
            }
            Err(e) => {
                panic!("Decoding failed: {e:?}");
            }
        }
    }

    #[test]
    fn shard_version_round_trip() -> Result<(), dcbor::Error> {
        let shard_version = ShardVersion::V0(ShardV0 {
            device_id: [0xAA; 32],
            seed_fingerprint: [0xBB; 32],
            seed_shamir_share: vec![1, 2, 3, 4, 5],
            seed_shamir_share_index: 2,
            part_of_magic_backup: true,
        });

        let encoded = shard_version.to_cbor_data();
        assert_eq!(encoded.len(), 84);
        let cbor = CBOR::try_from_data(&encoded)?;
        let decoded: ShardVersion = cbor.try_into()?;

        assert_eq!(shard_version, decoded);
        Ok(())
    }

    #[test]
    fn shard_version_v1_round_trip() -> Result<(), dcbor::Error> {
        let shard_version = ShardVersion::V1(ShardV1 {
            device_id: [0xAA; 32],
            seed_fingerprint: [0xBB; 32],
            seed_shamir_share: vec![1, 2, 3, 4, 5],
            seed_shamir_share_index: 2,
            part_of_magic_backup: true,
            timestamp: 1234567890,
            scheme_threshold: 3,
            scheme_share_count: 5,
        });

        let encoded = shard_version.to_cbor_data();
        assert_eq!(encoded.len(), 94); // Updated length for V1
        let cbor = CBOR::try_from_data(&encoded)?;
        let decoded: ShardVersion = cbor.try_into()?;

        assert_eq!(shard_version, decoded);
        Ok(())
    }

    #[test]
    fn hmac_input() {
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

        let uid = [44, 55, 66];
        let expected = {
            let mut expected = vec![];
            expected.extend_from_slice(Shard::FOUNDATION_KEYCARD_PREFIX);
            expected.extend(&uid);
            expected.extend(&shard.shard.to_cbor_data());
            expected
        };

        let hmac_input = shard.hmac_input(&uid);

        assert_eq!(hmac_input, expected);
    }

    #[test]
    fn hmac_input_v1() {
        let shard = Shard {
            shard: ShardVersion::V1(ShardV1 {
                device_id: [0xAA; 32],
                seed_fingerprint: [0xBB; 32],
                seed_shamir_share: vec![1, 2, 3, 4, 5],
                seed_shamir_share_index: 2,
                part_of_magic_backup: true,
                timestamp: 1234567890,
                scheme_threshold: 3,
                scheme_share_count: 5,
            }),
            hmac: [0xCC; 32],
        };

        let uid = [44, 55, 66];
        let expected = {
            let mut expected = vec![];
            expected.extend_from_slice(Shard::FOUNDATION_KEYCARD_PREFIX);
            expected.extend(&uid);
            expected.extend(&shard.shard.to_cbor_data());
            expected
        };

        let hmac_input = shard.hmac_input(&uid);

        assert_eq!(hmac_input, expected);
    }
}
