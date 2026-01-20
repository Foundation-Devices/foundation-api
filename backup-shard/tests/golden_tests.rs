//! golden/snapshot tests for backup-shard crate
//!
//! to update snapshots when serialization intentionally changes:
//! ```
//! INSTA_UPDATE=always cargo test
//! ```

use backup_shard::Shard;
use dcbor::CBOR;

#[test]
fn golden_backup_shard_v0() {
    let shard = Shard {
        shard: backup_shard::ShardVersion::V0(backup_shard::ShardV0 {
            device_id: [0xAA; 32],
            seed_fingerprint: [0xBB; 32],
            seed_shamir_share: vec![1, 2, 3, 4, 5],
            seed_shamir_share_index: 2,
            part_of_magic_backup: true,
        }),
        hmac: [0xCC; 32],
    };

    let cbor: CBOR = shard.clone().into();
    let bytes = cbor.to_cbor_data();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

    insta::assert_snapshot!(hex.clone());

    let decoded_cbor = CBOR::try_from_data(&bytes).unwrap();
    let decoded_shard: Shard = decoded_cbor.try_into().unwrap();
    assert_eq!(shard, decoded_shard, "roundtrip decode failed");
}

#[test]
fn golden_backup_shard_v1() {
    let shard = Shard {
        shard: backup_shard::ShardVersion::V1(backup_shard::ShardV1 {
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

    let cbor: CBOR = shard.clone().into();
    let bytes = cbor.to_cbor_data();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

    insta::assert_snapshot!(hex.clone());

    let decoded_cbor = CBOR::try_from_data(&bytes).unwrap();
    let decoded_shard: Shard = decoded_cbor.try_into().unwrap();
    assert_eq!(shard, decoded_shard, "roundtrip decode failed");
}

#[test]
fn golden_backup_shard_version_v0() {
    let shard_version = backup_shard::ShardVersion::V0(backup_shard::ShardV0 {
        device_id: [0xAA; 32],
        seed_fingerprint: [0xBB; 32],
        seed_shamir_share: vec![1, 2, 3, 4, 5],
        seed_shamir_share_index: 2,
        part_of_magic_backup: true,
    });

    let cbor: CBOR = shard_version.clone().into();
    let bytes = cbor.to_cbor_data();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

    insta::assert_snapshot!(hex.clone());

    let decoded_cbor = CBOR::try_from_data(&bytes).unwrap();
    let decoded_version: backup_shard::ShardVersion = decoded_cbor.try_into().unwrap();
    assert_eq!(shard_version, decoded_version, "roundtrip decode failed");
}

#[test]
fn golden_backup_shard_version_v1() {
    let shard_version = backup_shard::ShardVersion::V1(backup_shard::ShardV1 {
        device_id: [0xAA; 32],
        seed_fingerprint: [0xBB; 32],
        seed_shamir_share: vec![1, 2, 3, 4, 5],
        seed_shamir_share_index: 2,
        part_of_magic_backup: true,
        timestamp: 1234567890,
        scheme_threshold: 3,
        scheme_share_count: 5,
    });

    let cbor: CBOR = shard_version.clone().into();
    let bytes = cbor.to_cbor_data();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

    insta::assert_snapshot!(hex.clone());

    let decoded_cbor = CBOR::try_from_data(&bytes).unwrap();
    let decoded_version: backup_shard::ShardVersion = decoded_cbor.try_into().unwrap();
    assert_eq!(shard_version, decoded_version, "roundtrip decode failed");
}

#[test]
fn golden_backup_shard_hmac_input() {
    let shard = Shard {
        shard: backup_shard::ShardVersion::V0(backup_shard::ShardV0 {
            device_id: [0xAA; 32],
            seed_fingerprint: [0xBB; 32],
            seed_shamir_share: vec![1, 2, 3, 4, 5],
            seed_shamir_share_index: 2,
            part_of_magic_backup: true,
        }),
        hmac: [0xCC; 32],
    };

    let uid = [44, 55, 66];
    let hmac_input = shard.hmac_input(&uid);
    let hex = hmac_input
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    insta::assert_snapshot!(hex);
}

#[test]
fn golden_backup_shard_hmac_input_v1() {
    let shard = Shard {
        shard: backup_shard::ShardVersion::V1(backup_shard::ShardV1 {
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
    let hmac_input = shard.hmac_input(&uid);
    let hex = hmac_input
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    insta::assert_snapshot!(hex);
}
