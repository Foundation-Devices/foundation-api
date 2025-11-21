//! golden/snapshot tests for QuantumLinkMessage codec
//!
//! to update snapshots when serialization intentionally changes:
//! ```
//! INSTA_UPDATE=always cargo test
//! ```

use dcbor::CBOR;
use foundation_api::{
    backup::*, bitcoin::*, firmware::*, fx::*, message::*, onboarding::*, pairing::*, passport::*,
    raw::*, scv::*, status::*,
};

/// convert a message to hex-encoded CBOR bytes
fn to_hex(message: &QuantumLinkMessage) -> String {
    let cbor: CBOR = message.clone().into();
    let bytes = cbor.to_cbor_data();
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// decode hex-encoded CBOR bytes back to a message
fn from_hex(hex: &str) -> QuantumLinkMessage {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let cbor = CBOR::try_from_data(&bytes).unwrap();
    QuantumLinkMessage::try_from(cbor).unwrap()
}

macro_rules! assert_golden {
    ($message:expr) => {{
        let message = $message;
        let hex = to_hex(&message);
        insta::assert_snapshot!(hex.clone());

        let decoded = from_hex(&hex);
        assert_eq!(message, decoded, "roundtrip decode failed");
    }};
}

#[test]
fn golden_exchange_rate() {
    assert_golden!(QuantumLinkMessage::ExchangeRate(ExchangeRate {
        currency_code: "USD".to_string(),
        rate: 42000.50,
        timestamp: 1700000000,
    }));
}

#[test]
fn golden_exchange_rate_history() {
    assert_golden!(QuantumLinkMessage::ExchangeRateHistory(
        ExchangeRateHistory {
            history: vec![
                PricePoint {
                    rate: 41000.0,
                    timestamp: 1699999900,
                },
                PricePoint {
                    rate: 42000.0,
                    timestamp: 1700000000,
                },
            ],
            currency_code: "EUR".to_string(),
        }
    ));
}

#[test]
fn golden_firmware_update_check_request() {
    assert_golden!(QuantumLinkMessage::FirmwareUpdateCheckRequest(
        FirmwareUpdateCheckRequest {
            current_version: "2.4.0".to_string(),
        },
    ));
}

#[test]
fn golden_firmware_update_check_response_available() {
    assert_golden!(QuantumLinkMessage::FirmwareUpdateCheckResponse(
        FirmwareUpdateCheckResponse::Available(FirmwareUpdateAvailable {
            version: "2.5.0".to_string(),
            changelog: "Bug fixes".to_string(),
            timestamp: 1700000000,
            total_size: 1024000,
            patch_count: 3,
        }),
    ));
}

#[test]
fn golden_firmware_update_check_response_not_available() {
    assert_golden!(QuantumLinkMessage::FirmwareUpdateCheckResponse(
        FirmwareUpdateCheckResponse::NotAvailable,
    ));
}

#[test]
fn golden_firmware_fetch_request() {
    assert_golden!(QuantumLinkMessage::FirmwareFetchRequest(
        FirmwareFetchRequest {
            current_version: "2.4.0".to_string(),
        },
    ));
}

#[test]
fn golden_firmware_fetch_event_not_available() {
    assert_golden!(QuantumLinkMessage::FirmwareFetchEvent(
        FirmwareFetchEvent::UpdateNotAvailable,
    ));
}

#[test]
fn golden_firmware_fetch_event_starting() {
    assert_golden!(QuantumLinkMessage::FirmwareFetchEvent(
        FirmwareFetchEvent::Starting(FirmwareUpdateAvailable {
            version: "2.5.0".to_string(),
            changelog: "New features".to_string(),
            timestamp: 1700000000,
            total_size: 2048000,
            patch_count: 5,
        }),
    ));
}

#[test]
fn golden_firmware_fetch_event_downloading() {
    assert_golden!(QuantumLinkMessage::FirmwareFetchEvent(
        FirmwareFetchEvent::Downloading,
    ));
}

#[test]
fn golden_firmware_fetch_event_chunk() {
    assert_golden!(QuantumLinkMessage::FirmwareFetchEvent(
        FirmwareFetchEvent::Chunk(FirmwareChunk {
            patch_index: 0,
            total_patches: 3,
            chunk_index: 5,
            total_chunks: 100,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        }),
    ));
}

#[test]
fn golden_firmware_fetch_event_error() {
    assert_golden!(QuantumLinkMessage::FirmwareFetchEvent(
        FirmwareFetchEvent::Error {
            error: "Download failed".to_string(),
        },
    ));
}

#[test]
fn golden_firmware_update_result_success() {
    assert_golden!(QuantumLinkMessage::FirmwareUpdateResult(
        FirmwareUpdateResult::Success {
            installed_version: "2.5.0".to_string(),
        },
    ));
}

#[test]
fn golden_firmware_update_result_error() {
    assert_golden!(QuantumLinkMessage::FirmwareUpdateResult(
        FirmwareUpdateResult::Error {
            error: "Installation failed".to_string(),
        },
    ));
}

#[test]
fn golden_device_status() {
    assert_golden!(QuantumLinkMessage::DeviceStatus(DeviceStatus {
        state: DeviceState::Normal,
        battery_level: 85,
        ble_signal: -45,
        version: "2.4.0".to_string(),
    }));
}

#[test]
fn golden_device_status_updating() {
    assert_golden!(QuantumLinkMessage::DeviceStatus(DeviceStatus {
        state: DeviceState::UpdatingFirmware,
        battery_level: 90,
        ble_signal: -30,
        version: "2.4.0".to_string(),
    }));
}

#[test]
fn golden_envoy_status() {
    assert_golden!(QuantumLinkMessage::EnvoyStatus(EnvoyStatus {
        state: EnvoyState::Normal,
        version: "1.0.0".to_string(),
    }));
}

#[test]
fn golden_pairing_request() {
    assert_golden!(QuantumLinkMessage::PairingRequest(PairingRequest {
        xid_document: vec![0x01, 0x02, 0x03, 0x04],
        device_name: "My iPhone".to_string(),
    }));
}

#[test]
fn golden_pairing_response() {
    assert_golden!(QuantumLinkMessage::PairingResponse(PairingResponse {
        passport_model: PassportModel::Prime,
        passport_firmware_version: PassportFirmwareVersion("2.4.0".to_string()),
        passport_serial: PassportSerial("ABC123".to_string()),
        passport_color: PassportColor::Dark,
        onboarding_complete: true,
    }));
}

#[test]
fn golden_onboarding_state_firmware_update_screen() {
    assert_golden!(QuantumLinkMessage::OnboardingState(
        OnboardingState::FirmwareUpdateScreen,
    ));
}

#[test]
fn golden_onboarding_state_completed() {
    assert_golden!(QuantumLinkMessage::OnboardingState(
        OnboardingState::Completed,
    ));
}

#[test]
fn golden_sign_psbt() {
    assert_golden!(QuantumLinkMessage::SignPsbt(SignPsbt {
        account_id: "account-1".to_string(),
        psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
    }));
}

#[test]
fn golden_broadcast_transaction() {
    assert_golden!(QuantumLinkMessage::BroadcastTransaction(
        BroadcastTransaction {
            account_id: "account-1".to_string(),
            psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
        },
    ));
}

#[test]
fn golden_account_update() {
    assert_golden!(QuantumLinkMessage::AccountUpdate(AccountUpdate {
        account_id: "account-1".to_string(),
        update: vec![0x01, 0x02, 0x03],
    }));
}

#[test]
fn golden_apply_passphrase_some() {
    assert_golden!(QuantumLinkMessage::ApplyPassphrase(ApplyPassphrase {
        fingerprint: Some("abc123".to_string()),
    }));
}

#[test]
fn golden_apply_passphrase_none() {
    assert_golden!(QuantumLinkMessage::ApplyPassphrase(ApplyPassphrase {
        fingerprint: None,
    }));
}

#[test]
fn golden_security_check_challenge_request() {
    assert_golden!(QuantumLinkMessage::SecurityCheck(
        SecurityCheck::ChallengeRequest(ChallengeRequest {
            data: vec![0xca, 0xfe, 0xba, 0xbe],
        }),
    ));
}

#[test]
fn golden_security_check_challenge_response_success() {
    assert_golden!(QuantumLinkMessage::SecurityCheck(
        SecurityCheck::ChallengeResponse(ChallengeResponseResult::Success {
            data: vec![0xde, 0xad, 0xbe, 0xef],
        }),
    ));
}

#[test]
fn golden_security_check_challenge_response_error() {
    assert_golden!(QuantumLinkMessage::SecurityCheck(
        SecurityCheck::ChallengeResponse(ChallengeResponseResult::Error {
            error: "Invalid signature".to_string(),
        }),
    ));
}

#[test]
fn golden_security_check_verification_success() {
    assert_golden!(QuantumLinkMessage::SecurityCheck(
        SecurityCheck::VerificationResult(VerificationResult::Success),
    ));
}

#[test]
fn golden_security_check_verification_error() {
    assert_golden!(QuantumLinkMessage::SecurityCheck(
        SecurityCheck::VerificationResult(VerificationResult::Error {
            error: "Verification failed".to_string(),
        }),
    ));
}

#[test]
fn golden_envoy_magic_backup_enabled_request() {
    assert_golden!(QuantumLinkMessage::EnvoyMagicBackupEnabledRequest(
        EnvoyMagicBackupEnabledRequest {},
    ));
}

#[test]
fn golden_envoy_magic_backup_enabled_response() {
    assert_golden!(QuantumLinkMessage::EnvoyMagicBackupEnabledResponse(
        EnvoyMagicBackupEnabledResponse { enabled: true },
    ));
}

#[test]
fn golden_prime_magic_backup_enabled() {
    assert_golden!(QuantumLinkMessage::PrimeMagicBackupEnabled(
        PrimeMagicBackupEnabled {
            enabled: true,
            seed_fingerprint: [0x42; 32],
        },
    ));
}

#[test]
fn golden_prime_magic_backup_status_request() {
    assert_golden!(QuantumLinkMessage::PrimeMagicBackupStatusRequest(
        PrimeMagicBackupStatusRequest {
            seed_fingerprint: [0xab; 32],
        },
    ));
}

#[test]
fn golden_prime_magic_backup_status_response() {
    assert_golden!(QuantumLinkMessage::PrimeMagicBackupStatusResponse(
        PrimeMagicBackupStatusResponse {
            shard_backup_found: true,
        },
    ));
}

#[test]
fn golden_backup_shard_request() {
    assert_golden!(QuantumLinkMessage::BackupShardRequest(BackupShardRequest {
        shard: Shard(vec![0x01, 0x02, 0x03, 0x04, 0x05]),
    }));
}

#[test]
fn golden_backup_shard_response_success() {
    assert_golden!(QuantumLinkMessage::BackupShardResponse(
        BackupShardResponse::Success,
    ));
}

#[test]
fn golden_backup_shard_response_error() {
    assert_golden!(QuantumLinkMessage::BackupShardResponse(
        BackupShardResponse::Error {
            error: "Storage full".to_string(),
        },
    ));
}

#[test]
fn golden_restore_shard_request() {
    assert_golden!(QuantumLinkMessage::RestoreShardRequest(
        RestoreShardRequest {
            seed_fingerprint: [0xcd; 32],
        },
    ));
}

#[test]
fn golden_restore_shard_response_success() {
    assert_golden!(QuantumLinkMessage::RestoreShardResponse(
        RestoreShardResponse::Success {
            shard: Shard(vec![0x0a, 0x0b, 0x0c]),
        },
    ));
}

#[test]
fn golden_restore_shard_response_error() {
    assert_golden!(QuantumLinkMessage::RestoreShardResponse(
        RestoreShardResponse::Error {
            error: "Not found".to_string(),
        },
    ));
}

#[test]
fn golden_restore_shard_response_not_found() {
    assert_golden!(QuantumLinkMessage::RestoreShardResponse(
        RestoreShardResponse::NotFound,
    ));
}

#[test]
fn golden_create_magic_backup_event_start() {
    assert_golden!(QuantumLinkMessage::CreateMagicBackupEvent(
        CreateMagicBackupEvent::Start(StartMagicBackup {
            seed_fingerprint: [0xef; 32],
            total_chunks: 100,
            hash: [0xaa; 32],
        }),
    ));
}

#[test]
fn golden_create_magic_backup_event_chunk() {
    assert_golden!(QuantumLinkMessage::CreateMagicBackupEvent(
        CreateMagicBackupEvent::Chunk(BackupChunk {
            chunk_index: 5,
            total_chunks: 100,
            data: vec![0x11, 0x22, 0x33],
        }),
    ));
}

#[test]
fn golden_create_magic_backup_result_success() {
    assert_golden!(QuantumLinkMessage::CreateMagicBackupResult(
        CreateMagicBackupResult::Success,
    ));
}

#[test]
fn golden_create_magic_backup_result_error() {
    assert_golden!(QuantumLinkMessage::CreateMagicBackupResult(
        CreateMagicBackupResult::Error {
            error: "Upload failed".to_string(),
        },
    ));
}

#[test]
fn golden_restore_magic_backup_request() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupRequest(
        RestoreMagicBackupRequest {
            seed_fingerprint: [0xbb; 32],
            resume_from_chunk: 50,
        },
    ));
}

#[test]
fn golden_restore_magic_backup_event_no_backup() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupEvent(
        RestoreMagicBackupEvent::NoBackupFound,
    ));
}

#[test]
fn golden_restore_magic_backup_event_starting() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupEvent(
        RestoreMagicBackupEvent::Starting(BackupMetadata { total_chunks: 200 }),
    ));
}

#[test]
fn golden_restore_magic_backup_event_chunk() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupEvent(
        RestoreMagicBackupEvent::Chunk(BackupChunk {
            chunk_index: 10,
            total_chunks: 50,
            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
        }),
    ));
}

#[test]
fn golden_restore_magic_backup_event_error() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupEvent(
        RestoreMagicBackupEvent::Error {
            error: "Network error".to_string(),
        },
    ));
}

#[test]
fn golden_restore_magic_backup_result_success() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupResult(
        RestoreMagicBackupResult::Success,
    ));
}

#[test]
fn golden_restore_magic_backup_result_error() {
    assert_golden!(QuantumLinkMessage::RestoreMagicBackupResult(
        RestoreMagicBackupResult::Error {
            error: "Checksum mismatch".to_string(),
        },
    ));
}

#[test]
fn golden_raw_data() {
    assert_golden!(QuantumLinkMessage::RawData(RawData {
        payload: vec![0xfe, 0xed, 0xfa, 0xce],
    }));
}
