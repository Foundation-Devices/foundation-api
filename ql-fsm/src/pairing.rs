use ql_common::QID;
use ql_wire::PairingToken;

/// Out-of-band invite consumed by the initiator of an XX pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingInvite {
    pub qid: QID,
    pub token: PairingToken,
}
