use ql_common::QID;
use ql_wire::PairingToken;

ql_codec::codec! {
    /// Out-of-band invite consumed by the initiator of an XX pairing
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PairingInvite {
        pub version: u8,
        pub qid: QID,
        pub token: PairingToken,
    }
}

impl PairingInvite {
    pub const VERSION: u8 = 1;
}
