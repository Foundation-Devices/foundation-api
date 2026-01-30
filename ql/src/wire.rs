use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, Signature, SigningPublicKey, XID,
};
use dcbor::CBOR;

use crate::{MessageId, RouteId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Event,
    Nack,
    Heartbeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nack {
    Unknown,
    UnknownRoute,
    InvalidPayload,
    Expired,
}

/// public, un-encrypted message header
/// contents are verified during decryption
/// contains minimal data necessary for request routing
#[derive(Debug, Clone)]
pub enum QlHeader {
    Pairing {
        sender: XID,
        recipient: XID,
        kem_ct: EncapsulationCiphertext,
    },
    SessionReset {
        sender: XID,
        recipient: XID,
        kem_ct: EncapsulationCiphertext,
        signature: Signature,
    },
    Normal {
        sender: XID,
        recipient: XID,
        session: SessionState,
    },
}

#[derive(Debug, Clone)]
pub enum SessionState {
    Established,
    Init {
        kem_ct: EncapsulationCiphertext,
        signature: Signature,
    },
}

/// private, encrypted message envelope
/// contains sensitive message contents
#[derive(Debug, Clone)]
pub struct QlEnvelope {
    pub message_id: MessageId,
    pub valid_until: u64,
    pub kind: MessageKind,
    pub route_id: RouteId,
    pub payload: CBOR,
}

/// private, encrypted session control payload
#[derive(Debug, Clone)]
pub struct SessionPayload {
    pub message_id: MessageId,
    pub valid_until: u64,
}

/// aggregated request information
/// from unencrypted/encrypted wrappers
#[derive(Debug, Clone)]
pub struct QlDetails {
    pub kind: MessageKind,
    pub message_id: MessageId,
    pub route_id: RouteId,
    pub sender: XID,
    pub recipient: XID,
    pub valid_until: u64,
}

#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub header: QlHeader,
    pub encrypted: bc_components::EncryptedMessage,
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub header: QlDetails,
    pub payload: CBOR,
}

impl From<EncryptedMessage> for CBOR {
    fn from(value: EncryptedMessage) -> Self {
        CBOR::from(vec![CBOR::from(value.header), CBOR::from(value.encrypted)])
    }
}

impl TryFrom<CBOR> for EncryptedMessage {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let array = cbor.try_into_array()?;
        let [header_cbor, payload_cbor] = cbor_array::<2>(array)?;
        let header = QlHeader::try_from(header_cbor)?;
        let encrypted = payload_cbor.try_into()?;
        Ok(EncryptedMessage { header, encrypted })
    }
}

impl QlHeader {
    pub fn sender(&self) -> XID {
        match self {
            Self::Pairing { sender, .. }
            | Self::SessionReset { sender, .. }
            | Self::Normal { sender, .. } => *sender,
        }
    }

    pub fn recipient(&self) -> XID {
        match self {
            Self::Pairing { recipient, .. }
            | Self::SessionReset { recipient, .. }
            | Self::Normal { recipient, .. } => *recipient,
        }
    }

    pub fn aad_data(&self) -> Vec<u8> {
        match self {
            Self::Pairing {
                sender,
                recipient,
                kem_ct,
            } => header_cbor_pairing(*sender, *recipient, kem_ct.clone()).to_cbor_data(),
            Self::SessionReset {
                sender,
                recipient,
                kem_ct,
                ..
            } => header_cbor_session_reset_unsigned(*sender, *recipient, kem_ct.clone())
                .to_cbor_data(),
            Self::Normal {
                sender,
                recipient,
                session,
            } => match session {
                SessionState::Established => header_cbor_normal(*sender, *recipient).to_cbor_data(),
                SessionState::Init { kem_ct, .. } => {
                    header_cbor_normal_init_unsigned(*sender, *recipient, kem_ct.clone())
                        .to_cbor_data()
                }
            },
        }
    }

    pub fn normal_init_aad(
        sender: XID,
        recipient: XID,
        kem_ct: &EncapsulationCiphertext,
    ) -> Vec<u8> {
        header_cbor_normal_init_unsigned(sender, recipient, kem_ct.clone()).to_cbor_data()
    }

    pub fn session_reset_aad(
        sender: XID,
        recipient: XID,
        kem_ct: &EncapsulationCiphertext,
    ) -> Vec<u8> {
        header_cbor_session_reset_unsigned(sender, recipient, kem_ct.clone()).to_cbor_data()
    }

    pub fn has_new_session(&self) -> bool {
        match self {
            Self::Pairing { .. } | Self::SessionReset { .. } => true,
            Self::Normal { session, .. } => matches!(session, SessionState::Init { .. }),
        }
    }
}

impl From<QlHeader> for CBOR {
    fn from(value: QlHeader) -> Self {
        match value {
            QlHeader::Pairing {
                sender,
                recipient,
                kem_ct,
            } => header_cbor_pairing(sender, recipient, kem_ct),
            QlHeader::SessionReset {
                sender,
                recipient,
                kem_ct,
                signature,
            } => header_cbor_session_reset(sender, recipient, kem_ct, signature),
            QlHeader::Normal {
                sender,
                recipient,
                session,
            } => match session {
                SessionState::Established => header_cbor_normal(sender, recipient),
                SessionState::Init { kem_ct, signature } => {
                    header_cbor_normal_init(sender, recipient, kem_ct, signature)
                }
            },
        }
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let tag = array
            .first()
            .cloned()
            .ok_or_else(|| dcbor::Error::msg("missing header tag"))?;
        let tag: u8 = tag.try_into()?;
        match tag {
            0 => {
                let [_tag, sender_cbor, recipient_cbor] = cbor_array::<3>(array)?;
                Ok(Self::Normal {
                    sender: sender_cbor.try_into()?,
                    recipient: recipient_cbor.try_into()?,
                    session: SessionState::Established,
                })
            }
            1 => {
                let [_tag, sender_cbor, recipient_cbor, kem_ct_cbor, signature_cbor] =
                    cbor_array::<5>(array)?;
                Ok(Self::Normal {
                    sender: sender_cbor.try_into()?,
                    recipient: recipient_cbor.try_into()?,
                    session: SessionState::Init {
                        kem_ct: kem_ct_cbor.try_into()?,
                        signature: signature_cbor.try_into()?,
                    },
                })
            }
            2 => {
                let [_tag, sender_cbor, recipient_cbor, kem_ct_cbor] = cbor_array::<4>(array)?;
                Ok(Self::Pairing {
                    sender: sender_cbor.try_into()?,
                    recipient: recipient_cbor.try_into()?,
                    kem_ct: kem_ct_cbor.try_into()?,
                })
            }
            3 => {
                let [_tag, sender_cbor, recipient_cbor, kem_ct_cbor, signature_cbor] =
                    cbor_array::<5>(array)?;
                Ok(Self::SessionReset {
                    sender: sender_cbor.try_into()?,
                    recipient: recipient_cbor.try_into()?,
                    kem_ct: kem_ct_cbor.try_into()?,
                    signature: signature_cbor.try_into()?,
                })
            }
            _ => Err(dcbor::Error::msg("unknown header tag")),
        }
    }
}

impl From<QlEnvelope> for CBOR {
    fn from(value: QlEnvelope) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
            CBOR::from(value.kind),
            CBOR::from(value.route_id),
            value.payload,
        ])
    }
}

impl TryFrom<CBOR> for QlEnvelope {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [id_cbor, valid_until_cbor, kind_cbor, message_id_cbor, payload] =
            cbor_array::<5>(array)?;
        Ok(Self {
            message_id: id_cbor.try_into()?,
            valid_until: valid_until_cbor.try_into()?,
            kind: kind_cbor.try_into()?,
            route_id: message_id_cbor.try_into()?,
            payload,
        })
    }
}

impl From<SessionPayload> for CBOR {
    fn from(value: SessionPayload) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
        ])
    }
}

impl TryFrom<CBOR> for SessionPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [id_cbor, valid_until_cbor] = cbor_array::<2>(array)?;
        Ok(Self {
            message_id: id_cbor.try_into()?,
            valid_until: valid_until_cbor.try_into()?,
        })
    }
}

impl QlDetails {
    pub fn from_parts(header: &QlHeader, envelope: &QlEnvelope) -> Self {
        Self {
            kind: envelope.kind,
            message_id: envelope.message_id,
            route_id: envelope.route_id,
            sender: header.sender(),
            recipient: header.recipient(),
            valid_until: envelope.valid_until,
        }
    }
}

impl From<MessageKind> for CBOR {
    fn from(value: MessageKind) -> Self {
        let kind = match value {
            MessageKind::Request => 1,
            MessageKind::Response => 2,
            MessageKind::Event => 3,
            MessageKind::Nack => 6,
            MessageKind::Heartbeat => 7,
        };
        CBOR::from(kind)
    }
}

impl TryFrom<CBOR> for MessageKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let kind: u64 = value.try_into()?;
        match kind {
            1 => Ok(MessageKind::Request),
            2 => Ok(MessageKind::Response),
            3 => Ok(MessageKind::Event),
            6 => Ok(MessageKind::Nack),
            7 => Ok(MessageKind::Heartbeat),
            _ => Err(dcbor::Error::msg("unknown message kind")),
        }
    }
}

impl From<Ack> for CBOR {
    fn from(_value: Ack) -> Self {
        CBOR::null()
    }
}

impl TryFrom<CBOR> for Ack {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        if value.is_null() {
            Ok(Self)
        } else {
            Err(dcbor::Error::msg("expected null"))
        }
    }
}

impl From<Nack> for CBOR {
    fn from(value: Nack) -> Self {
        let value = match value {
            Nack::Unknown => 0,
            Nack::UnknownRoute => 1,
            Nack::InvalidPayload => 2,
            Nack::Expired => 3,
        };
        CBOR::from(value)
    }
}

impl From<CBOR> for Nack {
    fn from(value: CBOR) -> Self {
        let value: u8 = value.try_into().unwrap_or_default();
        match value {
            1 => Nack::UnknownRoute,
            2 => Nack::InvalidPayload,
            3 => Nack::Expired,
            _ => Nack::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PairingPayload {
    pub(crate) message_id: MessageId,
    pub(crate) valid_until: u64,
    pub(crate) signing_pub_key: SigningPublicKey,
    pub(crate) encapsulation_pub_key: EncapsulationPublicKey,
    pub(crate) proof: Signature,
}

impl From<PairingPayload> for CBOR {
    fn from(value: PairingPayload) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
            CBOR::from(value.signing_pub_key),
            CBOR::from(value.encapsulation_pub_key),
            CBOR::from(value.proof),
        ])
    }
}

impl TryFrom<CBOR> for PairingPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [message_id, valid_until, signing_pub_key, encapsulation_pub_key, proof] =
            cbor_array::<5>(array)?;
        Ok(Self {
            message_id: message_id.try_into()?,
            valid_until: valid_until.try_into()?,
            signing_pub_key: signing_pub_key.try_into()?,
            encapsulation_pub_key: encapsulation_pub_key.try_into()?,
            proof: proof.try_into()?,
        })
    }
}

fn header_cbor_pairing(sender: XID, recipient: XID, kem_ct: EncapsulationCiphertext) -> CBOR {
    CBOR::from(vec![
        CBOR::from(2u8),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(kem_ct),
    ])
}

fn header_cbor_session_reset(
    sender: XID,
    recipient: XID,
    kem_ct: EncapsulationCiphertext,
    signature: Signature,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(3u8),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(kem_ct),
        CBOR::from(signature),
    ])
}

fn header_cbor_session_reset_unsigned(
    sender: XID,
    recipient: XID,
    kem_ct: EncapsulationCiphertext,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(3u8),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(kem_ct),
    ])
}

fn header_cbor_normal(sender: XID, recipient: XID) -> CBOR {
    CBOR::from(vec![
        CBOR::from(0u8),
        CBOR::from(sender),
        CBOR::from(recipient),
    ])
}

fn header_cbor_normal_init(
    sender: XID,
    recipient: XID,
    kem_ct: EncapsulationCiphertext,
    signature: Signature,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(1u8),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(kem_ct),
        CBOR::from(signature),
    ])
}

fn header_cbor_normal_init_unsigned(
    sender: XID,
    recipient: XID,
    kem_ct: EncapsulationCiphertext,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(1u8),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(kem_ct),
    ])
}

fn cbor_array<const N: usize>(array: Vec<CBOR>) -> Result<[CBOR; N], dcbor::Error> {
    if array.len() != N {
        return Err(dcbor::Error::msg("invalid array length"));
    }
    array
        .try_into()
        .map_err(|_| dcbor::Error::msg("invalid array length"))
}
