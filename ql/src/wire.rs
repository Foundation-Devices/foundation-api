use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, EncryptedMessage, Signature, SigningPublicKey,
    ARID, XID,
};
use dcbor::CBOR;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Event,
    SessionReset,
    Pairing,
    Nack,
    Heartbeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nack {
    Unknown,
    UnknownMessage,
    InvalidPayload,
}

#[derive(Debug, Clone)]
pub struct QlHeader {
    pub kind: MessageKind,
    pub sender: XID,
    pub recipient: XID,
    pub kem_ct: Option<EncapsulationCiphertext>,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone)]
pub struct QlEnvelope {
    pub id: ARID,
    pub valid_until: u64,
    pub message_id: u64,
    pub payload: CBOR,
}

#[derive(Debug, Clone)]
pub struct QlDetails {
    pub kind: MessageKind,
    pub id: ARID,
    pub message_id: u64,
    pub sender: XID,
    pub recipient: XID,
    pub valid_until: u64,
}

#[derive(Debug, Clone)]
pub struct QlMessage {
    pub header: QlHeader,
    pub payload: EncryptedMessage,
}

impl QlHeader {
    pub fn aad_data(&self) -> Vec<u8> {
        header_cbor_unsigned(self.kind, self.sender, self.recipient, self.kem_ct.clone())
            .to_cbor_data()
    }
}

impl From<QlHeader> for CBOR {
    fn from(value: QlHeader) -> Self {
        header_cbor(
            value.kind,
            value.sender,
            value.recipient,
            value.kem_ct,
            value.signature,
        )
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [kind_cbor, sender_cbor, recipient_cbor, kem_ct_cbor, signature_cbor] =
            cbor_array::<5>(array)?;
        let kind = kind_cbor.try_into()?;
        let sender = sender_cbor.try_into()?;
        let recipient = recipient_cbor.try_into()?;
        let kem_ct = option_from_cbor(kem_ct_cbor)?;
        let signature = option_from_cbor(signature_cbor)?;
        Ok(Self {
            kind,
            sender,
            recipient,
            kem_ct,
            signature,
        })
    }
}

impl From<QlEnvelope> for CBOR {
    fn from(value: QlEnvelope) -> Self {
        CBOR::from(vec![
            CBOR::from(value.id),
            CBOR::from(value.valid_until),
            CBOR::from(value.message_id),
            value.payload,
        ])
    }
}

impl TryFrom<CBOR> for QlEnvelope {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [id_cbor, valid_until_cbor, message_id_cbor, payload] = cbor_array::<4>(array)?;
        Ok(Self {
            id: id_cbor.try_into()?,
            valid_until: valid_until_cbor.try_into()?,
            message_id: message_id_cbor.try_into()?,
            payload,
        })
    }
}

impl QlDetails {
    pub fn from_parts(header: &QlHeader, envelope: &QlEnvelope) -> Self {
        Self {
            kind: header.kind,
            id: envelope.id,
            message_id: envelope.message_id,
            sender: header.sender,
            recipient: header.recipient,
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
            MessageKind::SessionReset => 4,
            MessageKind::Pairing => 5,
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
            4 => Ok(MessageKind::SessionReset),
            5 => Ok(MessageKind::Pairing),
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
            Nack::UnknownMessage => 1,
            Nack::InvalidPayload => 2,
        };
        CBOR::from(value)
    }
}

impl TryFrom<CBOR> for Nack {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(match value {
            1 => Nack::UnknownMessage,
            2 => Nack::InvalidPayload,
            _ => Nack::Unknown,
        })
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error(transparent)]
    Cbor(#[from] dcbor::Error),
}

#[derive(Debug)]
pub struct DecodeErrContext {
    pub error: DecodeError,
    pub header: Option<QlHeader>,
}

pub fn encode_ql_message(header: QlHeader, payload: EncryptedMessage) -> Vec<u8> {
    let cbor = CBOR::from(vec![CBOR::from(header), CBOR::from(payload)]);
    cbor.to_cbor_data()
}

pub fn decode_ql_message(bytes: &[u8]) -> Result<QlMessage, DecodeErrContext> {
    let cbor = dcbor::CBOR::try_from_data(bytes).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let array = cbor.try_into_array().map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let [header_cbor, payload_cbor] = cbor_array::<2>(array).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let header = QlHeader::try_from(header_cbor).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let payload: EncryptedMessage = payload_cbor.try_into().map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: Some(header.clone()),
    })?;
    Ok(QlMessage { header, payload })
}

#[derive(Debug, Clone)]
pub(crate) struct PairingPayload {
    pub(crate) signing_pub_key: SigningPublicKey,
    pub(crate) encapsulation_pub_key: EncapsulationPublicKey,
    pub(crate) proof: Signature,
}

impl From<PairingPayload> for CBOR {
    fn from(value: PairingPayload) -> Self {
        CBOR::from(vec![
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
        let [signing_pub_key, encapsulation_pub_key, proof] = cbor_array::<3>(array)?;
        Ok(Self {
            signing_pub_key: signing_pub_key.try_into()?,
            encapsulation_pub_key: encapsulation_pub_key.try_into()?,
            proof: proof.try_into()?,
        })
    }
}

fn option_to_cbor<T>(value: Option<T>) -> CBOR
where
    T: Into<CBOR>,
{
    value.map_or_else(CBOR::null, Into::into)
}

fn option_from_cbor<T>(value: CBOR) -> Result<Option<T>, dcbor::Error>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(T::try_from(value)?))
    }
}

fn cbor_array<const N: usize>(array: Vec<CBOR>) -> Result<[CBOR; N], dcbor::Error> {
    if array.len() != N {
        return Err(dcbor::Error::msg("invalid array length"));
    }
    array
        .try_into()
        .map_err(|_| dcbor::Error::msg("invalid array length"))
}

fn header_cbor(
    kind: MessageKind,
    sender: XID,
    recipient: XID,
    kem_ct: Option<EncapsulationCiphertext>,
    signature: Option<Signature>,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(kind),
        CBOR::from(sender),
        CBOR::from(recipient),
        option_to_cbor(kem_ct),
        option_to_cbor(signature),
    ])
}

fn header_cbor_unsigned(
    kind: MessageKind,
    sender: XID,
    recipient: XID,
    kem_ct: Option<EncapsulationCiphertext>,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(kind),
        CBOR::from(sender),
        CBOR::from(recipient),
        option_to_cbor(kem_ct),
    ])
}
