use std::time::Duration;

use bc_components::{EncapsulationScheme, PrivateKeys, PublicKeys, SignatureScheme, ARID};
use bc_envelope::{
    prelude::{CBORCase, CBOR},
    Envelope, EventBehavior, Expression, ExpressionBehavior, Function,
};
use bc_xid::XIDDocument;
use chrono::{DateTime, Utc};
use dcbor::Date;
use gstp::{SealedEvent, SealedEventBehavior};

use crate::message::{EnvoyMessage, PassportMessage};

pub const QUANTUM_LINK: Function = Function::new_static_named("quantumLink");
pub const EXPIRATION_DURATION: Duration = Duration::from_secs(60);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReplayCheck {
    Fresh,
    Replay,
    Expired,
}

/// Storage for tracking received ARIDs to prevent replay attacks
#[derive(Debug, Default, Clone)]
pub struct ARIDCache {
    cache: Vec<(ARID, DateTime<Utc>)>,
}

impl ARIDCache {
    pub fn new() -> Self {
        Self { cache: Vec::new() }
    }

    /// Check if ARID has been seen before and store it until the event expires.
    pub fn check_and_store(
        &mut self,
        arid: &ARID,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> ReplayCheck {
        // Clean up expired entries first
        self.cache.retain(|(_, expires_at)| now < *expires_at);

        if now >= expires_at {
            return ReplayCheck::Expired;
        }

        // Check if ARID already exists (replay attack)
        if self.cache.iter().any(|(id, _)| id == arid) {
            return ReplayCheck::Replay;
        }

        self.cache.push((*arid, expires_at));
        ReplayCheck::Fresh
    }

    /// Get the number of stored ARIDs
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.len() == 0
    }

    /// Clear all stored ARIDs
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QlError {
    #[error(transparent)]
    Cbor(#[from] dcbor::Error),
    #[error(transparent)]
    Envelope(#[from] bc_envelope::Error),
    #[error(transparent)]
    Gstp(#[from] gstp::Error),

    #[error("envelope did not contain leaf")]
    NotLeaf,
    #[error("missing date")]
    MissingDate,
    #[error("invalid function")]
    InvalidFunction,
    #[error("replay attack")]
    ReplayAttack,
    #[error("expired")]
    Expired,
    #[error("date too far in the future")]
    FutureDated,
}

pub trait QuantumLink: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {
    fn encode(self) -> Expression {
        let cbor: CBOR = self.into();
        let envelope = Envelope::new(cbor);
        Expression::new(QUANTUM_LINK).with_parameter("ql", envelope)
    }

    fn decode(expression: &Expression) -> Result<Self, QlError> {
        if expression.function() != &QUANTUM_LINK {
            return Err(QlError::InvalidFunction);
        }
        let envelope = expression.object_for_parameter("ql")?;
        let cbor = envelope.as_leaf().ok_or(QlError::NotLeaf)?;

        let message = Self::try_from(cbor)?;
        Ok(message)
    }

    fn seal(
        self,
        (sender_pk, sender_xid): (&PrivateKeys, &XIDDocument),
        recipient: &XIDDocument,
    ) -> Envelope {
        let valid_until = Date::with_duration_from_now(EXPIRATION_DURATION);

        let event: SealedEvent<Expression> =
            SealedEvent::new(QuantumLink::encode(self), ARID::new(), sender_xid)
                .with_date(&valid_until);
        event
            .to_envelope(Some(&valid_until), Some(sender_pk), Some(recipient))
            .unwrap()
    }

    fn unseal(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
    ) -> Result<(Expression, XIDDocument), QlError> {
        let now = Utc::now();
        let event: SealedEvent<Expression> =
            SealedEvent::try_from_envelope(envelope, None, Some(&Date::from(now)), private_keys)?;
        let expires_at = event.date().ok_or(QlError::MissingDate)?.datetime();
        validate_expires_at(expires_at, now)?;

        let expression = event.content().clone();
        Ok((expression, event.sender().clone()))
    }

    fn unseal_with_replay_check(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
        arid_cache: &mut ARIDCache,
    ) -> Result<(Expression, XIDDocument), QlError> {
        let now = Utc::now();
        let event: SealedEvent<Expression> =
            SealedEvent::try_from_envelope(envelope, None, Some(&Date::from(now)), private_keys)?;

        let arid = event.id();
        let expires_at = event.date().ok_or(QlError::MissingDate)?.datetime();
        validate_expires_at(expires_at, now)?;

        match arid_cache.check_and_store(&arid, expires_at, now) {
            ReplayCheck::Fresh => {}
            ReplayCheck::Replay => return Err(QlError::ReplayAttack),
            ReplayCheck::Expired => return Err(QlError::Expired),
        }

        let expression = event.content().clone();
        Ok((expression, event.sender().clone()))
    }

    fn unseal_passport_message_with_replay_check(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
        arid_cache: &mut ARIDCache,
    ) -> Result<(PassportMessage, XIDDocument), QlError> {
        let (expression, sender) =
            PassportMessage::unseal_with_replay_check(envelope, private_keys, arid_cache)?;
        Ok((PassportMessage::decode(&expression)?, sender))
    }

    fn unseal_envoy_message_with_replay_check(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
        arid_cache: &mut ARIDCache,
    ) -> Result<(EnvoyMessage, XIDDocument), QlError> {
        let (expression, sender) =
            EnvoyMessage::unseal_with_replay_check(envelope, private_keys, arid_cache)?;
        Ok((EnvoyMessage::decode(&expression)?, sender))
    }
}

impl<T> QuantumLink for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "envoy", flutter_rust_bridge::frb(opaque))]
pub struct QuantumLinkIdentity {
    pub private_keys: Option<PrivateKeys>,
    pub xid_document: XIDDocument,
}

impl QuantumLinkIdentity {
    pub fn generate() -> Self {
        let (signing_private_key, signing_public_key) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private_key, encapsulation_public_key) =
            EncapsulationScheme::MLKEM512.keypair();

        let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
        let public_keys = PublicKeys::new(signing_public_key, encapsulation_public_key);

        let xid_document = XIDDocument::from(public_keys);

        QuantumLinkIdentity {
            private_keys: Some(private_keys),
            xid_document,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut map = bc_envelope::prelude::Map::new();
        map.insert(CBOR::from("xid_document"), self.clone().xid_document);
        if self.private_keys.is_some() {
            map.insert(
                CBOR::from("private_keys"),
                self.clone().private_keys.unwrap(),
            );
        }

        CBOR::from(map).to_cbor_data()
    }

    pub fn from_bytes(bytes: &[u8]) -> dcbor::Result<Self> {
        let cbor = CBOR::try_from_data(bytes)?;
        let case = cbor.into_case();

        let CBORCase::Map(map) = case else {
            return Err(dcbor::Error::WrongType);
        };

        Ok(QuantumLinkIdentity {
            xid_document: map.get("xid_document").ok_or(dcbor::Error::MissingMapKey)?,
            private_keys: map.get("private_keys"),
        })
    }
}

fn expiration_duration() -> chrono::Duration {
    chrono::Duration::from_std(EXPIRATION_DURATION).expect("expiration duration must fit chrono")
}

fn validate_expires_at(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Result<(), QlError> {
    if now >= expires_at {
        return Err(QlError::Expired);
    }

    if expires_at > now + expiration_duration() {
        return Err(QlError::FutureDated);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{
            message::{QuantumLinkMessage, PROTOCOL_VERSION},
            quantum_link::QuantumLink,
        },
        fx::ExchangeRate,
        message::EnvoyMessage,
        quantum_link::{ARIDCache, QlError, QuantumLinkIdentity},
    };

    #[test]
    fn accepts_fresh_and_rejects_immediate_replay() {
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let mut arid_cache = ARIDCache::new();

        let original_message = exchange_rate_envoy_message();
        let envelope = QuantumLink::seal(
            original_message.clone(),
            (envoy.private_keys.as_ref().unwrap(), &envoy.xid_document),
            &passport.xid_document,
        );

        let (decoded, _sender) = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope,
            &passport.private_keys.clone().unwrap(),
            &mut arid_cache,
        )
        .unwrap();
        assert_exchange_rate_matches(&original_message, &decoded);

        let result2 = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope,
            &passport.private_keys.unwrap(),
            &mut arid_cache,
        );
        assert!(matches!(result2, Err(QlError::ReplayAttack)));
    }

    #[test]
    fn rejects_expired_envelope() {
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let mut arid_cache = ARIDCache::new();
        let expired_at = Utc::now() - chrono::Duration::seconds(1);

        let envelope = seal_envoy_message_with_expiration(
            exchange_rate_envoy_message(),
            &envoy,
            &passport,
            expired_at,
        );

        let replay_checked_result = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope,
            &passport.private_keys.unwrap(),
            &mut arid_cache,
        );
        assert!(matches!(replay_checked_result, Err(QlError::Expired)));
    }

    #[test]
    fn rejects_future_dated_envelope() {
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let mut arid_cache = ARIDCache::new();
        let expires_at = Utc::now() + expiration_duration() + chrono::Duration::seconds(1);

        let envelope = seal_envoy_message_with_expiration(
            exchange_rate_envoy_message(),
            &envoy,
            &passport,
            expires_at,
        );

        let result = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope,
            &passport.private_keys.unwrap(),
            &mut arid_cache,
        );
        assert!(matches!(result, Err(QlError::FutureDated)));
    }

    #[test]
    fn arid_cache_reports_replay_and_expiration() {
        let mut cache = ARIDCache::new();
        let arid1 = ARID::new();
        let arid2 = ARID::new();

        let start = chrono::Utc::now();
        let expires_at = start + expiration_duration();

        assert_eq!(
            cache.check_and_store(&arid1, expires_at, start),
            ReplayCheck::Fresh
        );
        assert_eq!(
            cache.check_and_store(&arid1, expires_at, start),
            ReplayCheck::Replay
        );

        let after_expiration = expires_at + chrono::Duration::seconds(1);
        assert_eq!(
            cache.check_and_store(&arid1, expires_at, after_expiration),
            ReplayCheck::Expired
        );

        assert_eq!(
            cache.check_and_store(
                &arid2,
                after_expiration + expiration_duration(),
                after_expiration,
            ),
            ReplayCheck::Fresh
        );
        assert_eq!(cache.len(), 1);
        assert!(!cache.cache.iter().any(|(id, _)| id == &arid1));
    }

    fn exchange_rate_envoy_message() -> EnvoyMessage {
        let fx_rate = ExchangeRate {
            currency_code: String::from("USD"),
            rate: 0.85,
            timestamp: 0,
        };

        EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate),
            timestamp: 123456,
            protocol_version: Some(PROTOCOL_VERSION),
        }
    }

    fn assert_exchange_rate_matches(expected: &EnvoyMessage, actual: &EnvoyMessage) {
        let expected_rate = match &expected.message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };
        let actual_rate = match &actual.message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        assert_eq!(actual.timestamp, expected.timestamp);
        assert_eq!(actual.protocol_version, expected.protocol_version);
        assert_eq!(actual_rate.rate, expected_rate.rate);
    }

    fn seal_envoy_message_with_expiration(
        message: EnvoyMessage,
        sender: &QuantumLinkIdentity,
        recipient: &QuantumLinkIdentity,
        expires_at: DateTime<Utc>,
    ) -> Envelope {
        let valid_until = Date::from(expires_at);

        let event: SealedEvent<Expression> = SealedEvent::new(
            QuantumLink::encode(message),
            ARID::new(),
            &sender.xid_document,
        )
        .with_date(&valid_until);
        event
            .to_envelope(
                Some(&valid_until),
                Some(sender.private_keys.as_ref().unwrap()),
                Some(&recipient.xid_document),
            )
            .unwrap()
    }
}
