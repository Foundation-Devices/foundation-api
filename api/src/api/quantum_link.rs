use std::time::Duration;

use anyhow::bail;
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

/// Storage for tracking received ARIDs to prevent replay attacks
#[derive(Debug, Default, Clone)]
pub struct ARIDCache {
    cache: Vec<(ARID, DateTime<Utc>)>,
}

impl ARIDCache {
    pub fn new() -> Self {
        Self { cache: Vec::new() }
    }

    /// Check if ARID has been seen before and store it if not
    /// Returns true if this is a replay attack (ARID already exists)
    pub fn check_and_store(
        &mut self,
        arid: &ARID,
        sent_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> bool {
        // Clean up expired entries first
        self.cache
            .retain(|(_, date)| now < (*date + EXPIRATION_DURATION));

        // Check if ARID already exists (replay attack)
        if self.cache.iter().any(|(id, _)| id == arid) {
            return true; // Replay attack detected
        }

        if now < (sent_at + EXPIRATION_DURATION) {
            self.cache.push((arid.clone(), sent_at));
        }
        false // Not a replay attack
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

pub trait QuantumLink: minicbor::Encode<()> + for<'a> minicbor::Decode<'a, ()> {
    fn encode(&self) -> Expression {
        let mut buffer: Vec<u8> = Vec::new();

        minicbor::encode(self, &mut buffer).unwrap();
        let dcbor = CBOR::try_from_data(buffer).unwrap();

        let envelope = Envelope::new(dcbor);
        Expression::new(QUANTUM_LINK).with_parameter("ql", envelope)
    }

    fn decode(expression: &Expression) -> anyhow::Result<Self>
    where
        Self: for<'a> minicbor::Decode<'a, ()>,
    {
        if expression.function().clone() != QUANTUM_LINK {
            bail!("Expected QuantumLink function");
        }
        let envelope = expression.object_for_parameter("ql")?;
        let raw_data = envelope
            .as_leaf()
            .expect("there should be a leaf")
            .to_cbor_data();

        let message = minicbor::decode(&raw_data).map_err(|e| anyhow::anyhow!(e))?;
        Ok(message)
    }

    fn seal(
        &self,
        (sender_pk, sender_xid): (&PrivateKeys, &XIDDocument),
        recipient: &XIDDocument,
    ) -> Envelope
    where
        Self: minicbor::Encode<()>,
    {
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
    ) -> anyhow::Result<(Expression, XIDDocument)>
    where
        Self: for<'a> minicbor::Decode<'a, ()>,
    {
        let event: SealedEvent<Expression> =
            SealedEvent::try_from_envelope(envelope, None, Some(&Date::now()), private_keys)?;
        let expression = event.content().clone();
        Ok((expression, event.sender().clone()))
    }

    fn unseal_with_replay_check(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
        arid_cache: &mut ARIDCache,
    ) -> anyhow::Result<(Expression, XIDDocument)>
    where
        Self: for<'a> minicbor::Decode<'a, ()>,
    {
        let now = Utc::now();
        let event: SealedEvent<Expression> =
            SealedEvent::try_from_envelope(envelope, None, Some(&Date::from(now)), private_keys)?;

        // Check for replay attack
        let arid = event.id();
        let event_date = event
            .date()
            .ok_or_else(|| anyhow::anyhow!("event missing date"))?
            .datetime();
        if arid_cache.check_and_store(&arid, event_date, now) {
            bail!("Replay attack detected: ARID has been seen before");
        }

        let expression = event.content().clone();
        Ok((expression, event.sender().clone()))
    }

    fn unseal_passport_message(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
    ) -> anyhow::Result<(PassportMessage, XIDDocument)> {
        let (expression, sender) = PassportMessage::unseal(envelope, private_keys)?;
        Ok((PassportMessage::decode(&expression)?, sender))
    }

    fn unseal_passport_message_with_replay_check(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
        arid_cache: &mut ARIDCache,
    ) -> anyhow::Result<(PassportMessage, XIDDocument)> {
        let (expression, sender) =
            PassportMessage::unseal_with_replay_check(envelope, private_keys, arid_cache)?;
        Ok((PassportMessage::decode(&expression)?, sender))
    }

    fn unseal_envoy_message(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
    ) -> anyhow::Result<(EnvoyMessage, XIDDocument)> {
        let (expression, sender) = EnvoyMessage::unseal(envelope, private_keys)?;
        Ok((EnvoyMessage::decode(&expression)?, sender))
    }

    fn unseal_envoy_message_with_replay_check(
        envelope: &Envelope,
        private_keys: &PrivateKeys,
        arid_cache: &mut ARIDCache,
    ) -> anyhow::Result<(EnvoyMessage, XIDDocument)> {
        let (expression, sender) =
            EnvoyMessage::unseal_with_replay_check(envelope, private_keys, arid_cache)?;
        Ok((EnvoyMessage::decode(&expression)?, sender))
    }
}

impl<T> QuantumLink for T where T: minicbor::Encode<()> + for<'a> minicbor::Decode<'a, ()> {}

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

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut map = bc_envelope::prelude::Map::new();
        map.insert(CBOR::from("xid_document"), self.clone().xid_document);
        if self.private_keys.is_some() {
            map.insert(
                CBOR::from("private_keys"),
                self.clone().private_keys.unwrap(),
            );
        }

        Ok(CBOR::from(map).to_cbor_data())
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let cbor = CBOR::try_from_data(bytes)
            .ok()
            .ok_or_else(|| anyhow::anyhow!("Invalid CBOR"))?;
        let case = cbor.into_case();

        let CBORCase::Map(map) = case else {
            return Err(anyhow::anyhow!("Invalid CBOR case"));
        };

        Ok(QuantumLinkIdentity {
            xid_document: map
                .get("xid_document")
                .ok_or_else(|| anyhow::anyhow!("xid_document not found"))?,
            private_keys: map.get("private_keys"),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api::{message::QuantumLinkMessage, quantum_link::QuantumLink},
        fx::ExchangeRate,
        message::EnvoyMessage,
        quantum_link::{ARIDCache, QuantumLinkIdentity},
    };

    #[test]
    fn test_encode_decode_quantumlink_message() {
        let fx_rate = ExchangeRate {
            currency_code: String::from("USD"),
            rate: 0.85,
            timestamp: 0,
        };
        let original_message = QuantumLinkMessage::ExchangeRate(fx_rate.clone());

        // Encode the message
        let expression = QuantumLink::encode(&original_message);

        // Decode the message
        let decoded_message = QuantumLink::decode(&expression).unwrap();

        let fx_rate_decoded: ExchangeRate = match decoded_message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        // Assert that the original and decoded messages are the same
        assert_eq!(fx_rate.rate, fx_rate_decoded.rate);
    }

    #[test]
    fn test_seal_unseal_quantumlink_message() {
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();

        let fx_rate = ExchangeRate {
            currency_code: String::from("USD"),
            rate: 0.85,
            timestamp: 0,
        };
        let original_message = EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate.clone()),
            timestamp: 123456,
        };

        // Seal the message
        let envelope = QuantumLink::seal(
            &original_message,
            (envoy.private_keys.as_ref().unwrap(), &envoy.xid_document),
            &passport.xid_document,
        );

        // Decode the message
        let decoded_message =
            EnvoyMessage::unseal_envoy_message(&envelope, &passport.private_keys.unwrap()).unwrap();

        let fx_rate_decoded: ExchangeRate = match decoded_message.0.message {
            QuantumLinkMessage::ExchangeRate(rate) => rate,
            _ => panic!("Expected ExchangeRate message"),
        };

        // Assert that the original and decoded messages are the same
        assert_eq!(fx_rate.rate, fx_rate_decoded.rate);
    }

    #[test]
    fn test_serialize_ql_identity() {
        let identity = QuantumLinkIdentity::generate();
        let bytes = identity.to_bytes().unwrap();

        let deserialized_identity = QuantumLinkIdentity::from_bytes(bytes.as_slice()).unwrap();

        // Assert that the original and decoded messages are the same
        assert_eq!(
            identity.private_keys.unwrap(),
            deserialized_identity.private_keys.unwrap()
        );
    }

    #[test]
    fn test_replay_attack_prevention() {
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let mut arid_cache = ARIDCache::new();

        let fx_rate = ExchangeRate {
            currency_code: String::from("USD"),
            rate: 0.85,
            timestamp: 0,
        };
        let original_message = EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate.clone()),
            timestamp: 123456,
        };

        // Seal the message
        let envelope = QuantumLink::seal(
            &original_message,
            (envoy.private_keys.as_ref().unwrap(), &envoy.xid_document),
            &passport.xid_document,
        );

        // First unseal should succeed
        let result1 = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope,
            &passport.private_keys.clone().unwrap(),
            &mut arid_cache,
        );
        assert!(result1.is_ok());

        // Second unseal of the same message should fail (replay attack)
        let result2 = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope,
            &passport.private_keys.unwrap(),
            &mut arid_cache,
        );
        assert!(result2.is_err());
        assert!(result2
            .unwrap_err()
            .to_string()
            .contains("Replay attack detected"));
    }

    #[test]
    fn test_arid_cache_cleanup() {
        let mut arid_cache = ARIDCache::new();
        let envoy = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();

        // Create and seal multiple messages
        let fx_rate = ExchangeRate {
            currency_code: String::from("USD"),
            rate: 0.85,
            timestamp: 0,
        };
        let message1 = EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate.clone()),
            timestamp: 123456,
        };
        let message2 = EnvoyMessage {
            message: QuantumLinkMessage::ExchangeRate(fx_rate.clone()),
            timestamp: 123457,
        };

        let envelope1 = QuantumLink::seal(
            &message1,
            (envoy.private_keys.as_ref().unwrap(), &envoy.xid_document),
            &passport.xid_document,
        );

        let envelope2 = QuantumLink::seal(
            &message2,
            (envoy.private_keys.as_ref().unwrap(), &envoy.xid_document),
            &passport.xid_document,
        );

        // Unseal both messages
        let _result1 = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope1,
            &passport.private_keys.clone().unwrap(),
            &mut arid_cache,
        )
        .unwrap();
        let _result2 = EnvoyMessage::unseal_envoy_message_with_replay_check(
            &envelope2,
            &passport.private_keys.unwrap(),
            &mut arid_cache,
        )
        .unwrap();

        // Should have 2 ARIDs stored
        assert_eq!(arid_cache.len(), 2);

        // Clear cache manually to test cleanup
        arid_cache.clear();
        assert_eq!(arid_cache.len(), 0);
    }
}

#[test]
fn test_time_based_eviction() {
    let mut cache = ARIDCache::new();
    let arid1 = ARID::new();
    let arid2 = ARID::new();

    let expiration = chrono::Duration::from_std(EXPIRATION_DURATION).unwrap();
    let start = chrono::Utc::now();

    cache.check_and_store(&arid1, start, start);
    assert_eq!(cache.len(), 1);

    // evict the old time
    // evict the old time by advancing 'now' past expiration
    let future = start + expiration + chrono::Duration::seconds(1);
    cache.check_and_store(&arid2, future, future);
    assert_eq!(cache.len(), 1);
    assert!(!cache.cache.iter().any(|(id, _)| id == &arid1));
}

#[test]
fn test_replay_check() {
    use crate::{fx::ExchangeRate, message::QuantumLinkMessage};

    let mut arid_cache = ARIDCache::new();
    let envoy = QuantumLinkIdentity::generate();
    let passport = QuantumLinkIdentity::generate();

    let fx_rate = ExchangeRate {
        currency_code: String::from("USD"),
        rate: 0.85,
        timestamp: 0,
    };
    let message = EnvoyMessage {
        message: QuantumLinkMessage::ExchangeRate(fx_rate),
        timestamp: 123456,
    };

    let envelope = QuantumLink::seal(
        &message,
        (envoy.private_keys.as_ref().unwrap(), &envoy.xid_document),
        &passport.xid_document,
    );

    let result1 = EnvoyMessage::unseal_envoy_message_with_replay_check(
        &envelope,
        &passport.private_keys.clone().unwrap(),
        &mut arid_cache,
    );
    assert!(result1.is_ok());

    let result2 = EnvoyMessage::unseal_envoy_message_with_replay_check(
        &envelope,
        &passport.private_keys.unwrap(),
        &mut arid_cache,
    );
    assert!(result2.is_err());
}
