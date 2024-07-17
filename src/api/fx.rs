use {
    anyhow::Error,
    bc_components::tag_constant,
    bc_envelope::{Expression, ExpressionBehavior, Function, Parameter},
    dcbor::{CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag, CBOR},
    paste::paste,
};

tag_constant!(EXCHANGE_RATE, 750, "exchange-rate");

pub struct ExchangeRate {
    currency_code: String,
    rate: f32,
}

impl ExchangeRate {
    pub fn new(currency_code: &str, rate: f32) -> Self {
        Self {
            currency_code: currency_code.to_string(),
            rate,
        }
    }

    pub fn currency_code(&self) -> &str {
        &self.currency_code
    }

    pub fn rate(&self) -> f32 {
        self.rate
    }
}

impl CBORTagged for ExchangeRate {
    fn cbor_tags() -> Vec<Tag> {
        vec![EXCHANGE_RATE]
    }
}

impl CBORTaggedEncodable for ExchangeRate {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = dcbor::Map::new();
        map.insert(1, self.currency_code.clone());
        map.insert(2, self.rate);
        map.into()
    }
}

impl TryFrom<CBOR> for ExchangeRate {
    type Error = Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(value)
    }
}

impl CBORTaggedDecodable for ExchangeRate {
    fn from_untagged_cbor(cbor: CBOR) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let map = cbor.try_into_map()?;
        let currency_code: String = map.extract::<i32, CBOR>(1)?.try_into()?;
        let rate: f32 = map.extract::<i32, CBOR>(2)?.try_into()?;

        Ok(ExchangeRate {
            currency_code,
            rate,
        })
    }
}

// TODO: POST-NASHVILLE: determine whether to use Functions or more plain CBOR
// above

pub const EXCHANGE_RATE_FUNCTION: Function = Function::new_static_named("exchangeRate");
const CURRENCY_CODE_PARAM: Parameter = Parameter::new_static_named("currencyCode");
const RATE_PARAM: Parameter = Parameter::new_static_named("rate");

impl From<ExchangeRate> for Expression {
    fn from(value: ExchangeRate) -> Self {
        Expression::new(EXCHANGE_RATE_FUNCTION)
            .with_parameter(CURRENCY_CODE_PARAM, value.currency_code)
            .with_parameter(RATE_PARAM, value.rate)
    }
}

impl TryFrom<Expression> for ExchangeRate {
    type Error = anyhow::Error;

    fn try_from(expression: Expression) -> anyhow::Result<Self> {
        let currency_code: String = expression.extract_object_for_parameter(CURRENCY_CODE_PARAM)?;
        let rate: f32 = expression.extract_object_for_parameter(RATE_PARAM)?;

        Ok(ExchangeRate {
            currency_code,
            rate,
        })
    }
}
