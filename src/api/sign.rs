use bc_envelope::prelude::*;
use anyhow::Result;

use super::{SIGN_FUNCTION, SIGNING_SUBJECT_PARAM};

#[derive(Debug, Clone)]
pub struct Sign(Envelope);

impl Sign {
    pub fn new(signing_subject: Envelope) -> Self {
        Self(signing_subject)
    }
}

impl Sign {
    pub fn signing_subject(&self) -> &Envelope {
        &self.0
    }
}

impl From<Sign> for Expression {
    fn from(value: Sign) -> Self {
        Expression::new(SIGN_FUNCTION)
            .with_parameter(SIGNING_SUBJECT_PARAM, &value.0)
    }
}

impl TryFrom<Expression> for Sign {
    type Error = anyhow::Error;

    fn try_from(expression: Expression) -> Result<Self> {
        Ok(Self(expression.object_for_parameter(SIGNING_SUBJECT_PARAM)?))
    }
}
