use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidData,
    UnexpectedEof,
    InvalidDiscriminant,
    InvalidRange,
    LengthOverflow,
    InvalidVarint,
    InvalidUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidData => "invalid data",
            Self::UnexpectedEof => "unexpected end of input",
            Self::InvalidDiscriminant => "invalid discriminant",
            Self::InvalidRange => "invalid range",
            Self::LengthOverflow => "length overflow",
            Self::InvalidVarint => "invalid varint",
            Self::InvalidUtf8 => "invalid utf-8",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Error {}
