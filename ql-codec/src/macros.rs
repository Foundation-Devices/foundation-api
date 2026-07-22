/// Defines a newtype and encodes it exactly as the value it wraps.
#[macro_export]
macro_rules! codec_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($field_vis:vis $inner:ty);
    ) => {
        $(#[$meta])*
        $vis struct $name($field_vis $inner);

        impl $crate::Encode for $name {
            fn encoded_len(&self) -> usize {
                $crate::Encode::encoded_len(&self.0)
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                $crate::Encode::encode(&self.0, out);
            }
        }

        impl<CodecBytes: $crate::ByteSlice> $crate::Decode<CodecBytes> for $name {
            fn decode(reader: &mut $crate::Reader<CodecBytes>) -> Result<Self, $crate::Error> {
                Ok(Self(reader.decode()?))
            }
        }
    };
}

/// Defines a struct and encodes its fields back to back in declaration order.
///
/// A single generic parameter is taken to be the byte container, bound as
/// [`BufView`](crate::BufView) for encoding and [`ByteSlice`](crate::ByteSlice) for decoding. It
/// may only appear nested inside another codec type, and decoding ties it to the reader's own
/// container, because a borrowed field can only be taken from the reader it is read out of.
/// Anything whose fields do not map one to one onto the wire needs a hand-written impl.
#[macro_export]
macro_rules! codec_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $(<$bytes:ident>)? {
            $($(#[$field_meta:meta])* $field_vis:vis $field:ident: $ty:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name$(<$bytes>)? {
            $($(#[$field_meta])* $field_vis $field: $ty,)*
        }

        impl$(<$bytes: $crate::BufView>)? $crate::Encode for $name$(<$bytes>)? {
            fn encoded_len(&self) -> usize {
                $($crate::Encode::encoded_len(&self.$field) +)* 0
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                $($crate::Encode::encode(&self.$field, out);)*
            }
        }

        $crate::__codec_struct_decode!($name$(<$bytes>)?, $($field),*);
    };
}

/// The one impl that cannot be written once: `Decode` always needs a byte container to name, so
/// a generic struct reuses its own parameter while a plain one introduces a fresh name.
#[macro_export]
#[doc(hidden)]
macro_rules! __codec_struct_decode {
    ($name:ident<$bytes:ident>, $($field:ident),* $(,)?) => {
        impl<$bytes: $crate::ByteSlice> $crate::Decode<$bytes> for $name<$bytes> {
            fn decode(reader: &mut $crate::Reader<$bytes>) -> Result<Self, $crate::Error> {
                Ok(Self { $($field: reader.decode()?,)* })
            }
        }
    };

    ($name:ident, $($field:ident),* $(,)?) => {
        impl<CodecBytes: $crate::ByteSlice> $crate::Decode<CodecBytes> for $name {
            fn decode(reader: &mut $crate::Reader<CodecBytes>) -> Result<Self, $crate::Error> {
                Ok(Self { $($field: reader.decode()?,)* })
            }
        }
    };
}

/// Defines an enum carried on the wire as a `u8` discriminant.
///
/// `enum Frame as FrameKind` additionally defines the discriminant enum and a `kind` accessor,
/// and encodes each variant's payload after the discriminant.
///
/// ```
/// use ql_codec::{Decode, Encode};
///
/// ql_codec::codec_enum! {
///     #[derive(Debug, Clone, Copy, PartialEq, Eq)]
///     pub enum CloseReason {
///         Done = 1,
///         Refused = 2,
///     }
/// }
///
/// ql_codec::codec_enum! {
///     #[derive(Debug, PartialEq)]
///     pub enum Frame as FrameKind {
///         Ping = 1,
///         Close(CloseReason) = 3,
///     }
/// }
///
/// // A unit variant is just its discriminant.
/// assert_eq!(Frame::Ping.encode_vec(), [1]);
///
/// // A payload follows the discriminant, and `kind()` reads it back without the payload.
/// let frame = Frame::Close(CloseReason::Refused);
/// assert_eq!(frame.kind(), FrameKind::Close);
/// assert_eq!(frame.encode_vec(), [3, 2]);
/// assert_eq!(Frame::decode_bytes(&[3, 2][..]).unwrap(), frame);
///
/// assert_eq!(
///     Frame::decode_bytes(&[9][..]),
///     Err(ql_codec::Error::InvalidDiscriminant),
/// );
/// ```
#[macro_export]
macro_rules! codec_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident $(<$bytes:ident>)? as $kind:ident {
            $($(#[$variant_meta:meta])* $variant:ident $(($payload:ty))? = $value:literal),* $(,)?
        }
    ) => {
        $crate::codec_enum! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            $vis enum $kind {
                $($variant = $value,)*
            }
        }

        $(#[$meta])*
        $vis enum $name$(<$bytes>)? {
            $($(#[$variant_meta])* $variant $(($payload))?,)*
        }

        impl$(<$bytes>)? $name$(<$bytes>)? {
            $vis fn kind(&self) -> $kind {
                match self {
                    $(Self::$variant { .. } => $kind::$variant,)*
                }
            }
        }

        impl$(<$bytes: $crate::BufView>)? $crate::Encode for $name$(<$bytes>)? {
            #[allow(unreachable_patterns)]
            fn encoded_len(&self) -> usize {
                $crate::Encode::encoded_len(&self.kind())
                    + match self {
                        $($(Self::$variant(payload) =>
                            <$payload as $crate::Encode>::encoded_len(payload),)?)*
                        _ => 0,
                    }
            }

            #[allow(unreachable_patterns)]
            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                $crate::Encode::encode(&self.kind(), out);
                match self {
                    $($(Self::$variant(payload) =>
                        <$payload as $crate::Encode>::encode(payload, out),)?)*
                    _ => {}
                }
            }
        }

        $crate::__codec_enum_decode! {
            $name$(<$bytes>)?, $kind, $($variant $(($payload))?),*
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident = $value:literal),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr(u8)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant = $value,)*
        }

        impl TryFrom<u8> for $name {
            type Error = $crate::Error;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)*
                    _ => Err($crate::Error::InvalidDiscriminant),
                }
            }
        }

        impl $crate::Encode for $name {
            fn encoded_len(&self) -> usize {
                size_of::<u8>()
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                ::bytes::BufMut::put_u8(out, *self as u8);
            }
        }

        impl<CodecBytes: $crate::ByteSlice> $crate::Decode<CodecBytes> for $name {
            fn decode(reader: &mut $crate::Reader<CodecBytes>) -> Result<Self, $crate::Error> {
                reader.decode::<u8>()?.try_into()
            }
        }
    };
}

/// The one impl that cannot be written once: `Decode` always needs a byte container to name, so
/// a generic enum reuses its own parameter while a plain one introduces a fresh name.
#[macro_export]
#[doc(hidden)]
macro_rules! __codec_enum_decode {
    ($name:ident<$bytes:ident>, $kind:ident, $($variant:ident $(($payload:ty))?),* $(,)?) => {
        impl<$bytes: $crate::ByteSlice> $crate::Decode<$bytes> for $name<$bytes> {
            fn decode(reader: &mut $crate::Reader<$bytes>) -> Result<Self, $crate::Error> {
                Ok(match reader.decode::<$kind>()? {
                    $($kind::$variant => Self::$variant $((reader.decode::<$payload>()?))?,)*
                })
            }
        }
    };

    ($name:ident, $kind:ident, $($variant:ident $(($payload:ty))?),* $(,)?) => {
        impl<CodecBytes: $crate::ByteSlice> $crate::Decode<CodecBytes> for $name {
            fn decode(reader: &mut $crate::Reader<CodecBytes>) -> Result<Self, $crate::Error> {
                Ok(match reader.decode::<$kind>()? {
                    $($kind::$variant => Self::$variant $((reader.decode::<$payload>()?))?,)*
                })
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::{Decode, Encode, Error};

    codec_newtype! {
        /// A newtype carrying a fixed-size array.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Tag(pub [u8; 4]);
    }

    codec_enum! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Flavour {
            Sweet = 1,
            Salty = 3,
        }
    }

    codec_struct! {
        /// Fields encode in declaration order.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct Plain {
            pub tag: Tag,
            pub flavour: Flavour,
            pub name: String,
        }
    }

    codec_struct! {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct Wrapped<B> {
            pub tag: Tag,
            pub body: Nested<B>,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Nested<B>(pub B);

    impl<B: crate::BufView> Encode for Nested<B> {
        fn encoded_len(&self) -> usize {
            crate::encoded_len_bytes(&self.0)
        }

        fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
            crate::encode_bytes(&self.0, out);
        }
    }

    impl<B: crate::ByteSlice> Decode<B> for Nested<B> {
        fn decode(reader: &mut crate::Reader<B>) -> Result<Self, Error> {
            Ok(Self(reader.take_len_prefixed()?))
        }
    }

    codec_enum! {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum Frame<B> as FrameKind {
            Ping = 1,
            Plain(Plain) = 2,
            Body(Wrapped<B>) = 3,
            Pong = 4,
        }
    }

    codec_enum! {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum Message as MessageKind {
            Empty = 1,
            Plain(Plain) = 2,
        }
    }

    fn plain() -> Plain {
        Plain {
            tag: Tag([1, 2, 3, 4]),
            flavour: Flavour::Salty,
            name: "hello".to_owned(),
        }
    }

    #[test]
    fn struct_fields_encode_in_declaration_order() {
        let encoded = plain().encode_vec();
        assert_eq!(&encoded[..4], &[1, 2, 3, 4]);
        assert_eq!(encoded[4], 3);
        assert_eq!(Plain::decode_bytes(encoded.as_slice()).unwrap(), plain());

        let tag = Tag([9; 4]);
        assert_eq!(Tag::decode_bytes(tag.encode_vec().as_slice()).unwrap(), tag);
    }

    #[test]
    fn generic_struct_decodes_from_its_own_container() {
        let value = Wrapped {
            tag: Tag([5; 4]),
            body: Nested(Bytes::from_static(b"body")),
        };
        let encoded = Bytes::from(value.encode_vec());
        assert_eq!(Wrapped::<Bytes>::decode_bytes(encoded).unwrap(), value);
    }

    #[test]
    fn unknown_discriminant_is_rejected() {
        assert_eq!(Flavour::Salty.encode_vec(), [3]);
        assert_eq!(
            Flavour::decode_bytes(&[2u8][..]),
            Err(Error::InvalidDiscriminant)
        );
        assert_eq!(
            Message::decode_bytes(&[9u8][..]),
            Err(Error::InvalidDiscriminant)
        );
    }

    #[test]
    fn payload_enum_writes_the_kind_first() {
        let frame = Frame::<Bytes>::Plain(plain());
        assert_eq!(frame.kind(), FrameKind::Plain);
        assert_eq!(frame.encode_vec()[0], 2);
        assert_eq!(Frame::<Bytes>::Pong.encode_vec(), [4]);

        let encoded = Bytes::from(frame.encode_vec());
        assert_eq!(Frame::<Bytes>::decode_bytes(encoded).unwrap(), frame);
    }

    #[test]
    fn payload_enum_without_generics_round_trips() {
        for message in [Message::Empty, Message::Plain(plain())] {
            let encoded = message.encode_vec();
            assert_eq!(Message::decode_bytes(encoded.as_slice()).unwrap(), message);
        }
        assert_eq!(Message::Plain(plain()).kind(), MessageKind::Plain);
    }
}
