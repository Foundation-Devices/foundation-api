/// generates `Encode` and `Decode` for newtypes, structs, and enums.
///
/// newtypes encode as their wrapped value, structs in field order, and enums as a `u8` discriminant
/// followed by an optional payload; the lone generic parameter is treated as the reader's byte
/// container.
///
/// `enum Frame as FrameKind` also generates `FrameKind` and `Frame::kind()`:
/// ```
/// use ql_codec::Encode;
///
/// ql_codec::codec! {
///     #[derive(Debug, PartialEq)]
///     pub enum Frame as FrameKind {
///         Ping = 1,
///         Close(u16) = 2,
///     }
/// }
///
/// let frame = Frame::Close(7);
/// assert_eq!(frame.kind(), FrameKind::Close);
/// assert_eq!(frame.encode_vec(), [2, 7, 0]);
/// ```
#[macro_export]
macro_rules! codec {
    // newtype
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

    // struct with an optional byte container
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

        $crate::codec!(@struct_decode $name$(<$bytes>)?, $($field),*);
    };

    // payload enum with a separate discriminant enum
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident $(<$bytes:ident>)? as $kind:ident {
            $($(#[$variant_meta:meta])* $variant:ident $(($payload:ty))? = $value:literal),* $(,)?
        }
    ) => {
        $crate::codec! {
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

        $crate::codec! {
            @enum_decode $name$(<$bytes>)?, $kind, $($variant $(($payload))? = $value),*
        }
    };

    // u8 discriminant enum
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

    // struct decoding with its byte container
    (@struct_decode $name:ident<$bytes:ident>, $($field:ident),* $(,)?) => {
        impl<$bytes: $crate::ByteSlice> $crate::Decode<$bytes> for $name<$bytes> {
            fn decode(reader: &mut $crate::Reader<$bytes>) -> Result<Self, $crate::Error> {
                Ok(Self { $($field: reader.decode()?,)* })
            }
        }
    };

    // struct decoding with a fresh byte container
    (@struct_decode $name:ident, $($field:ident),* $(,)?) => {
        impl<CodecBytes: $crate::ByteSlice> $crate::Decode<CodecBytes> for $name {
            fn decode(reader: &mut $crate::Reader<CodecBytes>) -> Result<Self, $crate::Error> {
                Ok(Self { $($field: reader.decode()?,)* })
            }
        }
    };

    // payload enum decoding with its byte container
    (
        @enum_decode $name:ident<$bytes:ident>, $kind:ident,
        $($variant:ident $(($payload:ty))? = $value:literal),* $(,)?
    ) => {
        impl<$bytes: $crate::ByteSlice> $crate::Decode<$bytes> for $name<$bytes> {
            fn decode(reader: &mut $crate::Reader<$bytes>) -> Result<Self, $crate::Error> {
                Ok(match reader.decode::<$kind>()? {
                    $($kind::$variant => Self::$variant $((reader.decode::<$payload>()?))?,)*
                })
            }
        }
    };

    // payload enum decoding with a fresh byte container
    (
        @enum_decode $name:ident, $kind:ident,
        $($variant:ident $(($payload:ty))? = $value:literal),* $(,)?
    ) => {
        impl<CodecBytes: $crate::ByteSlice> $crate::Decode<CodecBytes> for $name {
            fn decode(reader: &mut $crate::Reader<CodecBytes>) -> Result<Self, $crate::Error> {
                Ok(match reader.decode::<$kind>()? {
                    $($kind::$variant => Self::$variant $((reader.decode::<$payload>()?))?,)*
                })
            }
        }
    };
}
