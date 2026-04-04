use crate::{ByteSlice, WireError};

pub fn write_u8(out: &mut [u8], value: u8) -> &mut [u8] {
    let (head, rest) = out.split_at_mut(1);
    head[0] = value;
    rest
}

pub fn write_u16(out: &mut [u8], value: u16) -> &mut [u8] {
    let (head, rest) = out.split_at_mut(size_of::<u16>());
    head.copy_from_slice(&value.to_le_bytes());
    rest
}

pub fn write_u32(out: &mut [u8], value: u32) -> &mut [u8] {
    let (head, rest) = out.split_at_mut(size_of::<u32>());
    head.copy_from_slice(&value.to_le_bytes());
    rest
}

pub fn write_u64(out: &mut [u8], value: u64) -> &mut [u8] {
    let (head, rest) = out.split_at_mut(size_of::<u64>());
    head.copy_from_slice(&value.to_le_bytes());
    rest
}

pub fn write_bool(out: &mut [u8], value: bool) -> &mut [u8] {
    write_u8(out, u8::from(value))
}

pub fn write_bytes<'a>(out: &'a mut [u8], bytes: &[u8]) -> &'a mut [u8] {
    let (head, rest) = out.split_at_mut(bytes.len());
    head.copy_from_slice(bytes);
    rest
}

pub trait WireParse<B: ByteSlice>: Sized {
    fn parse(reader: &mut Reader<B>) -> Result<Self, WireError>;

    fn parse_prefix(bytes: B) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        Self::parse(&mut reader)
    }

    fn parse_bytes(bytes: B) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let value = Self::parse(&mut reader)?;
        if reader.is_empty() {
            Ok(value)
        } else {
            Err(WireError::InvalidPayload)
        }
    }
}

pub struct Reader<B> {
    remaining: Option<B>,
}

impl<B: ByteSlice> Reader<B> {
    pub fn new(bytes: B) -> Self {
        Self {
            remaining: Some(bytes),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.remaining.as_ref().unwrap().is_empty()
    }

    pub fn remaining_len(&self) -> usize {
        self.remaining.as_ref().unwrap().len()
    }

    pub fn take_bytes(&mut self, len: usize) -> Result<B, WireError> {
        let remaining = self.remaining.take().unwrap();
        match remaining.split_at(len) {
            Ok((head, tail)) => {
                self.remaining = Some(tail);
                Ok(head)
            }
            Err(remaining) => {
                self.remaining = Some(remaining);
                Err(WireError::InvalidPayload)
            }
        }
    }

    pub fn take_rest(mut self) -> B {
        self.remaining.take().unwrap()
    }

    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let bytes = self.take_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub fn take_boxed_array<const N: usize>(&mut self) -> Result<Box<[u8; N]>, WireError> {
        let bytes = self.take_bytes(N)?;
        let mut out = Box::<[u8; N]>::new_uninit();
        let src = bytes.as_ptr();
        let dst = out.as_mut_ptr().cast::<u8>();
        // SAFETY: `take_bytes(N)` guarantees the source has exactly `N` bytes
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, N);
            Ok(out.assume_init())
        }
    }

    pub fn take_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take_bytes(1)?[0])
    }

    pub fn take_u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    pub fn take_u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    pub fn take_u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take_array()?))
    }

    pub fn take_bool(&mut self) -> Result<bool, WireError> {
        match self.take_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidPayload),
        }
    }

    #[inline]
    pub fn parse<T>(&mut self) -> Result<T, WireError>
    where
        T: WireParse<B>,
    {
        T::parse(self)
    }
}
