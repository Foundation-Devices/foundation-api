use crate::{ByteSlice, QlHeader, WireError};

pub fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
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

    pub fn remaining(&self) -> usize {
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

    pub fn finish(self) -> Result<(), WireError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(WireError::InvalidPayload)
        }
    }
}

pub fn append_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    append_framed_bytes(out, label);
    append_framed_bytes(out, value);
}

pub fn append_framed_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u64::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}

pub fn header_aad(header: &QlHeader) -> Vec<u8> {
    let mut aad = Vec::new();
    append_field(&mut aad, b"domain", b"ql-wire:header-aad:v1");
    append_field(&mut aad, b"sender", &header.sender.0);
    append_field(&mut aad, b"recipient", &header.recipient.0);
    aad
}
