use core::{mem, ops::Deref};

use bytes::{Buf, Bytes};

/// A byte slice owner used by the codec reader
pub trait ByteSlice: Deref<Target = [u8]> + Sized {
    /// splits `self[..mid]` off the front, leaving `self[mid..]` behind
    ///
    /// # Panics
    ///
    /// Panics if `mid` exceeds the slice length.
    fn split_off_front(&mut self, mid: usize) -> Self;

    fn take_u8(&mut self) -> Option<u8>;
}

impl ByteSlice for &[u8] {
    #[inline]
    fn split_off_front(&mut self, mid: usize) -> Self {
        let (head, tail) = self.split_at(mid);
        *self = tail;
        head
    }

    #[inline]
    fn take_u8(&mut self) -> Option<u8> {
        let (&byte, remaining) = self.split_first()?;
        *self = remaining;
        Some(byte)
    }
}

impl ByteSlice for &mut [u8] {
    #[inline]
    fn split_off_front(&mut self, mid: usize) -> Self {
        let (head, tail) = mem::take(self).split_at_mut(mid);
        *self = tail;
        head
    }

    #[inline]
    fn take_u8(&mut self) -> Option<u8> {
        let (byte, remaining) = mem::take(self).split_first_mut()?;
        let byte = *byte;
        *self = remaining;
        Some(byte)
    }
}

impl ByteSlice for Bytes {
    #[inline]
    fn split_off_front(&mut self, mid: usize) -> Self {
        self.split_to(mid)
    }

    #[inline]
    fn take_u8(&mut self) -> Option<u8> {
        Buf::try_get_u8(self).ok()
    }
}
