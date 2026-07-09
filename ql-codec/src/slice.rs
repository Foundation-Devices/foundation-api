use core::{mem, ops::Deref};

use bytes::{Buf, Bytes};

/// A byte slice owner used by the codec reader
///
/// # Safety
///
/// `split_at_unchecked` must return byte slices matching `self[..mid]` and
/// `self[mid..]` when `mid <= self.len()`
pub unsafe trait ByteSlice: Deref<Target = [u8]> + Sized {
    /// splits the current byte view at `mid` without checking bounds
    /// mid can be 0
    ///
    /// # Safety
    ///
    /// `mid` must not exceed the slice length.
    unsafe fn split_at_unchecked(self, mid: usize) -> (Self, Self);

    fn take_u8(&mut self) -> Option<u8>;
}

unsafe impl ByteSlice for &[u8] {
    #[inline]
    unsafe fn split_at_unchecked(self, mid: usize) -> (Self, Self) {
        <[u8]>::split_at_unchecked(self, mid)
    }

    #[inline]
    fn take_u8(&mut self) -> Option<u8> {
        let (&byte, remaining) = self.split_first()?;
        *self = remaining;
        Some(byte)
    }
}

unsafe impl ByteSlice for &mut [u8] {
    #[inline]
    unsafe fn split_at_unchecked(self, mid: usize) -> (Self, Self) {
        <[u8]>::split_at_mut_unchecked(self, mid)
    }

    #[inline]
    fn take_u8(&mut self) -> Option<u8> {
        let (byte, remaining) = mem::take(self).split_first_mut()?;
        let byte = *byte;
        *self = remaining;
        Some(byte)
    }
}

unsafe impl ByteSlice for Bytes {
    #[inline]
    unsafe fn split_at_unchecked(mut self, mid: usize) -> (Self, Self) {
        let head = self.split_to(mid);
        (head, self)
    }

    #[inline]
    fn take_u8(&mut self) -> Option<u8> {
        Buf::try_get_u8(self).ok()
    }
}
