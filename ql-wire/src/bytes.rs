use core::ops::{Deref, DerefMut};

/// A mutable or immutable reference to bytes.
///
/// # Safety
///
/// Implementations must provide stable dereferences. Given some `b: B`, repeated
/// calls to `Deref::deref(&b)` must always produce a byte slice with the same
/// address and length for as long as `b` is alive. If `B: ByteSliceMut`,
/// repeated calls to `DerefMut::deref_mut(&mut b)` must provide the same
/// guarantee.
pub unsafe trait ByteSlice: Deref<Target = [u8]> + Sized {}

/// A mutable reference to bytes.
pub trait ByteSliceMut: ByteSlice + DerefMut<Target = [u8]> {}

impl<B> ByteSliceMut for B where B: ByteSlice + DerefMut<Target = [u8]> {}

/// A [`ByteSlice`] that can be split in two.
///
/// # Safety
///
/// Implementations must guarantee that `split_at` and `split_at_unchecked`
/// correctly split the underlying bytes. If `self.deref()` yields a slice with
/// address `addr` and length `len`, then splitting at `mid <= len` must return
/// `(left, right)` such that:
/// - `left` starts at `addr` and has length `mid`
/// - `right` starts at `addr + mid` and has length `len - mid`
pub unsafe trait SplitByteSlice: ByteSlice {
    #[inline]
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self> {
        if mid <= self.len() {
            // SAFETY: We just proved that `mid` is in bounds.
            unsafe { Ok(self.split_at_unchecked(mid)) }
        } else {
            Err(self)
        }
    }

    /// Splits the underlying bytes at `mid`.
    ///
    /// # Safety
    ///
    /// `mid` must be less than or equal to the underlying slice length.
    unsafe fn split_at_unchecked(self, mid: usize) -> (Self, Self);
}

/// A shorthand for [`SplitByteSlice`] and [`ByteSliceMut`].
pub trait SplitByteSliceMut: SplitByteSlice + ByteSliceMut {}

impl<B> SplitByteSliceMut for B where B: SplitByteSlice + ByteSliceMut {}

// SAFETY: `&[u8]` dereferences to the same slice for the lifetime of the
// reference.
unsafe impl ByteSlice for &[u8] {}

// SAFETY: `&mut [u8]` dereferences to the same slice for the lifetime of the
// reference.
unsafe impl ByteSlice for &mut [u8] {}

// SAFETY: These methods delegate to the standard library slice split methods,
// which return the exact left and right sub-slices at `mid`.
unsafe impl SplitByteSlice for &[u8] {
    #[inline]
    unsafe fn split_at_unchecked(self, mid: usize) -> (Self, Self) {
        <[u8]>::split_at(self, mid)
    }
}

// SAFETY: These methods delegate to the standard library slice split methods,
// which return the exact left and right sub-slices at `mid`.
unsafe impl SplitByteSlice for &mut [u8] {
    #[inline]
    unsafe fn split_at_unchecked(self, mid: usize) -> (Self, Self) {
        <[u8]>::split_at_mut(self, mid)
    }
}

#[cfg(test)]
mod tests {
    use super::{SplitByteSlice, SplitByteSliceMut};

    #[test]
    fn shared_slice_split_at() {
        let bytes: &[u8] = b"abcdef";
        let (left, right) = SplitByteSlice::split_at(bytes, 2).unwrap();
        assert_eq!(left, b"ab");
        assert_eq!(right, b"cdef");
    }

    #[test]
    fn mutable_slice_split_at() {
        let mut bytes = *b"abcdef";
        let (left, right) = SplitByteSlice::split_at(&mut bytes[..], 2).unwrap();
        assert_eq!(left, b"ab");
        assert_eq!(right, b"cdef");
    }

    #[test]
    fn mutable_split_trait_is_implemented() {
        fn assert_split_mut<T: SplitByteSliceMut>(_value: T) {}

        let mut bytes = [0u8; 4];
        assert_split_mut(&mut bytes[..]);
    }

    #[test]
    fn split_at_rejects_out_of_bounds_index() {
        let bytes: &[u8] = b"abcdef";
        assert!(SplitByteSlice::split_at(bytes, 7).is_err());
    }
}
