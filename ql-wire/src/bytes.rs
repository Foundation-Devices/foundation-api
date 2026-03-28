use core::ops::{Deref, DerefMut};

/// A mutable or immutable byte slice owner used by the wire parser.
pub trait ByteSlice: Deref<Target = [u8]> + Sized {
    /// Splits the current byte view at `mid`.
    ///
    /// Returns `Err(self)` when `mid` is out of bounds.
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self>;
}

/// A mutable reference to bytes.
pub trait ByteSliceMut: ByteSlice + DerefMut<Target = [u8]> {}

impl<B> ByteSliceMut for B where B: ByteSlice + DerefMut<Target = [u8]> {}

impl ByteSlice for &[u8] {
    #[inline]
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self> {
        if mid <= self.len() {
            Ok(<[u8]>::split_at(self, mid))
        } else {
            Err(self)
        }
    }
}

impl ByteSlice for &mut [u8] {
    #[inline]
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self> {
        if mid <= self.len() {
            Ok(<[u8]>::split_at_mut(self, mid))
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteSlice, ByteSliceMut};

    #[test]
    fn shared_slice_split_at() {
        let bytes: &[u8] = b"abcdef";
        let (left, right) = ByteSlice::split_at(bytes, 2).unwrap();
        assert_eq!(left, b"ab");
        assert_eq!(right, b"cdef");
    }

    #[test]
    fn mutable_slice_split_at() {
        let mut bytes = *b"abcdef";
        let (left, right) = ByteSlice::split_at(&mut bytes[..], 2).unwrap();
        assert_eq!(left, b"ab");
        assert_eq!(right, b"cdef");
    }

    #[test]
    fn mutable_split_trait_is_implemented() {
        fn assert_split_mut<T: ByteSliceMut>(_value: T) {}

        let mut bytes = [0u8; 4];
        assert_split_mut(&mut bytes[..]);
    }

    #[test]
    fn split_at_rejects_out_of_bounds_index() {
        let bytes: &[u8] = b"abcdef";
        assert!(ByteSlice::split_at(bytes, 7).is_err());
    }
}
