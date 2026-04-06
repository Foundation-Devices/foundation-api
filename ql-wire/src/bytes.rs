use core::{
    iter::{once, Chain, Once},
    ops::{Deref, DerefMut},
};
use std::collections::VecDeque;

use bytes::Bytes;

/// A mutable or immutable byte slice owner used by the wire parser.
pub trait ByteSlice: Deref<Target = [u8]> + Sized {
    /// Splits the current byte view at `mid`.
    ///
    /// Returns `Err(self)` when `mid` is out of bounds.
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self>;
}

/// A mutable reference to bytes.
pub trait ByteSliceMut: ByteSlice + DerefMut<Target = [u8]> {}

/// A byte container that can be encoded from one or more chunks.
pub trait ByteChunks {
    type Chunks<'a>: Iterator<Item = &'a [u8]>
    where
        Self: 'a;

    fn len(&self) -> usize;

    fn chunks(&self) -> Self::Chunks<'_>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<B> ByteSliceMut for B where B: ByteSlice + DerefMut<Target = [u8]> {}

impl<T: ByteChunks + ?Sized> ByteChunks for &T {
    type Chunks<'a>
        = T::Chunks<'a>
    where
        Self: 'a;

    fn len(&self) -> usize {
        (*self).len()
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        (*self).chunks()
    }
}

impl<T: ByteChunks + ?Sized> ByteChunks for &mut T {
    type Chunks<'a>
        = T::Chunks<'a>
    where
        Self: 'a;

    fn len(&self) -> usize {
        (**self).len()
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        (**self).chunks()
    }
}

impl ByteChunks for [u8] {
    type Chunks<'a>
        = Once<&'a [u8]>
    where
        Self: 'a;

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        once(self)
    }
}

impl<const N: usize> ByteChunks for [u8; N] {
    type Chunks<'a>
        = Once<&'a [u8]>
    where
        Self: 'a;

    fn len(&self) -> usize {
        N
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        once(self.as_slice())
    }
}

impl ByteChunks for Vec<u8> {
    type Chunks<'a>
        = Once<&'a [u8]>
    where
        Self: 'a;

    fn len(&self) -> usize {
        Self::len(self)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        once(self.as_slice())
    }
}

impl ByteChunks for Bytes {
    type Chunks<'a>
        = Once<&'a [u8]>
    where
        Self: 'a;

    fn len(&self) -> usize {
        Bytes::len(self)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        once(self.as_ref())
    }
}

impl ByteChunks for VecDeque<u8> {
    type Chunks<'a>
        = Chain<Once<&'a [u8]>, Once<&'a [u8]>>
    where
        Self: 'a;

    fn len(&self) -> usize {
        Self::len(self)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        let (first, second) = self.as_slices();
        once(first).chain(once(second))
    }
}

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

impl ByteSlice for Bytes {
    #[inline]
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self> {
        if mid <= self.len() {
            Ok((self.slice(..mid), self.slice(mid..)))
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{ByteChunks, ByteSlice, ByteSliceMut};

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

    #[test]
    fn slice_byte_chunks_are_contiguous() {
        let bytes: &[u8] = b"abcdef";
        let chunks = ByteChunks::chunks(&bytes).collect::<Vec<_>>();
        assert_eq!(bytes.len(), 6);
        assert_eq!(chunks, vec![b"abcdef".as_slice()]);
    }

    #[test]
    fn vec_deque_byte_chunks_preserve_split_storage() {
        let mut bytes = VecDeque::with_capacity(8);
        bytes.extend(b"abcd".iter().copied());
        bytes.drain(..2);
        bytes.extend(b"efgh".iter().copied());

        let chunks = ByteChunks::chunks(&bytes).collect::<Vec<_>>();
        assert_eq!(bytes.len(), 6);
        assert_eq!(chunks.concat(), b"cdefgh");
        assert!(!chunks.is_empty());
    }
}
