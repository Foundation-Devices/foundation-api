use core::{
    iter::{once, Chain, Once},
    ops::{Deref, DerefMut},
};
use std::collections::VecDeque;

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
        Vec::len(self)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        once(self.as_slice())
    }
}

impl ByteChunks for VecDeque<u8> {
    type Chunks<'a>
        = Chain<Once<&'a [u8]>, Once<&'a [u8]>>
    where
        Self: 'a;

    fn len(&self) -> usize {
        VecDeque::len(self)
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

#[derive(Debug, Clone, Copy)]
pub struct CappedByteChunks<T> {
    pub inner: T,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct RangedByteChunks<T> {
    pub inner: T,
    pub offset: usize,
    pub len: usize,
}

pub struct CappedByteChunksIter<I> {
    inner: I,
    remaining: usize,
}

pub struct RangedByteChunksIter<I> {
    inner: I,
    skip: usize,
    remaining: usize,
}

impl<'a, I> Iterator for CappedByteChunksIter<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            let chunk = self.inner.next()?;
            if chunk.is_empty() {
                continue;
            }

            let len = chunk.len().min(self.remaining);
            self.remaining -= len;
            return Some(&chunk[..len]);
        }

        None
    }
}

impl<'a, I> Iterator for RangedByteChunksIter<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            let chunk = self.inner.next()?;
            if self.skip >= chunk.len() {
                self.skip -= chunk.len();
                continue;
            }

            let chunk = &chunk[self.skip..];
            self.skip = 0;
            if chunk.is_empty() {
                continue;
            }

            let len = chunk.len().min(self.remaining);
            self.remaining -= len;
            return Some(&chunk[..len]);
        }

        None
    }
}

impl<T: ByteChunks> ByteChunks for CappedByteChunks<T> {
    type Chunks<'a>
        = CappedByteChunksIter<T::Chunks<'a>>
    where
        Self: 'a;

    fn len(&self) -> usize {
        self.inner.len().min(self.limit)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        CappedByteChunksIter {
            inner: self.inner.chunks(),
            remaining: self.len(),
        }
    }
}

impl<T: ByteChunks> ByteChunks for RangedByteChunks<T> {
    type Chunks<'a>
        = RangedByteChunksIter<T::Chunks<'a>>
    where
        Self: 'a;

    fn len(&self) -> usize {
        self.inner.len().saturating_sub(self.offset).min(self.len)
    }

    fn chunks(&self) -> Self::Chunks<'_> {
        RangedByteChunksIter {
            inner: self.inner.chunks(),
            skip: self.offset,
            remaining: self.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{ByteChunks, ByteSlice, ByteSliceMut, CappedByteChunks, RangedByteChunks};

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
        assert!(chunks.len() >= 1);
    }

    #[test]
    fn capped_byte_chunks_truncate_slice() {
        let bytes: &[u8] = b"abcdef";
        let capped = CappedByteChunks {
            inner: bytes,
            limit: 4,
        };

        let chunks = capped.chunks().collect::<Vec<_>>();
        assert_eq!(capped.len(), 4);
        assert_eq!(chunks, vec![b"abcd".as_slice()]);
    }

    #[test]
    fn capped_byte_chunks_truncate_borrowed_vec_deque() {
        let mut bytes = VecDeque::with_capacity(8);
        bytes.extend(b"abcd".iter().copied());
        bytes.drain(..2);
        bytes.extend(b"efgh".iter().copied());

        let capped = CappedByteChunks {
            inner: &bytes,
            limit: 4,
        };

        let chunks = capped.chunks().collect::<Vec<_>>();
        assert_eq!(capped.len(), 4);
        assert_eq!(chunks.concat(), b"cdef");
    }

    #[test]
    fn ranged_byte_chunks_slice_middle() {
        let bytes: &[u8] = b"abcdef";
        let ranged = RangedByteChunks {
            inner: bytes,
            offset: 2,
            len: 3,
        };

        let chunks = ranged.chunks().collect::<Vec<_>>();
        assert_eq!(ranged.len(), 3);
        assert_eq!(chunks, vec![b"cde".as_slice()]);
    }

    #[test]
    fn ranged_byte_chunks_borrowed_vec_deque_middle() {
        let mut bytes = VecDeque::with_capacity(8);
        bytes.extend(b"abcd".iter().copied());
        bytes.drain(..2);
        bytes.extend(b"efgh".iter().copied());

        let ranged = RangedByteChunks {
            inner: &bytes,
            offset: 1,
            len: 4,
        };

        let chunks = ranged.chunks().collect::<Vec<_>>();
        assert_eq!(ranged.len(), 4);
        assert_eq!(chunks.concat(), b"defg");
    }
}
