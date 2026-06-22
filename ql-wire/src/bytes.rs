use core::ops::Deref;

use bytes::{Buf, Bytes};

/// A mutable or immutable byte slice owner used by the wire parser.
pub trait ByteSlice: Deref<Target = [u8]> + Sized {
    /// Splits the current byte view at `mid`.
    ///
    /// Returns `Err(self)` when `mid` is out of bounds.
    fn split_at(self, mid: usize) -> Result<(Self, Self), Self>;
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

/// A byte container that can expose a replayable [`Buf`] view for encoding.
pub trait BufView {
    type Buf<'a>: Buf
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_>;

    fn is_empty(&self) -> bool {
        self.buf().remaining() == 0
    }
}

impl<T: BufView + ?Sized> BufView for &T {
    type Buf<'a>
        = T::Buf<'a>
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        (*self).buf()
    }
}

impl<T: BufView + ?Sized> BufView for &mut T {
    type Buf<'a>
        = T::Buf<'a>
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        (**self).buf()
    }
}

impl BufView for [u8] {
    type Buf<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        self
    }
}

impl<const N: usize> BufView for [u8; N] {
    type Buf<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        self.as_slice()
    }
}

impl BufView for Vec<u8> {
    type Buf<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        self.as_slice()
    }
}

impl BufView for Bytes {
    type Buf<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        self.as_ref()
    }
}
