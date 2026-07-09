use bytes::{Buf, Bytes};

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

impl BufView for Box<[u8]> {
    type Buf<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        self.as_ref()
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
