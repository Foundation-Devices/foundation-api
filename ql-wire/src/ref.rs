use core::{
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use crate::{ByteSlice, ByteSliceMut};

/// Typed bytes backed by a mutable or immutable byte slice.
///
/// Unlike `zerocopy::Ref`, this type does not perform any size, alignment, or
/// layout validation for `T`. `T` is only a marker carried alongside the bytes.
pub struct Ref<B, T: ?Sized> {
    bytes: B,
    _marker: PhantomData<*const T>,
}

impl<B, T: ?Sized> Ref<B, T> {
    pub const fn new(bytes: B) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    pub fn into_bytes(self) -> B {
        self.bytes
    }

    pub fn retag<U: ?Sized>(self) -> Ref<B, U> {
        Ref::new(self.bytes)
    }
}

impl<B: ByteSlice, T: ?Sized> Ref<B, T> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.deref()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn reborrow(&self) -> Ref<&[u8], T> {
        Ref::new(self.bytes())
    }
}

impl<B: ByteSliceMut, T: ?Sized> Ref<B, T> {
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes.deref_mut()
    }

    pub fn reborrow_mut(&mut self) -> Ref<&mut [u8], T> {
        Ref::new(self.bytes_mut())
    }
}

impl<B: ByteSlice, T: ?Sized> Deref for Ref<B, T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

impl<B: ByteSliceMut, T: ?Sized> DerefMut for Ref<B, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.bytes_mut()
    }
}

impl<B: Clone, T: ?Sized> Clone for Ref<B, T> {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

impl<B: Copy, T: ?Sized> Copy for Ref<B, T> {}

impl<B: ByteSlice, T: ?Sized> AsRef<[u8]> for Ref<B, T> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl<B: ByteSliceMut, T: ?Sized> AsMut<[u8]> for Ref<B, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes_mut()
    }
}

impl<B: ByteSlice, T: ?Sized> fmt::Debug for Ref<B, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ref")
            .field("type", &core::any::type_name::<T>())
            .field("bytes", &self.bytes())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Ref;

    struct Message;
    struct OtherMessage;

    #[test]
    fn shared_ref_exposes_bytes() {
        let bytes = b"hello";
        let reference = Ref::<_, Message>::new(&bytes[..]);

        assert_eq!(reference.bytes(), b"hello");
        assert_eq!(reference.len(), 5);
        assert!(!reference.is_empty());
    }

    #[test]
    fn mutable_ref_exposes_mutable_bytes() {
        let mut bytes = *b"hello";
        let mut reference = Ref::<_, Message>::new(&mut bytes[..]);

        reference.bytes_mut()[0] = b'j';
        assert_eq!(&bytes, b"jello");
    }

    #[test]
    fn ref_can_be_retagged() {
        let bytes = b"hello";
        let reference = Ref::<_, Message>::new(&bytes[..]);
        let other = reference.retag::<OtherMessage>();

        assert_eq!(other.bytes(), b"hello");
    }

    #[test]
    fn ref_can_be_reborrowed() {
        let bytes = b"hello";
        let reference = Ref::<_, Message>::new(&bytes[..]);
        let borrowed = reference.reborrow();

        assert_eq!(borrowed.bytes(), b"hello");
    }

    #[test]
    fn mutable_ref_can_be_reborrowed_mutably() {
        let mut bytes = *b"hello";
        let mut reference = Ref::<_, Message>::new(&mut bytes[..]);

        {
            let mut borrowed = reference.reborrow_mut();
            borrowed[1] = b'a';
        }

        assert_eq!(&bytes, b"hallo");
    }
}
