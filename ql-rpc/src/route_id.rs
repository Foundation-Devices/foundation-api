#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RouteId(pub u32);

impl RouteId {
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    pub const fn into_inner(self) -> u32 {
        self.0
    }
}

impl From<u32> for RouteId {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}
