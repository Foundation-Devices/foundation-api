use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnpairBody;
