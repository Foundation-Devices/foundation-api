use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PingBody;
