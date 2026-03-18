use rkyv::{Archive, Deserialize, Serialize};

use crate::encrypted::stream::CloseCode;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionCloseBody {
    pub code: CloseCode,
}
