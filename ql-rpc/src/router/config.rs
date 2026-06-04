#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterConfig {
    pub max_request_bytes: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: usize::MAX,
        }
    }
}
