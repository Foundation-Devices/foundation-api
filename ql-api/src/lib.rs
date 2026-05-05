// 1. list catalog of apps (request/response)
// 2. get app by id
// 3. download version?

mod codec;
mod app_store;
mod benchmark;
mod bootstrap;

pub use app_store::*;
pub use benchmark::*;
pub use bootstrap::*;

pub type Error = ciborium::de::Error<std::io::Error>;

pub const SERVICE_ID: ql_rpc::ServiceId = ql_rpc::ServiceId([0; 16]);

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    // setup
    BootstrapQlv1 = 100,

    // app store
    ListApps = 200,
    AppDownload = 201,

    // debug
    Echo = 1000,
    BytesBenchmark = 1001,
    DownloadBenchmark = 1002,
}

impl Route {
    pub const fn id(self) -> ql_rpc::RouteId {
        ql_rpc::RouteId::from_u32(self as u32)
    }
}
