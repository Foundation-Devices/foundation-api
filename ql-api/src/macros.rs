macro_rules! impl_codec {
    ($ty:ty) => {
        impl ql_rpc::RpcCodec for $ty {
            type Error = crate::Error;

            fn encode_value<B: bytes::BufMut + ?Sized>(&self, out: &mut B) {
                $crate::codec::encode_cbor(self, out);
            }

            fn decode_value<B: bytes::Buf>(
                bytes: &mut B,
            ) -> Result<Self, <Self as ql_rpc::RpcCodec>::Error> {
                $crate::codec::decode_cbor(bytes)
            }
        }
    };
}

macro_rules! routes {
    ($($service:ident => $route_enum:ident { $($route:ident = $id:literal,)* })*) => {
        $(
            #[repr(u32)]
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub enum $route_enum {
                $($route = $id,)*
            }

            impl $route_enum {
                pub const fn id(self) -> ql_common::RouteId {
                    ql_common::RouteId::from_u32(self as u32)
                }
            }
        )*

        pub mod route {
            $(
                $(
                    #[derive(Debug)]
                    pub struct $route;

                    impl ql_rpc::Route for $route {
                        const SERVICE: ql_common::ServiceId = crate::$service;
                        const ROUTE: ql_common::RouteId = super::$route_enum::$route.id();
                    }
                )*
            )*
        }
    };
}

macro_rules! rpc {
    ($(#[$attr:meta])* $vis:vis struct $name:ident;) => {
        compile_error!("rpc! does not support unit structs");
    };
    (#[PartialEq] $(#[$attr:meta])* $vis:vis struct $name:ident $($body:tt)+) => {
        rpc_item!(PartialEq; $(#[$attr])* $vis struct $name $($body)+);
    };
    ($(#[$attr:meta])* $vis:vis struct $name:ident $($body:tt)+) => {
        rpc_item!(Eq; $(#[$attr])* $vis struct $name $($body)+);
    };
    (#[PartialEq] $(#[$attr:meta])* $vis:vis enum $name:ident $($body:tt)+) => {
        rpc_item!(PartialEq; $(#[$attr])* $vis enum $name $($body)+);
    };
    ($(#[$attr:meta])* $vis:vis enum $name:ident $($body:tt)+) => {
        rpc_item!(Eq; $(#[$attr])* $vis enum $name $($body)+);
    };
}

macro_rules! rpc_item {
    (PartialEq; $(#[$attr:meta])* $vis:vis $kind:ident $name:ident $($body:tt)+) => {
        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        $(#[$attr])*
        #[cfg_attr(feature = "frb", flutter_rust_bridge::frb(non_opaque))]
        $vis $kind $name $($body)+

        impl_codec!($name);
    };
    (Eq; $(#[$attr:meta])* $vis:vis $kind:ident $name:ident $($body:tt)+) => {
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        $(#[$attr])*
        #[cfg_attr(feature = "frb", flutter_rust_bridge::frb(non_opaque))]
        $vis $kind $name $($body)+

        impl_codec!($name);
    };
}
