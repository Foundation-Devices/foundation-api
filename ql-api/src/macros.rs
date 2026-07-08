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

macro_rules! duplicate_route_check {
    ($($id:literal,)*) => {
        const _: () = {
            const IDS: &[u32] = &[$($id,)*];
            let mut i = 0;
            while i < IDS.len() {
                let mut j = i + 1;
                while j < IDS.len() {
                    assert!(IDS[i] != IDS[j], "duplicate route id");
                    j += 1;
                }
                i += 1;
            }
        };
    };
}

macro_rules! assert_route_impl {
    ($route:ident: $kind:ident) => {
        const _: () = {
            struct Assert<T: ql_rpc::$kind>(core::marker::PhantomData<T>);
            let _ = Assert::<$route>(core::marker::PhantomData);
        };
    };
}

macro_rules! service_routes {
    ($service_id:expr => { $($route:ident: $kind:ident = $id:literal,)* }) => {
        duplicate_route_check!($($id,)*);

        $(
            #[derive(Debug)]
            pub struct $route;

            impl ql_rpc::Route for $route {
                type Key = crate::ServiceRouteKey;

                fn key() -> Self::Key {
                    crate::ServiceRouteKey {
                        service_id: $service_id,
                        route_id: ql_keyos::RouteId($id),
                    }
                }
            }

            assert_route_impl!($route: $kind);
        )*
    };
}

macro_rules! app_routes {
    ($app_id:expr => { $($route:ident: $kind:ident = $id:literal,)* }) => {
        duplicate_route_check!($($id,)*);

        $(
            #[derive(Debug)]
            pub struct $route;

            impl ql_rpc::Route for $route {
                type Key = crate::AppRouteKey;

                fn key() -> Self::Key {
                    crate::AppRouteKey {
                        app_id: $app_id,
                        route_id: ql_keyos::RouteId($id),
                    }
                }
            }

            assert_route_impl!($route: $kind);
        )*
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
