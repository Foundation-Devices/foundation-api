#![allow(unused_imports, unused_macros)]

#[cfg(any(feature = "log", test))]
macro_rules! log {
    ($level:ident, $($arg:tt)*) => {
        ::log::log!(::log::Level::$level, $($arg)*)
    };
}

#[cfg(not(any(feature = "log", test)))]
macro_rules! log {
    ($level:ident, $($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::log::log!(Trace, $($arg)*)
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::log::log!(Debug, $($arg)*)
    };
}

macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log::log!(Info, $($arg)*)
    };
}

macro_rules! warn_ {
    ($($arg:tt)*) => {
        $crate::log::log!(Warn, $($arg)*)
    };
}

macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log::log!(Error, $($arg)*)
    };
}

pub(crate) use debug;
pub(crate) use error;
pub(crate) use info;
pub(crate) use log;
pub(crate) use trace;
pub(crate) use warn_ as warn;
