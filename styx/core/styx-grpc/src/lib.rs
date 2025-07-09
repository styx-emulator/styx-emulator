// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! Central area for gRPC defs, client stubs and services to use.
//!
//! Ideally at some point we can feature gate most of this down
//! so you don't need to import and bulid the entire package of
//! gRPC servers every time.

use tonic::Status;

/// ToArg vec supports the ability to serialize into a vector or string
/// to support [`clap`] argument parsing and generation.
pub trait ToArgVec {
    /// Return a vec of clap style `--argname` `arg_value`
    fn arg_vec(&self) -> Vec<String>;

    /// Return a single string of args
    fn arg_string(&self) -> String {
        self.arg_vec().join(" ")
    }
}

/// trait indicating that a message can be validated
pub trait Validator: Send + Sync + 'static {
    fn is_valid(&self) -> bool;
}

/// Contains all the IO gRPC implementations.
pub mod io {
    pub mod uart {
        tonic::include_proto!("uart");
        /// CPU to peripheral direction
        pub const TX_DIRECTION: Option<subscribe_request::Direction> =
            Some(subscribe_request::Direction::Tx(TxDirection {}));
        // Peripheral to CPU direction
        pub const RX_DIRECTION: Option<subscribe_request::Direction> =
            Some(subscribe_request::Direction::Rx(RxDirection {}));
        pub const BOTH_DIRECTION: Option<subscribe_request::Direction> =
            Some(subscribe_request::Direction::Both(BothDirection {}));
    }
    pub mod i2c {
        tonic::include_proto!("styx.peripherals.i2c");
    }
    pub mod spi {
        tonic::include_proto!("styx.peripherals.spi");
    }
    pub mod ethernet {
        tonic::include_proto!("styx.peripherals.ethernet");
    }
}

pub mod symbolic {
    use tonic::include_proto;

    include_proto!("symbolic");
}
pub mod args;
pub mod db;
pub mod emulation;
pub mod emulation_registry;
pub mod machines;
pub mod traceapp;
pub mod typhunix_interop;
pub mod utils;
pub mod workspace;

pub use typhunix_interop::i64_addr_deser_hex_str8;
pub use typhunix_interop::i64_addr_ser_hex_str8;
pub use typhunix_interop::u64_addr_deser_hex_str8;
pub use typhunix_interop::u64_addr_ser_hex_str8;

/// Try to determine the type of error from the tonic [Status] which
/// occurred, for example, while reading a stream of rpc / grpc messages.
///
/// For example, if `io_err.kind() == ErrorKind::BrokenPipe`, the sender
/// (client) disconnected in the midst of streaming.
pub fn match_io_error(err_status: &Status) -> Option<&std::io::Error> {
    let mut err: &(dyn std::error::Error + 'static) = err_status;
    loop {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return Some(io_err);
        }
        // h2::Error do not expose std::io::Error with `source()`
        // https://github.com/hyperium/h2/pull/462
        if let Some(h2_err) = err.downcast_ref::<h2::Error>() {
            if let Some(io_err) = h2_err.get_io() {
                return Some(io_err);
            }
        }
        err = err.source()?;
    }
}
