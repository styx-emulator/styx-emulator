// SPDX-License-Identifier: BSD-2-Clause
//! All services relating to `styx_machines`

pub use super::utils;

pub mod processor {
    tonic::include_proto!("processor");
}
