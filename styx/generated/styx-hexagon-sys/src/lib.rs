// SPDX-License-Identifier: BSD-2-Clause
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_cast)]

pub mod clade {
    include!(concat!(env!("OUT_DIR"), "/clade.rs"));
}
