// SPDX-License-Identifier: BSD-2-Clause
//! Blackfin processor headers.
//!
//! Currently only generates bf512 headers.
//!
//! FIXME add other variants, blocked behind feature flags
//!
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_cast)]

pub mod bf512 {
    include!(concat!(env!("OUT_DIR"), "/bf512.rs"));
}

#[cfg(test)]
mod tests {
    use super::bf512;

    #[test]
    fn test_bf512_sanity() {
        let sic_imask = bf512::SIC_IMASK0;

        assert_eq!(sic_imask, 0xFFC0_010C)
    }
}
