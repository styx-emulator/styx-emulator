// SPDX-License-Identifier: BSD-2-Clause
/// A CPU that Styx supports emulation for.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types, unused)]
pub enum StyxTarget {
    CycloneV,
    Mpc8xx,
    Ppc4xx,
    Kinetis21,
    Stm32f107,
    Stm32f405,
    Bf512,
    Raw,
    SuperH2A,
}
