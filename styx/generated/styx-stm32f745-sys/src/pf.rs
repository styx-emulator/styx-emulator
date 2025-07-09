// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    clidr: Clidr,
    ctr: Ctr,
    ccsidr: Ccsidr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Cache Level ID register"]
    #[inline(always)]
    pub const fn clidr(&self) -> &Clidr {
        &self.clidr
    }
    #[doc = "0x04 - Cache Type register"]
    #[inline(always)]
    pub const fn ctr(&self) -> &Ctr {
        &self.ctr
    }
    #[doc = "0x08 - Cache Size ID register"]
    #[inline(always)]
    pub const fn ccsidr(&self) -> &Ccsidr {
        &self.ccsidr
    }
}
#[doc = "CLIDR (r) register accessor: Cache Level ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clidr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@clidr`]
module"]
#[doc(alias = "CLIDR")]
pub type Clidr = crate::Reg<clidr::ClidrSpec>;
#[doc = "Cache Level ID register"]
pub mod clidr;
#[doc = "CTR (r) register accessor: Cache Type register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctr`]
module"]
#[doc(alias = "CTR")]
pub type Ctr = crate::Reg<ctr::CtrSpec>;
#[doc = "Cache Type register"]
pub mod ctr;
#[doc = "CCSIDR (r) register accessor: Cache Size ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccsidr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ccsidr`]
module"]
#[doc(alias = "CCSIDR")]
pub type Ccsidr = crate::Reg<ccsidr::CcsidrSpec>;
#[doc = "Cache Size ID register"]
pub mod ccsidr;
