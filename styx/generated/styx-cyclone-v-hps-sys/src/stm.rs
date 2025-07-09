// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    reg: Reg,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Placeholder"]
    #[inline(always)]
    pub const fn reg(&self) -> &Reg {
        &self.reg
    }
}
#[doc = "reg (rw) register accessor: Placeholder\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`reg::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`reg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@reg`]
module"]
#[doc(alias = "reg")]
pub type Reg = crate::Reg<reg::RegSpec>;
#[doc = "Placeholder"]
pub mod reg;
