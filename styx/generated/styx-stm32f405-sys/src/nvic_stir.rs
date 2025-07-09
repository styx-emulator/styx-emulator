// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    stir: Stir,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Software trigger interrupt register"]
    #[inline(always)]
    pub const fn stir(&self) -> &Stir {
        &self.stir
    }
}
#[doc = "STIR (rw) register accessor: Software trigger interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stir::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stir::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@stir`]
module"]
#[doc(alias = "STIR")]
pub type Stir = crate::Reg<stir::StirSpec>;
#[doc = "Software trigger interrupt register"]
pub mod stir;
