// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    dbgmcu_idcode: DbgmcuIdcode,
    dbgmcu_cr: DbgmcuCr,
    dbgmcu_apb1_fz: DbgmcuApb1Fz,
    dbgmcu_apb2_fz: DbgmcuApb2Fz,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - IDCODE"]
    #[inline(always)]
    pub const fn dbgmcu_idcode(&self) -> &DbgmcuIdcode {
        &self.dbgmcu_idcode
    }
    #[doc = "0x04 - Control Register"]
    #[inline(always)]
    pub const fn dbgmcu_cr(&self) -> &DbgmcuCr {
        &self.dbgmcu_cr
    }
    #[doc = "0x08 - Debug MCU APB1 Freeze registe"]
    #[inline(always)]
    pub const fn dbgmcu_apb1_fz(&self) -> &DbgmcuApb1Fz {
        &self.dbgmcu_apb1_fz
    }
    #[doc = "0x0c - Debug MCU APB2 Freeze registe"]
    #[inline(always)]
    pub const fn dbgmcu_apb2_fz(&self) -> &DbgmcuApb2Fz {
        &self.dbgmcu_apb2_fz
    }
}
#[doc = "DBGMCU_IDCODE (r) register accessor: IDCODE\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_idcode::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dbgmcu_idcode`]
module"]
#[doc(alias = "DBGMCU_IDCODE")]
pub type DbgmcuIdcode = crate::Reg<dbgmcu_idcode::DbgmcuIdcodeSpec>;
#[doc = "IDCODE"]
pub mod dbgmcu_idcode;
#[doc = "DBGMCU_CR (rw) register accessor: Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbgmcu_cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dbgmcu_cr`]
module"]
#[doc(alias = "DBGMCU_CR")]
pub type DbgmcuCr = crate::Reg<dbgmcu_cr::DbgmcuCrSpec>;
#[doc = "Control Register"]
pub mod dbgmcu_cr;
#[doc = "DBGMCU_APB1_FZ (rw) register accessor: Debug MCU APB1 Freeze registe\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_apb1_fz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbgmcu_apb1_fz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dbgmcu_apb1_fz`]
module"]
#[doc(alias = "DBGMCU_APB1_FZ")]
pub type DbgmcuApb1Fz = crate::Reg<dbgmcu_apb1_fz::DbgmcuApb1FzSpec>;
#[doc = "Debug MCU APB1 Freeze registe"]
pub mod dbgmcu_apb1_fz;
#[doc = "DBGMCU_APB2_FZ (rw) register accessor: Debug MCU APB2 Freeze registe\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_apb2_fz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbgmcu_apb2_fz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dbgmcu_apb2_fz`]
module"]
#[doc(alias = "DBGMCU_APB2_FZ")]
pub type DbgmcuApb2Fz = crate::Reg<dbgmcu_apb2_fz::DbgmcuApb2FzSpec>;
#[doc = "Debug MCU APB2 Freeze registe"]
pub mod dbgmcu_apb2_fz;
