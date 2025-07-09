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
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    wdt_cr: WdtCr,
    wdt_torr: WdtTorr,
    wdt_ccvr: WdtCcvr,
    wdt_crr: WdtCrr,
    wdt_stat: WdtStat,
    wdt_eoi: WdtEoi,
    _reserved6: [u8; 0xcc],
    cp_wdt_user_top_max: CpWdtUserTopMax,
    cp_wdt_user_top_init_max: CpWdtUserTopInitMax,
    cd_wdt_top_rst: CdWdtTopRst,
    cp_wdt_cnt_rst: CpWdtCntRst,
    wdt_comp_param_1: WdtCompParam1,
    wdt_comp_version: WdtCompVersion,
    wdt_comp_type: WdtCompType,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Contains fields that control operating functions."]
    #[inline(always)]
    pub const fn wdt_cr(&self) -> &WdtCr {
        &self.wdt_cr
    }
    #[doc = "0x04 - Contains fields that determine the watchdog timeout."]
    #[inline(always)]
    pub const fn wdt_torr(&self) -> &WdtTorr {
        &self.wdt_torr
    }
    #[doc = "0x08 - See Field Description"]
    #[inline(always)]
    pub const fn wdt_ccvr(&self) -> &WdtCcvr {
        &self.wdt_ccvr
    }
    #[doc = "0x0c - Restarts the watchdog."]
    #[inline(always)]
    pub const fn wdt_crr(&self) -> &WdtCrr {
        &self.wdt_crr
    }
    #[doc = "0x10 - Provides interrupt status"]
    #[inline(always)]
    pub const fn wdt_stat(&self) -> &WdtStat {
        &self.wdt_stat
    }
    #[doc = "0x14 - Clears the watchdog interrupt when read."]
    #[inline(always)]
    pub const fn wdt_eoi(&self) -> &WdtEoi {
        &self.wdt_eoi
    }
    #[doc = "0xe4 - This is a constant read-only register that contains encoded information about the component's parameter settings."]
    #[inline(always)]
    pub const fn cp_wdt_user_top_max(&self) -> &CpWdtUserTopMax {
        &self.cp_wdt_user_top_max
    }
    #[doc = "0xe8 - This is a constant read-only register that contains encoded information about the component's parameter settings"]
    #[inline(always)]
    pub const fn cp_wdt_user_top_init_max(&self) -> &CpWdtUserTopInitMax {
        &self.cp_wdt_user_top_init_max
    }
    #[doc = "0xec - This is a constant read-only register that contains encoded information about the component's parameter settings."]
    #[inline(always)]
    pub const fn cd_wdt_top_rst(&self) -> &CdWdtTopRst {
        &self.cd_wdt_top_rst
    }
    #[doc = "0xf0 - This is a constant read-only register that contains encoded information about the component's parameter settings."]
    #[inline(always)]
    pub const fn cp_wdt_cnt_rst(&self) -> &CpWdtCntRst {
        &self.cp_wdt_cnt_rst
    }
    #[doc = "0xf4 - This is a constant read-only register that contains encoded information about the component's parameter settings."]
    #[inline(always)]
    pub const fn wdt_comp_param_1(&self) -> &WdtCompParam1 {
        &self.wdt_comp_param_1
    }
    #[doc = "0xf8 - "]
    #[inline(always)]
    pub const fn wdt_comp_version(&self) -> &WdtCompVersion {
        &self.wdt_comp_version
    }
    #[doc = "0xfc - "]
    #[inline(always)]
    pub const fn wdt_comp_type(&self) -> &WdtCompType {
        &self.wdt_comp_type
    }
}
#[doc = "wdt_cr (rw) register accessor: Contains fields that control operating functions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_cr`]
module"]
#[doc(alias = "wdt_cr")]
pub type WdtCr = crate::Reg<wdt_cr::WdtCrSpec>;
#[doc = "Contains fields that control operating functions."]
pub mod wdt_cr;
#[doc = "wdt_torr (rw) register accessor: Contains fields that determine the watchdog timeout.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_torr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_torr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_torr`]
module"]
#[doc(alias = "wdt_torr")]
pub type WdtTorr = crate::Reg<wdt_torr::WdtTorrSpec>;
#[doc = "Contains fields that determine the watchdog timeout."]
pub mod wdt_torr;
#[doc = "wdt_ccvr (r) register accessor: See Field Description\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_ccvr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_ccvr`]
module"]
#[doc(alias = "wdt_ccvr")]
pub type WdtCcvr = crate::Reg<wdt_ccvr::WdtCcvrSpec>;
#[doc = "See Field Description"]
pub mod wdt_ccvr;
#[doc = "wdt_crr (w) register accessor: Restarts the watchdog.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_crr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_crr`]
module"]
#[doc(alias = "wdt_crr")]
pub type WdtCrr = crate::Reg<wdt_crr::WdtCrrSpec>;
#[doc = "Restarts the watchdog."]
pub mod wdt_crr;
#[doc = "wdt_stat (r) register accessor: Provides interrupt status\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_stat`]
module"]
#[doc(alias = "wdt_stat")]
pub type WdtStat = crate::Reg<wdt_stat::WdtStatSpec>;
#[doc = "Provides interrupt status"]
pub mod wdt_stat;
#[doc = "wdt_eoi (r) register accessor: Clears the watchdog interrupt when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_eoi::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_eoi`]
module"]
#[doc(alias = "wdt_eoi")]
pub type WdtEoi = crate::Reg<wdt_eoi::WdtEoiSpec>;
#[doc = "Clears the watchdog interrupt when read."]
pub mod wdt_eoi;
#[doc = "cp_wdt_user_top_max (r) register accessor: This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_user_top_max::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cp_wdt_user_top_max`]
module"]
#[doc(alias = "cp_wdt_user_top_max")]
pub type CpWdtUserTopMax = crate::Reg<cp_wdt_user_top_max::CpWdtUserTopMaxSpec>;
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings."]
pub mod cp_wdt_user_top_max;
#[doc = "cp_wdt_user_top_init_max (r) register accessor: This is a constant read-only register that contains encoded information about the component's parameter settings\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_user_top_init_max::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cp_wdt_user_top_init_max`]
module"]
#[doc(alias = "cp_wdt_user_top_init_max")]
pub type CpWdtUserTopInitMax = crate::Reg<cp_wdt_user_top_init_max::CpWdtUserTopInitMaxSpec>;
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings"]
pub mod cp_wdt_user_top_init_max;
#[doc = "cd_wdt_top_rst (r) register accessor: This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cd_wdt_top_rst::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cd_wdt_top_rst`]
module"]
#[doc(alias = "cd_wdt_top_rst")]
pub type CdWdtTopRst = crate::Reg<cd_wdt_top_rst::CdWdtTopRstSpec>;
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings."]
pub mod cd_wdt_top_rst;
#[doc = "cp_wdt_cnt_rst (r) register accessor: This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_cnt_rst::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cp_wdt_cnt_rst`]
module"]
#[doc(alias = "cp_wdt_cnt_rst")]
pub type CpWdtCntRst = crate::Reg<cp_wdt_cnt_rst::CpWdtCntRstSpec>;
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings."]
pub mod cp_wdt_cnt_rst;
#[doc = "wdt_comp_param_1 (r) register accessor: This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_comp_param_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_comp_param_1`]
module"]
#[doc(alias = "wdt_comp_param_1")]
pub type WdtCompParam1 = crate::Reg<wdt_comp_param_1::WdtCompParam1Spec>;
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings."]
pub mod wdt_comp_param_1;
#[doc = "wdt_comp_version (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_comp_version::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_comp_version`]
module"]
#[doc(alias = "wdt_comp_version")]
pub type WdtCompVersion = crate::Reg<wdt_comp_version::WdtCompVersionSpec>;
#[doc = ""]
pub mod wdt_comp_version;
#[doc = "wdt_comp_type (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_comp_type::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wdt_comp_type`]
module"]
#[doc(alias = "wdt_comp_type")]
pub type WdtCompType = crate::Reg<wdt_comp_type::WdtCompTypeSpec>;
#[doc = ""]
pub mod wdt_comp_type;
