// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    ctrl: Ctrl,
    bypass: Bypass,
    inter: Inter,
    intren: Intren,
    dbctrl: Dbctrl,
    stat: Stat,
    _reserved6: [u8; 0x28],
    mainpllgrp_vco: MainpllgrpVco,
    mainpllgrp_misc: MainpllgrpMisc,
    mainpllgrp_mpuclk: MainpllgrpMpuclk,
    mainpllgrp_mainclk: MainpllgrpMainclk,
    mainpllgrp_dbgatclk: MainpllgrpDbgatclk,
    mainpllgrp_mainqspiclk: MainpllgrpMainqspiclk,
    mainpllgrp_mainnandsdmmcclk: MainpllgrpMainnandsdmmcclk,
    mainpllgrp_cfgs2fuser0clk: MainpllgrpCfgs2fuser0clk,
    mainpllgrp_en: MainpllgrpEn,
    mainpllgrp_maindiv: MainpllgrpMaindiv,
    mainpllgrp_dbgdiv: MainpllgrpDbgdiv,
    mainpllgrp_tracediv: MainpllgrpTracediv,
    mainpllgrp_l4src: MainpllgrpL4src,
    mainpllgrp_stat: MainpllgrpStat,
    _reserved20: [u8; 0x08],
    perpllgrp_vco: PerpllgrpVco,
    perpllgrp_misc: PerpllgrpMisc,
    perpllgrp_emac0clk: PerpllgrpEmac0clk,
    perpllgrp_emac1clk: PerpllgrpEmac1clk,
    perpllgrp_perqspiclk: PerpllgrpPerqspiclk,
    perpllgrp_pernandsdmmcclk: PerpllgrpPernandsdmmcclk,
    perpllgrp_perbaseclk: PerpllgrpPerbaseclk,
    perpllgrp_s2fuser1clk: PerpllgrpS2fuser1clk,
    perpllgrp_en: PerpllgrpEn,
    perpllgrp_div: PerpllgrpDiv,
    perpllgrp_gpiodiv: PerpllgrpGpiodiv,
    perpllgrp_src: PerpllgrpSrc,
    perpllgrp_stat: PerpllgrpStat,
    _reserved33: [u8; 0x0c],
    sdrpllgrp_vco: SdrpllgrpVco,
    sdrpllgrp_ctrl: SdrpllgrpCtrl,
    sdrpllgrp_ddrdqsclk: SdrpllgrpDdrdqsclk,
    sdrpllgrp_ddr2xdqsclk: SdrpllgrpDdr2xdqsclk,
    sdrpllgrp_ddrdqclk: SdrpllgrpDdrdqclk,
    sdrpllgrp_s2fuser2clk: SdrpllgrpS2fuser2clk,
    sdrpllgrp_en: SdrpllgrpEn,
    sdrpllgrp_stat: SdrpllgrpStat,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Contains fields that control the entire Clock Manager."]
    #[inline(always)]
    pub const fn ctrl(&self) -> &Ctrl {
        &self.ctrl
    }
    #[doc = "0x04 - Contains fields that control bypassing each PLL."]
    #[inline(always)]
    pub const fn bypass(&self) -> &Bypass {
        &self.bypass
    }
    #[doc = "0x08 - Contains fields that indicate the PLL lock status. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn inter(&self) -> &Inter {
        &self.inter
    }
    #[doc = "0x0c - Contain fields that enable the interrupt. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn intren(&self) -> &Intren {
        &self.intren
    }
    #[doc = "0x10 - Contains fields that control the debug clocks."]
    #[inline(always)]
    pub const fn dbctrl(&self) -> &Dbctrl {
        &self.dbctrl
    }
    #[doc = "0x14 - Provides status of Hardware Managed Clock transition State Machine."]
    #[inline(always)]
    pub const fn stat(&self) -> &Stat {
        &self.stat
    }
    #[doc = "0x40 - Contains settings that control the Main PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). The VCO input clock source is always eosc1_clk. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_vco(&self) -> &MainpllgrpVco {
        &self.mainpllgrp_vco
    }
    #[doc = "0x44 - Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_misc(&self) -> &MainpllgrpMisc {
        &self.mainpllgrp_misc
    }
    #[doc = "0x48 - Contains settings that control clock mpu_clk generated from the C0 output of the Main PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_mpuclk(&self) -> &MainpllgrpMpuclk {
        &self.mainpllgrp_mpuclk
    }
    #[doc = "0x4c - Contains settings that control clock main_clk generated from the C1 output of the Main PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_mainclk(&self) -> &MainpllgrpMainclk {
        &self.mainpllgrp_mainclk
    }
    #[doc = "0x50 - Contains settings that control clock dbg_base_clk generated from the C2 output of the Main PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_dbgatclk(&self) -> &MainpllgrpDbgatclk {
        &self.mainpllgrp_dbgatclk
    }
    #[doc = "0x54 - Contains settings that control clock main_qspi_clk generated from the C3 output of the Main PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_mainqspiclk(&self) -> &MainpllgrpMainqspiclk {
        &self.mainpllgrp_mainqspiclk
    }
    #[doc = "0x58 - Contains settings that control clock main_nand_sdmmc_clk generated from the C4 output of the Main PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_mainnandsdmmcclk(&self) -> &MainpllgrpMainnandsdmmcclk {
        &self.mainpllgrp_mainnandsdmmcclk
    }
    #[doc = "0x5c - Contains settings that control clock cfg_s2f_user0_clk generated from the C5 output of the Main PLL. Qsys and user documenation refer to cfg_s2f_user0_clk as cfg_h2f_user0_clk. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_cfgs2fuser0clk(&self) -> &MainpllgrpCfgs2fuser0clk {
        &self.mainpllgrp_cfgs2fuser0clk
    }
    #[doc = "0x60 - Contains fields that control clock enables for clocks derived from the Main PLL. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_en(&self) -> &MainpllgrpEn {
        &self.mainpllgrp_en
    }
    #[doc = "0x64 - Contains fields that control clock dividers for main clocks derived from the Main PLL Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_maindiv(&self) -> &MainpllgrpMaindiv {
        &self.mainpllgrp_maindiv
    }
    #[doc = "0x68 - Contains fields that control clock dividers for debug clocks derived from the Main PLL Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_dbgdiv(&self) -> &MainpllgrpDbgdiv {
        &self.mainpllgrp_dbgdiv
    }
    #[doc = "0x6c - Contains a field that controls the clock divider for the debug trace clock derived from the Main PLL Only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_tracediv(&self) -> &MainpllgrpTracediv {
        &self.mainpllgrp_tracediv
    }
    #[doc = "0x70 - Contains fields that select the clock source for L4 MP and SP APB interconnect Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn mainpllgrp_l4src(&self) -> &MainpllgrpL4src {
        &self.mainpllgrp_l4src
    }
    #[doc = "0x74 - Contains Output Clock Counter Reset acknowledge status."]
    #[inline(always)]
    pub const fn mainpllgrp_stat(&self) -> &MainpllgrpStat {
        &self.mainpllgrp_stat
    }
    #[doc = "0x80 - Contains settings that control the Peripheral PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_vco(&self) -> &PerpllgrpVco {
        &self.perpllgrp_vco
    }
    #[doc = "0x84 - Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_misc(&self) -> &PerpllgrpMisc {
        &self.perpllgrp_misc
    }
    #[doc = "0x88 - Contains settings that control clock emac0_clk generated from the C0 output of the Peripheral PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_emac0clk(&self) -> &PerpllgrpEmac0clk {
        &self.perpllgrp_emac0clk
    }
    #[doc = "0x8c - Contains settings that control clock emac1_clk generated from the C1 output of the Peripheral PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_emac1clk(&self) -> &PerpllgrpEmac1clk {
        &self.perpllgrp_emac1clk
    }
    #[doc = "0x90 - Contains settings that control clock periph_qspi_clk generated from the C2 output of the Peripheral PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_perqspiclk(&self) -> &PerpllgrpPerqspiclk {
        &self.perpllgrp_perqspiclk
    }
    #[doc = "0x94 - Contains settings that control clock periph_nand_sdmmc_clk generated from the C3 output of the Peripheral PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_pernandsdmmcclk(&self) -> &PerpllgrpPernandsdmmcclk {
        &self.perpllgrp_pernandsdmmcclk
    }
    #[doc = "0x98 - Contains settings that control clock periph_base_clk generated from the C4 output of the Peripheral PLL. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_perbaseclk(&self) -> &PerpllgrpPerbaseclk {
        &self.perpllgrp_perbaseclk
    }
    #[doc = "0x9c - Contains settings that control clock s2f_user1_clk generated from the C5 output of the Peripheral PLL. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_s2fuser1clk(&self) -> &PerpllgrpS2fuser1clk {
        &self.perpllgrp_s2fuser1clk
    }
    #[doc = "0xa0 - Contains fields that control clock enables for clocks derived from the Peripheral PLL 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_en(&self) -> &PerpllgrpEn {
        &self.perpllgrp_en
    }
    #[doc = "0xa4 - Contains fields that control clock dividers for clocks derived from the Peripheral PLL Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_div(&self) -> &PerpllgrpDiv {
        &self.perpllgrp_div
    }
    #[doc = "0xa8 - Contains a field that controls the clock divider for the GPIO De-bounce clock. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_gpiodiv(&self) -> &PerpllgrpGpiodiv {
        &self.perpllgrp_gpiodiv
    }
    #[doc = "0xac - Contains fields that select the source clocks for the flash controllers. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn perpllgrp_src(&self) -> &PerpllgrpSrc {
        &self.perpllgrp_src
    }
    #[doc = "0xb0 - Contains Output Clock Counter Reset acknowledge status."]
    #[inline(always)]
    pub const fn perpllgrp_stat(&self) -> &PerpllgrpStat {
        &self.perpllgrp_stat
    }
    #[doc = "0xc0 - Contains settings that control the SDRAM PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_vco(&self) -> &SdrpllgrpVco {
        &self.sdrpllgrp_vco
    }
    #[doc = "0xc4 - Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_ctrl(&self) -> &SdrpllgrpCtrl {
        &self.sdrpllgrp_ctrl
    }
    #[doc = "0xc8 - Contains settings that control clock ddr_dqs_clk generated from the C0 output of the SDRAM PLL. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_ddrdqsclk(&self) -> &SdrpllgrpDdrdqsclk {
        &self.sdrpllgrp_ddrdqsclk
    }
    #[doc = "0xcc - Contains settings that control clock ddr_2x_dqs_clk generated from the C1 output of the SDRAM PLL. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_ddr2xdqsclk(&self) -> &SdrpllgrpDdr2xdqsclk {
        &self.sdrpllgrp_ddr2xdqsclk
    }
    #[doc = "0xd0 - Contains settings that control clock ddr_dq_clk generated from the C2 output of the SDRAM PLL. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_ddrdqclk(&self) -> &SdrpllgrpDdrdqclk {
        &self.sdrpllgrp_ddrdqclk
    }
    #[doc = "0xd4 - Contains settings that control clock s2f_user2_clk generated from the C5 output of the SDRAM PLL. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_s2fuser2clk(&self) -> &SdrpllgrpS2fuser2clk {
        &self.sdrpllgrp_s2fuser2clk
    }
    #[doc = "0xd8 - Contains fields that control the SDRAM Clock Group enables generated from the SDRAM PLL clock outputs. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset."]
    #[inline(always)]
    pub const fn sdrpllgrp_en(&self) -> &SdrpllgrpEn {
        &self.sdrpllgrp_en
    }
    #[doc = "0xdc - Contains Output Clock Counter Reset acknowledge status."]
    #[inline(always)]
    pub const fn sdrpllgrp_stat(&self) -> &SdrpllgrpStat {
        &self.sdrpllgrp_stat
    }
}
#[doc = "ctrl (rw) register accessor: Contains fields that control the entire Clock Manager.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrl`]
module"]
#[doc(alias = "ctrl")]
pub type Ctrl = crate::Reg<ctrl::CtrlSpec>;
#[doc = "Contains fields that control the entire Clock Manager."]
pub mod ctrl;
#[doc = "bypass (rw) register accessor: Contains fields that control bypassing each PLL.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bypass::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bypass::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bypass`]
module"]
#[doc(alias = "bypass")]
pub type Bypass = crate::Reg<bypass::BypassSpec>;
#[doc = "Contains fields that control bypassing each PLL."]
pub mod bypass;
#[doc = "inter (rw) register accessor: Contains fields that indicate the PLL lock status. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`inter::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`inter::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@inter`]
module"]
#[doc(alias = "inter")]
pub type Inter = crate::Reg<inter::InterSpec>;
#[doc = "Contains fields that indicate the PLL lock status. Fields are only reset by a cold reset."]
pub mod inter;
#[doc = "intren (rw) register accessor: Contain fields that enable the interrupt. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`intren::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`intren::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@intren`]
module"]
#[doc(alias = "intren")]
pub type Intren = crate::Reg<intren::IntrenSpec>;
#[doc = "Contain fields that enable the interrupt. Fields are only reset by a cold reset."]
pub mod intren;
#[doc = "dbctrl (rw) register accessor: Contains fields that control the debug clocks.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dbctrl`]
module"]
#[doc(alias = "dbctrl")]
pub type Dbctrl = crate::Reg<dbctrl::DbctrlSpec>;
#[doc = "Contains fields that control the debug clocks."]
pub mod dbctrl;
#[doc = "stat (r) register accessor: Provides status of Hardware Managed Clock transition State Machine.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@stat`]
module"]
#[doc(alias = "stat")]
pub type Stat = crate::Reg<stat::StatSpec>;
#[doc = "Provides status of Hardware Managed Clock transition State Machine."]
pub mod stat;
#[doc = "mainpllgrp_vco (rw) register accessor: Contains settings that control the Main PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). The VCO input clock source is always eosc1_clk. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_vco::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_vco::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_vco`]
module"]
#[doc(alias = "mainpllgrp_vco")]
pub type MainpllgrpVco = crate::Reg<mainpllgrp_vco::MainpllgrpVcoSpec>;
#[doc = "Contains settings that control the Main PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). The VCO input clock source is always eosc1_clk. Fields are only reset by a cold reset."]
pub mod mainpllgrp_vco;
#[doc = "mainpllgrp_misc (rw) register accessor: Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_misc::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_misc::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_misc`]
module"]
#[doc(alias = "mainpllgrp_misc")]
pub type MainpllgrpMisc = crate::Reg<mainpllgrp_misc::MainpllgrpMiscSpec>;
#[doc = "Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset."]
pub mod mainpllgrp_misc;
#[doc = "mainpllgrp_mpuclk (rw) register accessor: Contains settings that control clock mpu_clk generated from the C0 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_mpuclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_mpuclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_mpuclk`]
module"]
#[doc(alias = "mainpllgrp_mpuclk")]
pub type MainpllgrpMpuclk = crate::Reg<mainpllgrp_mpuclk::MainpllgrpMpuclkSpec>;
#[doc = "Contains settings that control clock mpu_clk generated from the C0 output of the Main PLL. Only reset by a cold reset."]
pub mod mainpllgrp_mpuclk;
#[doc = "mainpllgrp_mainclk (rw) register accessor: Contains settings that control clock main_clk generated from the C1 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_mainclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_mainclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_mainclk`]
module"]
#[doc(alias = "mainpllgrp_mainclk")]
pub type MainpllgrpMainclk = crate::Reg<mainpllgrp_mainclk::MainpllgrpMainclkSpec>;
#[doc = "Contains settings that control clock main_clk generated from the C1 output of the Main PLL. Only reset by a cold reset."]
pub mod mainpllgrp_mainclk;
#[doc = "mainpllgrp_dbgatclk (rw) register accessor: Contains settings that control clock dbg_base_clk generated from the C2 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_dbgatclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_dbgatclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_dbgatclk`]
module"]
#[doc(alias = "mainpllgrp_dbgatclk")]
pub type MainpllgrpDbgatclk = crate::Reg<mainpllgrp_dbgatclk::MainpllgrpDbgatclkSpec>;
#[doc = "Contains settings that control clock dbg_base_clk generated from the C2 output of the Main PLL. Only reset by a cold reset."]
pub mod mainpllgrp_dbgatclk;
#[doc = "mainpllgrp_mainqspiclk (rw) register accessor: Contains settings that control clock main_qspi_clk generated from the C3 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_mainqspiclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_mainqspiclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_mainqspiclk`]
module"]
#[doc(alias = "mainpllgrp_mainqspiclk")]
pub type MainpllgrpMainqspiclk = crate::Reg<mainpllgrp_mainqspiclk::MainpllgrpMainqspiclkSpec>;
#[doc = "Contains settings that control clock main_qspi_clk generated from the C3 output of the Main PLL. Only reset by a cold reset."]
pub mod mainpllgrp_mainqspiclk;
#[doc = "mainpllgrp_mainnandsdmmcclk (rw) register accessor: Contains settings that control clock main_nand_sdmmc_clk generated from the C4 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_mainnandsdmmcclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_mainnandsdmmcclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_mainnandsdmmcclk`]
module"]
#[doc(alias = "mainpllgrp_mainnandsdmmcclk")]
pub type MainpllgrpMainnandsdmmcclk =
    crate::Reg<mainpllgrp_mainnandsdmmcclk::MainpllgrpMainnandsdmmcclkSpec>;
#[doc = "Contains settings that control clock main_nand_sdmmc_clk generated from the C4 output of the Main PLL. Only reset by a cold reset."]
pub mod mainpllgrp_mainnandsdmmcclk;
#[doc = "mainpllgrp_cfgs2fuser0clk (rw) register accessor: Contains settings that control clock cfg_s2f_user0_clk generated from the C5 output of the Main PLL. Qsys and user documenation refer to cfg_s2f_user0_clk as cfg_h2f_user0_clk. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_cfgs2fuser0clk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_cfgs2fuser0clk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_cfgs2fuser0clk`]
module"]
#[doc(alias = "mainpllgrp_cfgs2fuser0clk")]
pub type MainpllgrpCfgs2fuser0clk =
    crate::Reg<mainpllgrp_cfgs2fuser0clk::MainpllgrpCfgs2fuser0clkSpec>;
#[doc = "Contains settings that control clock cfg_s2f_user0_clk generated from the C5 output of the Main PLL. Qsys and user documenation refer to cfg_s2f_user0_clk as cfg_h2f_user0_clk. Only reset by a cold reset."]
pub mod mainpllgrp_cfgs2fuser0clk;
#[doc = "mainpllgrp_en (rw) register accessor: Contains fields that control clock enables for clocks derived from the Main PLL. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_en::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_en::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_en`]
module"]
#[doc(alias = "mainpllgrp_en")]
pub type MainpllgrpEn = crate::Reg<mainpllgrp_en::MainpllgrpEnSpec>;
#[doc = "Contains fields that control clock enables for clocks derived from the Main PLL. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset."]
pub mod mainpllgrp_en;
#[doc = "mainpllgrp_maindiv (rw) register accessor: Contains fields that control clock dividers for main clocks derived from the Main PLL Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_maindiv::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_maindiv::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_maindiv`]
module"]
#[doc(alias = "mainpllgrp_maindiv")]
pub type MainpllgrpMaindiv = crate::Reg<mainpllgrp_maindiv::MainpllgrpMaindivSpec>;
#[doc = "Contains fields that control clock dividers for main clocks derived from the Main PLL Fields are only reset by a cold reset."]
pub mod mainpllgrp_maindiv;
#[doc = "mainpllgrp_dbgdiv (rw) register accessor: Contains fields that control clock dividers for debug clocks derived from the Main PLL Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_dbgdiv::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_dbgdiv::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_dbgdiv`]
module"]
#[doc(alias = "mainpllgrp_dbgdiv")]
pub type MainpllgrpDbgdiv = crate::Reg<mainpllgrp_dbgdiv::MainpllgrpDbgdivSpec>;
#[doc = "Contains fields that control clock dividers for debug clocks derived from the Main PLL Fields are only reset by a cold reset."]
pub mod mainpllgrp_dbgdiv;
#[doc = "mainpllgrp_tracediv (rw) register accessor: Contains a field that controls the clock divider for the debug trace clock derived from the Main PLL Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_tracediv::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_tracediv::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_tracediv`]
module"]
#[doc(alias = "mainpllgrp_tracediv")]
pub type MainpllgrpTracediv = crate::Reg<mainpllgrp_tracediv::MainpllgrpTracedivSpec>;
#[doc = "Contains a field that controls the clock divider for the debug trace clock derived from the Main PLL Only reset by a cold reset."]
pub mod mainpllgrp_tracediv;
#[doc = "mainpllgrp_l4src (rw) register accessor: Contains fields that select the clock source for L4 MP and SP APB interconnect Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_l4src::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_l4src::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_l4src`]
module"]
#[doc(alias = "mainpllgrp_l4src")]
pub type MainpllgrpL4src = crate::Reg<mainpllgrp_l4src::MainpllgrpL4srcSpec>;
#[doc = "Contains fields that select the clock source for L4 MP and SP APB interconnect Fields are only reset by a cold reset."]
pub mod mainpllgrp_l4src;
#[doc = "mainpllgrp_stat (r) register accessor: Contains Output Clock Counter Reset acknowledge status.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mainpllgrp_stat`]
module"]
#[doc(alias = "mainpllgrp_stat")]
pub type MainpllgrpStat = crate::Reg<mainpllgrp_stat::MainpllgrpStatSpec>;
#[doc = "Contains Output Clock Counter Reset acknowledge status."]
pub mod mainpllgrp_stat;
#[doc = "perpllgrp_vco (rw) register accessor: Contains settings that control the Peripheral PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_vco::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_vco::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_vco`]
module"]
#[doc(alias = "perpllgrp_vco")]
pub type PerpllgrpVco = crate::Reg<perpllgrp_vco::PerpllgrpVcoSpec>;
#[doc = "Contains settings that control the Peripheral PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset."]
pub mod perpllgrp_vco;
#[doc = "perpllgrp_misc (rw) register accessor: Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_misc::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_misc::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_misc`]
module"]
#[doc(alias = "perpllgrp_misc")]
pub type PerpllgrpMisc = crate::Reg<perpllgrp_misc::PerpllgrpMiscSpec>;
#[doc = "Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset."]
pub mod perpllgrp_misc;
#[doc = "perpllgrp_emac0clk (rw) register accessor: Contains settings that control clock emac0_clk generated from the C0 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_emac0clk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_emac0clk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_emac0clk`]
module"]
#[doc(alias = "perpllgrp_emac0clk")]
pub type PerpllgrpEmac0clk = crate::Reg<perpllgrp_emac0clk::PerpllgrpEmac0clkSpec>;
#[doc = "Contains settings that control clock emac0_clk generated from the C0 output of the Peripheral PLL. Only reset by a cold reset."]
pub mod perpllgrp_emac0clk;
#[doc = "perpllgrp_emac1clk (rw) register accessor: Contains settings that control clock emac1_clk generated from the C1 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_emac1clk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_emac1clk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_emac1clk`]
module"]
#[doc(alias = "perpllgrp_emac1clk")]
pub type PerpllgrpEmac1clk = crate::Reg<perpllgrp_emac1clk::PerpllgrpEmac1clkSpec>;
#[doc = "Contains settings that control clock emac1_clk generated from the C1 output of the Peripheral PLL. Only reset by a cold reset."]
pub mod perpllgrp_emac1clk;
#[doc = "perpllgrp_perqspiclk (rw) register accessor: Contains settings that control clock periph_qspi_clk generated from the C2 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_perqspiclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_perqspiclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_perqspiclk`]
module"]
#[doc(alias = "perpllgrp_perqspiclk")]
pub type PerpllgrpPerqspiclk = crate::Reg<perpllgrp_perqspiclk::PerpllgrpPerqspiclkSpec>;
#[doc = "Contains settings that control clock periph_qspi_clk generated from the C2 output of the Peripheral PLL. Only reset by a cold reset."]
pub mod perpllgrp_perqspiclk;
#[doc = "perpllgrp_pernandsdmmcclk (rw) register accessor: Contains settings that control clock periph_nand_sdmmc_clk generated from the C3 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_pernandsdmmcclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_pernandsdmmcclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_pernandsdmmcclk`]
module"]
#[doc(alias = "perpllgrp_pernandsdmmcclk")]
pub type PerpllgrpPernandsdmmcclk =
    crate::Reg<perpllgrp_pernandsdmmcclk::PerpllgrpPernandsdmmcclkSpec>;
#[doc = "Contains settings that control clock periph_nand_sdmmc_clk generated from the C3 output of the Peripheral PLL. Only reset by a cold reset."]
pub mod perpllgrp_pernandsdmmcclk;
#[doc = "perpllgrp_perbaseclk (rw) register accessor: Contains settings that control clock periph_base_clk generated from the C4 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_perbaseclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_perbaseclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_perbaseclk`]
module"]
#[doc(alias = "perpllgrp_perbaseclk")]
pub type PerpllgrpPerbaseclk = crate::Reg<perpllgrp_perbaseclk::PerpllgrpPerbaseclkSpec>;
#[doc = "Contains settings that control clock periph_base_clk generated from the C4 output of the Peripheral PLL. Only reset by a cold reset."]
pub mod perpllgrp_perbaseclk;
#[doc = "perpllgrp_s2fuser1clk (rw) register accessor: Contains settings that control clock s2f_user1_clk generated from the C5 output of the Peripheral PLL. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_s2fuser1clk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_s2fuser1clk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_s2fuser1clk`]
module"]
#[doc(alias = "perpllgrp_s2fuser1clk")]
pub type PerpllgrpS2fuser1clk = crate::Reg<perpllgrp_s2fuser1clk::PerpllgrpS2fuser1clkSpec>;
#[doc = "Contains settings that control clock s2f_user1_clk generated from the C5 output of the Peripheral PLL. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk. Only reset by a cold reset."]
pub mod perpllgrp_s2fuser1clk;
#[doc = "perpllgrp_en (rw) register accessor: Contains fields that control clock enables for clocks derived from the Peripheral PLL 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_en::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_en::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_en`]
module"]
#[doc(alias = "perpllgrp_en")]
pub type PerpllgrpEn = crate::Reg<perpllgrp_en::PerpllgrpEnSpec>;
#[doc = "Contains fields that control clock enables for clocks derived from the Peripheral PLL 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset."]
pub mod perpllgrp_en;
#[doc = "perpllgrp_div (rw) register accessor: Contains fields that control clock dividers for clocks derived from the Peripheral PLL Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_div::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_div::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_div`]
module"]
#[doc(alias = "perpllgrp_div")]
pub type PerpllgrpDiv = crate::Reg<perpllgrp_div::PerpllgrpDivSpec>;
#[doc = "Contains fields that control clock dividers for clocks derived from the Peripheral PLL Fields are only reset by a cold reset."]
pub mod perpllgrp_div;
#[doc = "perpllgrp_gpiodiv (rw) register accessor: Contains a field that controls the clock divider for the GPIO De-bounce clock. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_gpiodiv::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_gpiodiv::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_gpiodiv`]
module"]
#[doc(alias = "perpllgrp_gpiodiv")]
pub type PerpllgrpGpiodiv = crate::Reg<perpllgrp_gpiodiv::PerpllgrpGpiodivSpec>;
#[doc = "Contains a field that controls the clock divider for the GPIO De-bounce clock. Only reset by a cold reset."]
pub mod perpllgrp_gpiodiv;
#[doc = "perpllgrp_src (rw) register accessor: Contains fields that select the source clocks for the flash controllers. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_src::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_src::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_src`]
module"]
#[doc(alias = "perpllgrp_src")]
pub type PerpllgrpSrc = crate::Reg<perpllgrp_src::PerpllgrpSrcSpec>;
#[doc = "Contains fields that select the source clocks for the flash controllers. Fields are only reset by a cold reset."]
pub mod perpllgrp_src;
#[doc = "perpllgrp_stat (r) register accessor: Contains Output Clock Counter Reset acknowledge status.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@perpllgrp_stat`]
module"]
#[doc(alias = "perpllgrp_stat")]
pub type PerpllgrpStat = crate::Reg<perpllgrp_stat::PerpllgrpStatSpec>;
#[doc = "Contains Output Clock Counter Reset acknowledge status."]
pub mod perpllgrp_stat;
#[doc = "sdrpllgrp_vco (rw) register accessor: Contains settings that control the SDRAM PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_vco::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_vco::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_vco`]
module"]
#[doc(alias = "sdrpllgrp_vco")]
pub type SdrpllgrpVco = crate::Reg<sdrpllgrp_vco::SdrpllgrpVcoSpec>;
#[doc = "Contains settings that control the SDRAM PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset."]
pub mod sdrpllgrp_vco;
#[doc = "sdrpllgrp_ctrl (rw) register accessor: Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_ctrl`]
module"]
#[doc(alias = "sdrpllgrp_ctrl")]
pub type SdrpllgrpCtrl = crate::Reg<sdrpllgrp_ctrl::SdrpllgrpCtrlSpec>;
#[doc = "Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset."]
pub mod sdrpllgrp_ctrl;
#[doc = "sdrpllgrp_ddrdqsclk (rw) register accessor: Contains settings that control clock ddr_dqs_clk generated from the C0 output of the SDRAM PLL. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_ddrdqsclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_ddrdqsclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_ddrdqsclk`]
module"]
#[doc(alias = "sdrpllgrp_ddrdqsclk")]
pub type SdrpllgrpDdrdqsclk = crate::Reg<sdrpllgrp_ddrdqsclk::SdrpllgrpDdrdqsclkSpec>;
#[doc = "Contains settings that control clock ddr_dqs_clk generated from the C0 output of the SDRAM PLL. Fields are only reset by a cold reset."]
pub mod sdrpllgrp_ddrdqsclk;
#[doc = "sdrpllgrp_ddr2xdqsclk (rw) register accessor: Contains settings that control clock ddr_2x_dqs_clk generated from the C1 output of the SDRAM PLL. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_ddr2xdqsclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_ddr2xdqsclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_ddr2xdqsclk`]
module"]
#[doc(alias = "sdrpllgrp_ddr2xdqsclk")]
pub type SdrpllgrpDdr2xdqsclk = crate::Reg<sdrpllgrp_ddr2xdqsclk::SdrpllgrpDdr2xdqsclkSpec>;
#[doc = "Contains settings that control clock ddr_2x_dqs_clk generated from the C1 output of the SDRAM PLL. Fields are only reset by a cold reset."]
pub mod sdrpllgrp_ddr2xdqsclk;
#[doc = "sdrpllgrp_ddrdqclk (rw) register accessor: Contains settings that control clock ddr_dq_clk generated from the C2 output of the SDRAM PLL. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_ddrdqclk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_ddrdqclk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_ddrdqclk`]
module"]
#[doc(alias = "sdrpllgrp_ddrdqclk")]
pub type SdrpllgrpDdrdqclk = crate::Reg<sdrpllgrp_ddrdqclk::SdrpllgrpDdrdqclkSpec>;
#[doc = "Contains settings that control clock ddr_dq_clk generated from the C2 output of the SDRAM PLL. Fields are only reset by a cold reset."]
pub mod sdrpllgrp_ddrdqclk;
#[doc = "sdrpllgrp_s2fuser2clk (rw) register accessor: Contains settings that control clock s2f_user2_clk generated from the C5 output of the SDRAM PLL. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_s2fuser2clk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_s2fuser2clk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_s2fuser2clk`]
module"]
#[doc(alias = "sdrpllgrp_s2fuser2clk")]
pub type SdrpllgrpS2fuser2clk = crate::Reg<sdrpllgrp_s2fuser2clk::SdrpllgrpS2fuser2clkSpec>;
#[doc = "Contains settings that control clock s2f_user2_clk generated from the C5 output of the SDRAM PLL. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk Fields are only reset by a cold reset."]
pub mod sdrpllgrp_s2fuser2clk;
#[doc = "sdrpllgrp_en (rw) register accessor: Contains fields that control the SDRAM Clock Group enables generated from the SDRAM PLL clock outputs. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_en::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_en::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_en`]
module"]
#[doc(alias = "sdrpllgrp_en")]
pub type SdrpllgrpEn = crate::Reg<sdrpllgrp_en::SdrpllgrpEnSpec>;
#[doc = "Contains fields that control the SDRAM Clock Group enables generated from the SDRAM PLL clock outputs. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset."]
pub mod sdrpllgrp_en;
#[doc = "sdrpllgrp_stat (r) register accessor: Contains Output Clock Counter Reset acknowledge status.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdrpllgrp_stat`]
module"]
#[doc(alias = "sdrpllgrp_stat")]
pub type SdrpllgrpStat = crate::Reg<sdrpllgrp_stat::SdrpllgrpStatSpec>;
#[doc = "Contains Output Clock Counter Reset acknowledge status."]
pub mod sdrpllgrp_stat;
