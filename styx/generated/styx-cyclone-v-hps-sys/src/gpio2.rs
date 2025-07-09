// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    gpio_swporta_dr: GpioSwportaDr,
    gpio_swporta_ddr: GpioSwportaDdr,
    _reserved2: [u8; 0x28],
    gpio_inten: GpioInten,
    gpio_intmask: GpioIntmask,
    gpio_inttype_level: GpioInttypeLevel,
    gpio_int_polarity: GpioIntPolarity,
    gpio_intstatus: GpioIntstatus,
    gpio_raw_intstatus: GpioRawIntstatus,
    gpio_debounce: GpioDebounce,
    gpio_porta_eoi: GpioPortaEoi,
    gpio_ext_porta: GpioExtPorta,
    _reserved11: [u8; 0x0c],
    gpio_ls_sync: GpioLsSync,
    gpio_id_code: GpioIdCode,
    _reserved13: [u8; 0x04],
    gpio_ver_id_code: GpioVerIdCode,
    gpio_config_reg2: GpioConfigReg2,
    gpio_config_reg1: GpioConfigReg1,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - This GPIO Data register is used to input or output data Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
    #[inline(always)]
    pub const fn gpio_swporta_dr(&self) -> &GpioSwportaDr {
        &self.gpio_swporta_dr
    }
    #[doc = "0x04 - This register establishes the direction of each corresponding GPIO Data Field Bit. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
    #[inline(always)]
    pub const fn gpio_swporta_ddr(&self) -> &GpioSwportaDdr {
        &self.gpio_swporta_ddr
    }
    #[doc = "0x30 - The Interrupt enable register allows interrupts for each bit of the Port A data register."]
    #[inline(always)]
    pub const fn gpio_inten(&self) -> &GpioInten {
        &self.gpio_inten
    }
    #[doc = "0x34 - Controls which pins cause interrupts on Port A Data Register inputs."]
    #[inline(always)]
    pub const fn gpio_intmask(&self) -> &GpioIntmask {
        &self.gpio_intmask
    }
    #[doc = "0x38 - The interrupt level register defines the type of interrupt (edge or level)."]
    #[inline(always)]
    pub const fn gpio_inttype_level(&self) -> &GpioInttypeLevel {
        &self.gpio_inttype_level
    }
    #[doc = "0x3c - Controls the Polarity of Interrupts that can occur on inputs of Port A Data Register"]
    #[inline(always)]
    pub const fn gpio_int_polarity(&self) -> &GpioIntPolarity {
        &self.gpio_int_polarity
    }
    #[doc = "0x40 - The Interrupt status is reported for all Port A Data Register Bits."]
    #[inline(always)]
    pub const fn gpio_intstatus(&self) -> &GpioIntstatus {
        &self.gpio_intstatus
    }
    #[doc = "0x44 - This is the Raw Interrupt Status Register for Port A Data Register. It is used with the Interrupt Mask Register to allow interrupts from the Port A Data Register."]
    #[inline(always)]
    pub const fn gpio_raw_intstatus(&self) -> &GpioRawIntstatus {
        &self.gpio_raw_intstatus
    }
    #[doc = "0x48 - Debounces each IO Pin"]
    #[inline(always)]
    pub const fn gpio_debounce(&self) -> &GpioDebounce {
        &self.gpio_debounce
    }
    #[doc = "0x4c - Port A Data Register interrupt handling."]
    #[inline(always)]
    pub const fn gpio_porta_eoi(&self) -> &GpioPortaEoi {
        &self.gpio_porta_eoi
    }
    #[doc = "0x50 - The external port register is used to input data to the metastability flops."]
    #[inline(always)]
    pub const fn gpio_ext_porta(&self) -> &GpioExtPorta {
        &self.gpio_ext_porta
    }
    #[doc = "0x60 - The Synchronization level register is used to synchronize input with l4_mp_clk"]
    #[inline(always)]
    pub const fn gpio_ls_sync(&self) -> &GpioLsSync {
        &self.gpio_ls_sync
    }
    #[doc = "0x64 - GPIO ID code."]
    #[inline(always)]
    pub const fn gpio_id_code(&self) -> &GpioIdCode {
        &self.gpio_id_code
    }
    #[doc = "0x6c - GPIO Component Version"]
    #[inline(always)]
    pub const fn gpio_ver_id_code(&self) -> &GpioVerIdCode {
        &self.gpio_ver_id_code
    }
    #[doc = "0x70 - Specifies the bit width of port A."]
    #[inline(always)]
    pub const fn gpio_config_reg2(&self) -> &GpioConfigReg2 {
        &self.gpio_config_reg2
    }
    #[doc = "0x74 - Reports settings of various GPIO configuration parameters"]
    #[inline(always)]
    pub const fn gpio_config_reg1(&self) -> &GpioConfigReg1 {
        &self.gpio_config_reg1
    }
}
#[doc = "gpio_swporta_dr (rw) register accessor: This GPIO Data register is used to input or output data Check the GPIO chapter in the handbook for details on how GPIO2 is implemented.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_swporta_dr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_swporta_dr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_swporta_dr`]
module"]
#[doc(alias = "gpio_swporta_dr")]
pub type GpioSwportaDr = crate::Reg<gpio_swporta_dr::GpioSwportaDrSpec>;
#[doc = "This GPIO Data register is used to input or output data Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
pub mod gpio_swporta_dr;
#[doc = "gpio_swporta_ddr (rw) register accessor: This register establishes the direction of each corresponding GPIO Data Field Bit. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_swporta_ddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_swporta_ddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_swporta_ddr`]
module"]
#[doc(alias = "gpio_swporta_ddr")]
pub type GpioSwportaDdr = crate::Reg<gpio_swporta_ddr::GpioSwportaDdrSpec>;
#[doc = "This register establishes the direction of each corresponding GPIO Data Field Bit. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
pub mod gpio_swporta_ddr;
#[doc = "gpio_inten (rw) register accessor: The Interrupt enable register allows interrupts for each bit of the Port A data register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_inten::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_inten::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_inten`]
module"]
#[doc(alias = "gpio_inten")]
pub type GpioInten = crate::Reg<gpio_inten::GpioIntenSpec>;
#[doc = "The Interrupt enable register allows interrupts for each bit of the Port A data register."]
pub mod gpio_inten;
#[doc = "gpio_intmask (rw) register accessor: Controls which pins cause interrupts on Port A Data Register inputs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_intmask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_intmask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_intmask`]
module"]
#[doc(alias = "gpio_intmask")]
pub type GpioIntmask = crate::Reg<gpio_intmask::GpioIntmaskSpec>;
#[doc = "Controls which pins cause interrupts on Port A Data Register inputs."]
pub mod gpio_intmask;
#[doc = "gpio_inttype_level (rw) register accessor: The interrupt level register defines the type of interrupt (edge or level).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_inttype_level::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_inttype_level::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_inttype_level`]
module"]
#[doc(alias = "gpio_inttype_level")]
pub type GpioInttypeLevel = crate::Reg<gpio_inttype_level::GpioInttypeLevelSpec>;
#[doc = "The interrupt level register defines the type of interrupt (edge or level)."]
pub mod gpio_inttype_level;
#[doc = "gpio_int_polarity (rw) register accessor: Controls the Polarity of Interrupts that can occur on inputs of Port A Data Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_int_polarity::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_int_polarity::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_int_polarity`]
module"]
#[doc(alias = "gpio_int_polarity")]
pub type GpioIntPolarity = crate::Reg<gpio_int_polarity::GpioIntPolaritySpec>;
#[doc = "Controls the Polarity of Interrupts that can occur on inputs of Port A Data Register"]
pub mod gpio_int_polarity;
#[doc = "gpio_intstatus (rw) register accessor: The Interrupt status is reported for all Port A Data Register Bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_intstatus::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_intstatus::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_intstatus`]
module"]
#[doc(alias = "gpio_intstatus")]
pub type GpioIntstatus = crate::Reg<gpio_intstatus::GpioIntstatusSpec>;
#[doc = "The Interrupt status is reported for all Port A Data Register Bits."]
pub mod gpio_intstatus;
#[doc = "gpio_raw_intstatus (rw) register accessor: This is the Raw Interrupt Status Register for Port A Data Register. It is used with the Interrupt Mask Register to allow interrupts from the Port A Data Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_raw_intstatus::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_raw_intstatus::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_raw_intstatus`]
module"]
#[doc(alias = "gpio_raw_intstatus")]
pub type GpioRawIntstatus = crate::Reg<gpio_raw_intstatus::GpioRawIntstatusSpec>;
#[doc = "This is the Raw Interrupt Status Register for Port A Data Register. It is used with the Interrupt Mask Register to allow interrupts from the Port A Data Register."]
pub mod gpio_raw_intstatus;
#[doc = "gpio_debounce (rw) register accessor: Debounces each IO Pin\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_debounce::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_debounce::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_debounce`]
module"]
#[doc(alias = "gpio_debounce")]
pub type GpioDebounce = crate::Reg<gpio_debounce::GpioDebounceSpec>;
#[doc = "Debounces each IO Pin"]
pub mod gpio_debounce;
#[doc = "gpio_porta_eoi (w) register accessor: Port A Data Register interrupt handling.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_porta_eoi::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_porta_eoi`]
module"]
#[doc(alias = "gpio_porta_eoi")]
pub type GpioPortaEoi = crate::Reg<gpio_porta_eoi::GpioPortaEoiSpec>;
#[doc = "Port A Data Register interrupt handling."]
pub mod gpio_porta_eoi;
#[doc = "gpio_ext_porta (r) register accessor: The external port register is used to input data to the metastability flops.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_ext_porta::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_ext_porta`]
module"]
#[doc(alias = "gpio_ext_porta")]
pub type GpioExtPorta = crate::Reg<gpio_ext_porta::GpioExtPortaSpec>;
#[doc = "The external port register is used to input data to the metastability flops."]
pub mod gpio_ext_porta;
#[doc = "gpio_ls_sync (rw) register accessor: The Synchronization level register is used to synchronize input with l4_mp_clk\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_ls_sync::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_ls_sync::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_ls_sync`]
module"]
#[doc(alias = "gpio_ls_sync")]
pub type GpioLsSync = crate::Reg<gpio_ls_sync::GpioLsSyncSpec>;
#[doc = "The Synchronization level register is used to synchronize input with l4_mp_clk"]
pub mod gpio_ls_sync;
#[doc = "gpio_id_code (r) register accessor: GPIO ID code.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_id_code::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_id_code`]
module"]
#[doc(alias = "gpio_id_code")]
pub type GpioIdCode = crate::Reg<gpio_id_code::GpioIdCodeSpec>;
#[doc = "GPIO ID code."]
pub mod gpio_id_code;
#[doc = "gpio_ver_id_code (r) register accessor: GPIO Component Version\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_ver_id_code::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_ver_id_code`]
module"]
#[doc(alias = "gpio_ver_id_code")]
pub type GpioVerIdCode = crate::Reg<gpio_ver_id_code::GpioVerIdCodeSpec>;
#[doc = "GPIO Component Version"]
pub mod gpio_ver_id_code;
#[doc = "gpio_config_reg2 (r) register accessor: Specifies the bit width of port A.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_config_reg2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_config_reg2`]
module"]
#[doc(alias = "gpio_config_reg2")]
pub type GpioConfigReg2 = crate::Reg<gpio_config_reg2::GpioConfigReg2Spec>;
#[doc = "Specifies the bit width of port A."]
pub mod gpio_config_reg2;
#[doc = "gpio_config_reg1 (r) register accessor: Reports settings of various GPIO configuration parameters\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_config_reg1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpio_config_reg1`]
module"]
#[doc(alias = "gpio_config_reg1")]
pub type GpioConfigReg1 = crate::Reg<gpio_config_reg1::GpioConfigReg1Spec>;
#[doc = "Reports settings of various GPIO configuration parameters"]
pub mod gpio_config_reg1;
