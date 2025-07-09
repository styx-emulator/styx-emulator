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
    stat: Stat,
    ctrl: Ctrl,
    dclkcnt: Dclkcnt,
    dclkstat: Dclkstat,
    gpo: Gpo,
    gpi: Gpi,
    misci: Misci,
    _reserved7: [u8; 0x0814],
    mon_gpio_inten: MonGpioInten,
    mon_gpio_intmask: MonGpioIntmask,
    mon_gpio_inttype_level: MonGpioInttypeLevel,
    mon_gpio_int_polarity: MonGpioIntPolarity,
    mon_gpio_intstatus: MonGpioIntstatus,
    mon_gpio_raw_intstatus: MonGpioRawIntstatus,
    _reserved13: [u8; 0x04],
    mon_gpio_porta_eoi: MonGpioPortaEoi,
    mon_gpio_ext_porta: MonGpioExtPorta,
    _reserved15: [u8; 0x0c],
    mon_gpio_ls_sync: MonGpioLsSync,
    _reserved16: [u8; 0x08],
    mon_gpio_ver_id_code: MonGpioVerIdCode,
    mon_gpio_config_reg2: MonGpioConfigReg2,
    mon_gpio_config_reg1: MonGpioConfigReg1,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Provides status fields for software for the FPGA Manager. The Mode field tells software what configuration phase the FPGA currently is in. For regular configuration through the PINs or through the HPS, these states map directly to customer configuration documentation. For Configuration Via PCI Express (CVP), the IOCSR configuration is done through the PINS or through HPS. Then the complete configuration is done through the PCI Express Bus. When CVP is being done, InitPhase indicates only IOCSR configuration has completed. CVP_CONF_DONE is available in the CB Monitor for observation by software. The MSEL field provides a read only register for software to read the MSEL value driven from the external pins."]
    #[inline(always)]
    pub const fn stat(&self) -> &Stat {
        &self.stat
    }
    #[doc = "0x04 - Allows HPS to control FPGA configuration. The NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields drive signals to the FPGA Control Block that are logically ORed into their respective pins. These signals are always driven independent of the value of EN. The polarity of the NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields is inverted relative to their associated pins. The MSEL (external pins), CDRATIO and CFGWDTH signals determine the mode of operation for Normal Configuration. For Partial Reconfiguration, CDRATIO is used to set the appropriate clock to data ratio, and CFGWDTH should always be set to 16-bit Passive Parallel. AXICFGEN is used to enable transfer of configuration data by enabling or disabling DCLK during data transfers."]
    #[inline(always)]
    pub const fn ctrl(&self) -> &Ctrl {
        &self.ctrl
    }
    #[doc = "0x08 - Used to give software control in enabling DCLK at any time. SW will need control of the DCLK in specific configuration and partial reconfiguration initialization steps to send spurious DCLKs required by the CB. SW takes ownership for DCLK during normal configuration, partial reconfiguration, error scenerio handshakes including SEU CRC error during partial reconfiguration, SW early abort of partial reconfiguration, and initializatin phase DCLK driving. During initialization phase, a configuration image loaded into the FPGA can request that DCLK be used as the initialization phase clock instead of the default internal oscillator or optionally the CLKUSR pin. In the case that DCLK is requested, the DCLKCNT register is used by software to control DCLK during the initialization phase. Software should poll the DCLKSTAT.DCNTDONE write one to clear register to be set when the correct number of DCLKs have completed. Software should clear DCLKSTAT.DCNTDONE before writing to the DCLKCNT register again. This field only affects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    pub const fn dclkcnt(&self) -> &Dclkcnt {
        &self.dclkcnt
    }
    #[doc = "0x0c - This write one to clear register indicates that the DCLKCNT has counted down to zero. The DCLKCNT is used by software to drive spurious DCLKs to the FPGA. Software will poll this bit after writing DCLKCNT to know when all of the DCLKs have been sent."]
    #[inline(always)]
    pub const fn dclkstat(&self) -> &Dclkstat {
        &self.dclkstat
    }
    #[doc = "0x10 - Provides a low-latency, low-performance, and simple way to drive general-purpose signals to the FPGA fabric."]
    #[inline(always)]
    pub const fn gpo(&self) -> &Gpo {
        &self.gpo
    }
    #[doc = "0x14 - Provides a low-latency, low-performance, and simple way to read general-purpose signals driven from the FPGA fabric."]
    #[inline(always)]
    pub const fn gpi(&self) -> &Gpi {
        &self.gpi
    }
    #[doc = "0x18 - Provides a low-latency, low-performance, and simple way to read specific handshaking signals driven from the FPGA fabric."]
    #[inline(always)]
    pub const fn misci(&self) -> &Misci {
        &self.misci
    }
    #[doc = "0x830 - Allows each bit of Port A to be configured to generate an interrupt or not."]
    #[inline(always)]
    pub const fn mon_gpio_inten(&self) -> &MonGpioInten {
        &self.mon_gpio_inten
    }
    #[doc = "0x834 - This register has 12 individual interrupt masks for the MON. Controls whether an interrupt on Port A can create an interrupt for the interrupt controller by not masking it. By default, all interrupts bits are unmasked. Whenever a 1 is written to a bit in this register, it masks the interrupt generation capability for this signal; otherwise interrupts are allowed through. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub const fn mon_gpio_intmask(&self) -> &MonGpioIntmask {
        &self.mon_gpio_intmask
    }
    #[doc = "0x838 - The interrupt level register defines the type of interrupt (edge or level) for each GPIO input."]
    #[inline(always)]
    pub const fn mon_gpio_inttype_level(&self) -> &MonGpioInttypeLevel {
        &self.mon_gpio_inttype_level
    }
    #[doc = "0x83c - Controls the polarity of interrupts that can occur on each GPIO input."]
    #[inline(always)]
    pub const fn mon_gpio_int_polarity(&self) -> &MonGpioIntPolarity {
        &self.mon_gpio_int_polarity
    }
    #[doc = "0x840 - Reports on interrupt status for each GPIO input. The interrupt status includes the effects of masking."]
    #[inline(always)]
    pub const fn mon_gpio_intstatus(&self) -> &MonGpioIntstatus {
        &self.mon_gpio_intstatus
    }
    #[doc = "0x844 - Reports on raw interrupt status for each GPIO input. The raw interrupt status excludes the effects of masking."]
    #[inline(always)]
    pub const fn mon_gpio_raw_intstatus(&self) -> &MonGpioRawIntstatus {
        &self.mon_gpio_raw_intstatus
    }
    #[doc = "0x84c - This register is written by software to clear edge interrupts generated by each individual GPIO input. This register always reads back as zero."]
    #[inline(always)]
    pub const fn mon_gpio_porta_eoi(&self) -> &MonGpioPortaEoi {
        &self.mon_gpio_porta_eoi
    }
    #[doc = "0x850 - Reading this register reads the values of the GPIO inputs."]
    #[inline(always)]
    pub const fn mon_gpio_ext_porta(&self) -> &MonGpioExtPorta {
        &self.mon_gpio_ext_porta
    }
    #[doc = "0x860 - The Synchronization level register is used to synchronize inputs to the l4_mp_clk. All MON interrupts are already synchronized before the GPIO instance so it is not necessary to setup this register to enable synchronization."]
    #[inline(always)]
    pub const fn mon_gpio_ls_sync(&self) -> &MonGpioLsSync {
        &self.mon_gpio_ls_sync
    }
    #[doc = "0x86c - GPIO Component Version"]
    #[inline(always)]
    pub const fn mon_gpio_ver_id_code(&self) -> &MonGpioVerIdCode {
        &self.mon_gpio_ver_id_code
    }
    #[doc = "0x870 - Specifies the bit width of port A."]
    #[inline(always)]
    pub const fn mon_gpio_config_reg2(&self) -> &MonGpioConfigReg2 {
        &self.mon_gpio_config_reg2
    }
    #[doc = "0x874 - Reports settings of various GPIO configuration parameters"]
    #[inline(always)]
    pub const fn mon_gpio_config_reg1(&self) -> &MonGpioConfigReg1 {
        &self.mon_gpio_config_reg1
    }
}
#[doc = "stat (rw) register accessor: Provides status fields for software for the FPGA Manager. The Mode field tells software what configuration phase the FPGA currently is in. For regular configuration through the PINs or through the HPS, these states map directly to customer configuration documentation. For Configuration Via PCI Express (CVP), the IOCSR configuration is done through the PINS or through HPS. Then the complete configuration is done through the PCI Express Bus. When CVP is being done, InitPhase indicates only IOCSR configuration has completed. CVP_CONF_DONE is available in the CB Monitor for observation by software. The MSEL field provides a read only register for software to read the MSEL value driven from the external pins.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stat::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@stat`]
module"]
#[doc(alias = "stat")]
pub type Stat = crate::Reg<stat::StatSpec>;
#[doc = "Provides status fields for software for the FPGA Manager. The Mode field tells software what configuration phase the FPGA currently is in. For regular configuration through the PINs or through the HPS, these states map directly to customer configuration documentation. For Configuration Via PCI Express (CVP), the IOCSR configuration is done through the PINS or through HPS. Then the complete configuration is done through the PCI Express Bus. When CVP is being done, InitPhase indicates only IOCSR configuration has completed. CVP_CONF_DONE is available in the CB Monitor for observation by software. The MSEL field provides a read only register for software to read the MSEL value driven from the external pins."]
pub mod stat;
#[doc = "ctrl (rw) register accessor: Allows HPS to control FPGA configuration. The NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields drive signals to the FPGA Control Block that are logically ORed into their respective pins. These signals are always driven independent of the value of EN. The polarity of the NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields is inverted relative to their associated pins. The MSEL (external pins), CDRATIO and CFGWDTH signals determine the mode of operation for Normal Configuration. For Partial Reconfiguration, CDRATIO is used to set the appropriate clock to data ratio, and CFGWDTH should always be set to 16-bit Passive Parallel. AXICFGEN is used to enable transfer of configuration data by enabling or disabling DCLK during data transfers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrl`]
module"]
#[doc(alias = "ctrl")]
pub type Ctrl = crate::Reg<ctrl::CtrlSpec>;
#[doc = "Allows HPS to control FPGA configuration. The NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields drive signals to the FPGA Control Block that are logically ORed into their respective pins. These signals are always driven independent of the value of EN. The polarity of the NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields is inverted relative to their associated pins. The MSEL (external pins), CDRATIO and CFGWDTH signals determine the mode of operation for Normal Configuration. For Partial Reconfiguration, CDRATIO is used to set the appropriate clock to data ratio, and CFGWDTH should always be set to 16-bit Passive Parallel. AXICFGEN is used to enable transfer of configuration data by enabling or disabling DCLK during data transfers."]
pub mod ctrl;
#[doc = "dclkcnt (rw) register accessor: Used to give software control in enabling DCLK at any time. SW will need control of the DCLK in specific configuration and partial reconfiguration initialization steps to send spurious DCLKs required by the CB. SW takes ownership for DCLK during normal configuration, partial reconfiguration, error scenerio handshakes including SEU CRC error during partial reconfiguration, SW early abort of partial reconfiguration, and initializatin phase DCLK driving. During initialization phase, a configuration image loaded into the FPGA can request that DCLK be used as the initialization phase clock instead of the default internal oscillator or optionally the CLKUSR pin. In the case that DCLK is requested, the DCLKCNT register is used by software to control DCLK during the initialization phase. Software should poll the DCLKSTAT.DCNTDONE write one to clear register to be set when the correct number of DCLKs have completed. Software should clear DCLKSTAT.DCNTDONE before writing to the DCLKCNT register again. This field only affects the FPGA if CTRL.EN is 1.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dclkcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dclkcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dclkcnt`]
module"]
#[doc(alias = "dclkcnt")]
pub type Dclkcnt = crate::Reg<dclkcnt::DclkcntSpec>;
#[doc = "Used to give software control in enabling DCLK at any time. SW will need control of the DCLK in specific configuration and partial reconfiguration initialization steps to send spurious DCLKs required by the CB. SW takes ownership for DCLK during normal configuration, partial reconfiguration, error scenerio handshakes including SEU CRC error during partial reconfiguration, SW early abort of partial reconfiguration, and initializatin phase DCLK driving. During initialization phase, a configuration image loaded into the FPGA can request that DCLK be used as the initialization phase clock instead of the default internal oscillator or optionally the CLKUSR pin. In the case that DCLK is requested, the DCLKCNT register is used by software to control DCLK during the initialization phase. Software should poll the DCLKSTAT.DCNTDONE write one to clear register to be set when the correct number of DCLKs have completed. Software should clear DCLKSTAT.DCNTDONE before writing to the DCLKCNT register again. This field only affects the FPGA if CTRL.EN is 1."]
pub mod dclkcnt;
#[doc = "dclkstat (rw) register accessor: This write one to clear register indicates that the DCLKCNT has counted down to zero. The DCLKCNT is used by software to drive spurious DCLKs to the FPGA. Software will poll this bit after writing DCLKCNT to know when all of the DCLKs have been sent.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dclkstat::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dclkstat::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dclkstat`]
module"]
#[doc(alias = "dclkstat")]
pub type Dclkstat = crate::Reg<dclkstat::DclkstatSpec>;
#[doc = "This write one to clear register indicates that the DCLKCNT has counted down to zero. The DCLKCNT is used by software to drive spurious DCLKs to the FPGA. Software will poll this bit after writing DCLKCNT to know when all of the DCLKs have been sent."]
pub mod dclkstat;
#[doc = "gpo (rw) register accessor: Provides a low-latency, low-performance, and simple way to drive general-purpose signals to the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpo::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpo::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpo`]
module"]
#[doc(alias = "gpo")]
pub type Gpo = crate::Reg<gpo::GpoSpec>;
#[doc = "Provides a low-latency, low-performance, and simple way to drive general-purpose signals to the FPGA fabric."]
pub mod gpo;
#[doc = "gpi (r) register accessor: Provides a low-latency, low-performance, and simple way to read general-purpose signals driven from the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpi::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gpi`]
module"]
#[doc(alias = "gpi")]
pub type Gpi = crate::Reg<gpi::GpiSpec>;
#[doc = "Provides a low-latency, low-performance, and simple way to read general-purpose signals driven from the FPGA fabric."]
pub mod gpi;
#[doc = "misci (r) register accessor: Provides a low-latency, low-performance, and simple way to read specific handshaking signals driven from the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`misci::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@misci`]
module"]
#[doc(alias = "misci")]
pub type Misci = crate::Reg<misci::MisciSpec>;
#[doc = "Provides a low-latency, low-performance, and simple way to read specific handshaking signals driven from the FPGA fabric."]
pub mod misci;
#[doc = "mon_gpio_inten (rw) register accessor: Allows each bit of Port A to be configured to generate an interrupt or not.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_inten::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_inten::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_inten`]
module"]
#[doc(alias = "mon_gpio_inten")]
pub type MonGpioInten = crate::Reg<mon_gpio_inten::MonGpioIntenSpec>;
#[doc = "Allows each bit of Port A to be configured to generate an interrupt or not."]
pub mod mon_gpio_inten;
#[doc = "mon_gpio_intmask (rw) register accessor: This register has 12 individual interrupt masks for the MON. Controls whether an interrupt on Port A can create an interrupt for the interrupt controller by not masking it. By default, all interrupts bits are unmasked. Whenever a 1 is written to a bit in this register, it masks the interrupt generation capability for this signal; otherwise interrupts are allowed through. The unmasked status can be read as well as the resultant status after masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_intmask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_intmask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_intmask`]
module"]
#[doc(alias = "mon_gpio_intmask")]
pub type MonGpioIntmask = crate::Reg<mon_gpio_intmask::MonGpioIntmaskSpec>;
#[doc = "This register has 12 individual interrupt masks for the MON. Controls whether an interrupt on Port A can create an interrupt for the interrupt controller by not masking it. By default, all interrupts bits are unmasked. Whenever a 1 is written to a bit in this register, it masks the interrupt generation capability for this signal; otherwise interrupts are allowed through. The unmasked status can be read as well as the resultant status after masking."]
pub mod mon_gpio_intmask;
#[doc = "mon_gpio_inttype_level (rw) register accessor: The interrupt level register defines the type of interrupt (edge or level) for each GPIO input.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_inttype_level::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_inttype_level::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_inttype_level`]
module"]
#[doc(alias = "mon_gpio_inttype_level")]
pub type MonGpioInttypeLevel = crate::Reg<mon_gpio_inttype_level::MonGpioInttypeLevelSpec>;
#[doc = "The interrupt level register defines the type of interrupt (edge or level) for each GPIO input."]
pub mod mon_gpio_inttype_level;
#[doc = "mon_gpio_int_polarity (rw) register accessor: Controls the polarity of interrupts that can occur on each GPIO input.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_int_polarity::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_int_polarity::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_int_polarity`]
module"]
#[doc(alias = "mon_gpio_int_polarity")]
pub type MonGpioIntPolarity = crate::Reg<mon_gpio_int_polarity::MonGpioIntPolaritySpec>;
#[doc = "Controls the polarity of interrupts that can occur on each GPIO input."]
pub mod mon_gpio_int_polarity;
#[doc = "mon_gpio_intstatus (r) register accessor: Reports on interrupt status for each GPIO input. The interrupt status includes the effects of masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_intstatus::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_intstatus`]
module"]
#[doc(alias = "mon_gpio_intstatus")]
pub type MonGpioIntstatus = crate::Reg<mon_gpio_intstatus::MonGpioIntstatusSpec>;
#[doc = "Reports on interrupt status for each GPIO input. The interrupt status includes the effects of masking."]
pub mod mon_gpio_intstatus;
#[doc = "mon_gpio_raw_intstatus (r) register accessor: Reports on raw interrupt status for each GPIO input. The raw interrupt status excludes the effects of masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_raw_intstatus::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_raw_intstatus`]
module"]
#[doc(alias = "mon_gpio_raw_intstatus")]
pub type MonGpioRawIntstatus = crate::Reg<mon_gpio_raw_intstatus::MonGpioRawIntstatusSpec>;
#[doc = "Reports on raw interrupt status for each GPIO input. The raw interrupt status excludes the effects of masking."]
pub mod mon_gpio_raw_intstatus;
#[doc = "mon_gpio_porta_eoi (w) register accessor: This register is written by software to clear edge interrupts generated by each individual GPIO input. This register always reads back as zero.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_porta_eoi::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_porta_eoi`]
module"]
#[doc(alias = "mon_gpio_porta_eoi")]
pub type MonGpioPortaEoi = crate::Reg<mon_gpio_porta_eoi::MonGpioPortaEoiSpec>;
#[doc = "This register is written by software to clear edge interrupts generated by each individual GPIO input. This register always reads back as zero."]
pub mod mon_gpio_porta_eoi;
#[doc = "mon_gpio_ext_porta (r) register accessor: Reading this register reads the values of the GPIO inputs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_ext_porta::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_ext_porta`]
module"]
#[doc(alias = "mon_gpio_ext_porta")]
pub type MonGpioExtPorta = crate::Reg<mon_gpio_ext_porta::MonGpioExtPortaSpec>;
#[doc = "Reading this register reads the values of the GPIO inputs."]
pub mod mon_gpio_ext_porta;
#[doc = "mon_gpio_ls_sync (rw) register accessor: The Synchronization level register is used to synchronize inputs to the l4_mp_clk. All MON interrupts are already synchronized before the GPIO instance so it is not necessary to setup this register to enable synchronization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_ls_sync::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_ls_sync::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_ls_sync`]
module"]
#[doc(alias = "mon_gpio_ls_sync")]
pub type MonGpioLsSync = crate::Reg<mon_gpio_ls_sync::MonGpioLsSyncSpec>;
#[doc = "The Synchronization level register is used to synchronize inputs to the l4_mp_clk. All MON interrupts are already synchronized before the GPIO instance so it is not necessary to setup this register to enable synchronization."]
pub mod mon_gpio_ls_sync;
#[doc = "mon_gpio_ver_id_code (r) register accessor: GPIO Component Version\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_ver_id_code::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_ver_id_code`]
module"]
#[doc(alias = "mon_gpio_ver_id_code")]
pub type MonGpioVerIdCode = crate::Reg<mon_gpio_ver_id_code::MonGpioVerIdCodeSpec>;
#[doc = "GPIO Component Version"]
pub mod mon_gpio_ver_id_code;
#[doc = "mon_gpio_config_reg2 (r) register accessor: Specifies the bit width of port A.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_config_reg2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_config_reg2`]
module"]
#[doc(alias = "mon_gpio_config_reg2")]
pub type MonGpioConfigReg2 = crate::Reg<mon_gpio_config_reg2::MonGpioConfigReg2Spec>;
#[doc = "Specifies the bit width of port A."]
pub mod mon_gpio_config_reg2;
#[doc = "mon_gpio_config_reg1 (r) register accessor: Reports settings of various GPIO configuration parameters\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_config_reg1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mon_gpio_config_reg1`]
module"]
#[doc(alias = "mon_gpio_config_reg1")]
pub type MonGpioConfigReg1 = crate::Reg<mon_gpio_config_reg1::MonGpioConfigReg1Spec>;
#[doc = "Reports settings of various GPIO configuration parameters"]
pub mod mon_gpio_config_reg1;
