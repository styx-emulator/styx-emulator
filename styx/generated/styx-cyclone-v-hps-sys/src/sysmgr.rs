// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    siliconid1: Siliconid1,
    siliconid2: Siliconid2,
    _reserved2: [u8; 0x08],
    wddbg: Wddbg,
    bootinfo: Bootinfo,
    hpsinfo: Hpsinfo,
    parityinj: Parityinj,
    fpgaintfgrp_gbl: FpgaintfgrpGbl,
    fpgaintfgrp_indiv: FpgaintfgrpIndiv,
    fpgaintfgrp_module: FpgaintfgrpModule,
    _reserved9: [u8; 0x04],
    scanmgrgrp_ctrl: ScanmgrgrpCtrl,
    _reserved10: [u8; 0x0c],
    frzctrl_vioctrl_: [FrzctrlVioctrl_; 3],
    _reserved11: [u8; 0x04],
    frzctrl_hioctrl: FrzctrlHioctrl,
    frzctrl_src: FrzctrlSrc,
    frzctrl_hwctrl: FrzctrlHwctrl,
    _reserved14: [u8; 0x04],
    emacgrp_ctrl: EmacgrpCtrl,
    emacgrp_l3master: EmacgrpL3master,
    _reserved16: [u8; 0x08],
    dmagrp_ctrl: DmagrpCtrl,
    dmagrp_persecurity: DmagrpPersecurity,
    _reserved18: [u8; 0x08],
    iswgrp_handoff_: [IswgrpHandoff_; 8],
    _reserved19: [u8; 0x20],
    romcodegrp_ctrl: RomcodegrpCtrl,
    romcodegrp_cpu1startaddr: RomcodegrpCpu1startaddr,
    romcodegrp_initswstate: RomcodegrpInitswstate,
    romcodegrp_initswlastld: RomcodegrpInitswlastld,
    romcodegrp_bootromswstate: RomcodegrpBootromswstate,
    _reserved24: [u8; 0x0c],
    romcodegrp_warmramgrp_enable: RomcodegrpWarmramgrpEnable,
    romcodegrp_warmramgrp_datastart: RomcodegrpWarmramgrpDatastart,
    romcodegrp_warmramgrp_length: RomcodegrpWarmramgrpLength,
    romcodegrp_warmramgrp_execution: RomcodegrpWarmramgrpExecution,
    romcodegrp_warmramgrp_crc: RomcodegrpWarmramgrpCrc,
    _reserved29: [u8; 0x0c],
    romhwgrp_ctrl: RomhwgrpCtrl,
    _reserved30: [u8; 0x04],
    sdmmcgrp_ctrl: SdmmcgrpCtrl,
    sdmmcgrp_l3master: SdmmcgrpL3master,
    nandgrp_bootstrap: NandgrpBootstrap,
    nandgrp_l3master: NandgrpL3master,
    usbgrp_l3master: UsbgrpL3master,
    _reserved35: [u8; 0x24],
    eccgrp_l2: EccgrpL2,
    eccgrp_ocram: EccgrpOcram,
    eccgrp_usb0: EccgrpUsb0,
    eccgrp_usb1: EccgrpUsb1,
    eccgrp_emac0: EccgrpEmac0,
    eccgrp_emac1: EccgrpEmac1,
    eccgrp_dma: EccgrpDma,
    eccgrp_can0: EccgrpCan0,
    eccgrp_can1: EccgrpCan1,
    eccgrp_nand: EccgrpNand,
    eccgrp_qspi: EccgrpQspi,
    eccgrp_sdmmc: EccgrpSdmmc,
    _reserved47: [u8; 0x0290],
    pinmuxgrp_emacio0: PinmuxgrpEmacio0,
    pinmuxgrp_emacio1: PinmuxgrpEmacio1,
    pinmuxgrp_emacio2: PinmuxgrpEmacio2,
    pinmuxgrp_emacio3: PinmuxgrpEmacio3,
    pinmuxgrp_emacio4: PinmuxgrpEmacio4,
    pinmuxgrp_emacio5: PinmuxgrpEmacio5,
    pinmuxgrp_emacio6: PinmuxgrpEmacio6,
    pinmuxgrp_emacio7: PinmuxgrpEmacio7,
    pinmuxgrp_emacio8: PinmuxgrpEmacio8,
    pinmuxgrp_emacio9: PinmuxgrpEmacio9,
    pinmuxgrp_emacio10: PinmuxgrpEmacio10,
    pinmuxgrp_emacio11: PinmuxgrpEmacio11,
    pinmuxgrp_emacio12: PinmuxgrpEmacio12,
    pinmuxgrp_emacio13: PinmuxgrpEmacio13,
    pinmuxgrp_emacio14: PinmuxgrpEmacio14,
    pinmuxgrp_emacio15: PinmuxgrpEmacio15,
    pinmuxgrp_emacio16: PinmuxgrpEmacio16,
    pinmuxgrp_emacio17: PinmuxgrpEmacio17,
    pinmuxgrp_emacio18: PinmuxgrpEmacio18,
    pinmuxgrp_emacio19: PinmuxgrpEmacio19,
    pinmuxgrp_flashio0: PinmuxgrpFlashio0,
    pinmuxgrp_flashio1: PinmuxgrpFlashio1,
    pinmuxgrp_flashio2: PinmuxgrpFlashio2,
    pinmuxgrp_flashio3: PinmuxgrpFlashio3,
    pinmuxgrp_flashio4: PinmuxgrpFlashio4,
    pinmuxgrp_flashio5: PinmuxgrpFlashio5,
    pinmuxgrp_flashio6: PinmuxgrpFlashio6,
    pinmuxgrp_flashio7: PinmuxgrpFlashio7,
    pinmuxgrp_flashio8: PinmuxgrpFlashio8,
    pinmuxgrp_flashio9: PinmuxgrpFlashio9,
    pinmuxgrp_flashio10: PinmuxgrpFlashio10,
    pinmuxgrp_flashio11: PinmuxgrpFlashio11,
    pinmuxgrp_generalio0: PinmuxgrpGeneralio0,
    pinmuxgrp_generalio1: PinmuxgrpGeneralio1,
    pinmuxgrp_generalio2: PinmuxgrpGeneralio2,
    pinmuxgrp_generalio3: PinmuxgrpGeneralio3,
    pinmuxgrp_generalio4: PinmuxgrpGeneralio4,
    pinmuxgrp_generalio5: PinmuxgrpGeneralio5,
    pinmuxgrp_generalio6: PinmuxgrpGeneralio6,
    pinmuxgrp_generalio7: PinmuxgrpGeneralio7,
    pinmuxgrp_generalio8: PinmuxgrpGeneralio8,
    pinmuxgrp_generalio9: PinmuxgrpGeneralio9,
    pinmuxgrp_generalio10: PinmuxgrpGeneralio10,
    pinmuxgrp_generalio11: PinmuxgrpGeneralio11,
    pinmuxgrp_generalio12: PinmuxgrpGeneralio12,
    pinmuxgrp_generalio13: PinmuxgrpGeneralio13,
    pinmuxgrp_generalio14: PinmuxgrpGeneralio14,
    pinmuxgrp_generalio15: PinmuxgrpGeneralio15,
    pinmuxgrp_generalio16: PinmuxgrpGeneralio16,
    pinmuxgrp_generalio17: PinmuxgrpGeneralio17,
    pinmuxgrp_generalio18: PinmuxgrpGeneralio18,
    pinmuxgrp_generalio19: PinmuxgrpGeneralio19,
    pinmuxgrp_generalio20: PinmuxgrpGeneralio20,
    pinmuxgrp_generalio21: PinmuxgrpGeneralio21,
    pinmuxgrp_generalio22: PinmuxgrpGeneralio22,
    pinmuxgrp_generalio23: PinmuxgrpGeneralio23,
    pinmuxgrp_generalio24: PinmuxgrpGeneralio24,
    pinmuxgrp_generalio25: PinmuxgrpGeneralio25,
    pinmuxgrp_generalio26: PinmuxgrpGeneralio26,
    pinmuxgrp_generalio27: PinmuxgrpGeneralio27,
    pinmuxgrp_generalio28: PinmuxgrpGeneralio28,
    pinmuxgrp_generalio29: PinmuxgrpGeneralio29,
    pinmuxgrp_generalio30: PinmuxgrpGeneralio30,
    pinmuxgrp_generalio31: PinmuxgrpGeneralio31,
    pinmuxgrp_mixed1io0: PinmuxgrpMixed1io0,
    pinmuxgrp_mixed1io1: PinmuxgrpMixed1io1,
    pinmuxgrp_mixed1io2: PinmuxgrpMixed1io2,
    pinmuxgrp_mixed1io3: PinmuxgrpMixed1io3,
    pinmuxgrp_mixed1io4: PinmuxgrpMixed1io4,
    pinmuxgrp_mixed1io5: PinmuxgrpMixed1io5,
    pinmuxgrp_mixed1io6: PinmuxgrpMixed1io6,
    pinmuxgrp_mixed1io7: PinmuxgrpMixed1io7,
    pinmuxgrp_mixed1io8: PinmuxgrpMixed1io8,
    pinmuxgrp_mixed1io9: PinmuxgrpMixed1io9,
    pinmuxgrp_mixed1io10: PinmuxgrpMixed1io10,
    pinmuxgrp_mixed1io11: PinmuxgrpMixed1io11,
    pinmuxgrp_mixed1io12: PinmuxgrpMixed1io12,
    pinmuxgrp_mixed1io13: PinmuxgrpMixed1io13,
    pinmuxgrp_mixed1io14: PinmuxgrpMixed1io14,
    pinmuxgrp_mixed1io15: PinmuxgrpMixed1io15,
    pinmuxgrp_mixed1io16: PinmuxgrpMixed1io16,
    pinmuxgrp_mixed1io17: PinmuxgrpMixed1io17,
    pinmuxgrp_mixed1io18: PinmuxgrpMixed1io18,
    pinmuxgrp_mixed1io19: PinmuxgrpMixed1io19,
    pinmuxgrp_mixed1io20: PinmuxgrpMixed1io20,
    pinmuxgrp_mixed1io21: PinmuxgrpMixed1io21,
    pinmuxgrp_mixed2io0: PinmuxgrpMixed2io0,
    pinmuxgrp_mixed2io1: PinmuxgrpMixed2io1,
    pinmuxgrp_mixed2io2: PinmuxgrpMixed2io2,
    pinmuxgrp_mixed2io3: PinmuxgrpMixed2io3,
    pinmuxgrp_mixed2io4: PinmuxgrpMixed2io4,
    pinmuxgrp_mixed2io5: PinmuxgrpMixed2io5,
    pinmuxgrp_mixed2io6: PinmuxgrpMixed2io6,
    pinmuxgrp_mixed2io7: PinmuxgrpMixed2io7,
    pinmuxgrp_gplinmux48: PinmuxgrpGplinmux48,
    pinmuxgrp_gplinmux49: PinmuxgrpGplinmux49,
    pinmuxgrp_gplinmux50: PinmuxgrpGplinmux50,
    pinmuxgrp_gplinmux51: PinmuxgrpGplinmux51,
    pinmuxgrp_gplinmux52: PinmuxgrpGplinmux52,
    pinmuxgrp_gplinmux53: PinmuxgrpGplinmux53,
    pinmuxgrp_gplinmux54: PinmuxgrpGplinmux54,
    pinmuxgrp_gplinmux55: PinmuxgrpGplinmux55,
    pinmuxgrp_gplinmux56: PinmuxgrpGplinmux56,
    pinmuxgrp_gplinmux57: PinmuxgrpGplinmux57,
    pinmuxgrp_gplinmux58: PinmuxgrpGplinmux58,
    pinmuxgrp_gplinmux59: PinmuxgrpGplinmux59,
    pinmuxgrp_gplinmux60: PinmuxgrpGplinmux60,
    pinmuxgrp_gplinmux61: PinmuxgrpGplinmux61,
    pinmuxgrp_gplinmux62: PinmuxgrpGplinmux62,
    pinmuxgrp_gplinmux63: PinmuxgrpGplinmux63,
    pinmuxgrp_gplinmux64: PinmuxgrpGplinmux64,
    pinmuxgrp_gplinmux65: PinmuxgrpGplinmux65,
    pinmuxgrp_gplinmux66: PinmuxgrpGplinmux66,
    pinmuxgrp_gplinmux67: PinmuxgrpGplinmux67,
    pinmuxgrp_gplinmux68: PinmuxgrpGplinmux68,
    pinmuxgrp_gplinmux69: PinmuxgrpGplinmux69,
    pinmuxgrp_gplinmux70: PinmuxgrpGplinmux70,
    pinmuxgrp_gplmux0: PinmuxgrpGplmux0,
    pinmuxgrp_gplmux1: PinmuxgrpGplmux1,
    pinmuxgrp_gplmux2: PinmuxgrpGplmux2,
    pinmuxgrp_gplmux3: PinmuxgrpGplmux3,
    pinmuxgrp_gplmux4: PinmuxgrpGplmux4,
    pinmuxgrp_gplmux5: PinmuxgrpGplmux5,
    pinmuxgrp_gplmux6: PinmuxgrpGplmux6,
    pinmuxgrp_gplmux7: PinmuxgrpGplmux7,
    pinmuxgrp_gplmux8: PinmuxgrpGplmux8,
    pinmuxgrp_gplmux9: PinmuxgrpGplmux9,
    pinmuxgrp_gplmux10: PinmuxgrpGplmux10,
    pinmuxgrp_gplmux11: PinmuxgrpGplmux11,
    pinmuxgrp_gplmux12: PinmuxgrpGplmux12,
    pinmuxgrp_gplmux13: PinmuxgrpGplmux13,
    pinmuxgrp_gplmux14: PinmuxgrpGplmux14,
    pinmuxgrp_gplmux15: PinmuxgrpGplmux15,
    pinmuxgrp_gplmux16: PinmuxgrpGplmux16,
    pinmuxgrp_gplmux17: PinmuxgrpGplmux17,
    pinmuxgrp_gplmux18: PinmuxgrpGplmux18,
    pinmuxgrp_gplmux19: PinmuxgrpGplmux19,
    pinmuxgrp_gplmux20: PinmuxgrpGplmux20,
    pinmuxgrp_gplmux21: PinmuxgrpGplmux21,
    pinmuxgrp_gplmux22: PinmuxgrpGplmux22,
    pinmuxgrp_gplmux23: PinmuxgrpGplmux23,
    pinmuxgrp_gplmux24: PinmuxgrpGplmux24,
    pinmuxgrp_gplmux25: PinmuxgrpGplmux25,
    pinmuxgrp_gplmux26: PinmuxgrpGplmux26,
    pinmuxgrp_gplmux27: PinmuxgrpGplmux27,
    pinmuxgrp_gplmux28: PinmuxgrpGplmux28,
    pinmuxgrp_gplmux29: PinmuxgrpGplmux29,
    pinmuxgrp_gplmux30: PinmuxgrpGplmux30,
    pinmuxgrp_gplmux31: PinmuxgrpGplmux31,
    pinmuxgrp_gplmux32: PinmuxgrpGplmux32,
    pinmuxgrp_gplmux33: PinmuxgrpGplmux33,
    pinmuxgrp_gplmux34: PinmuxgrpGplmux34,
    pinmuxgrp_gplmux35: PinmuxgrpGplmux35,
    pinmuxgrp_gplmux36: PinmuxgrpGplmux36,
    pinmuxgrp_gplmux37: PinmuxgrpGplmux37,
    pinmuxgrp_gplmux38: PinmuxgrpGplmux38,
    pinmuxgrp_gplmux39: PinmuxgrpGplmux39,
    pinmuxgrp_gplmux40: PinmuxgrpGplmux40,
    pinmuxgrp_gplmux41: PinmuxgrpGplmux41,
    pinmuxgrp_gplmux42: PinmuxgrpGplmux42,
    pinmuxgrp_gplmux43: PinmuxgrpGplmux43,
    pinmuxgrp_gplmux44: PinmuxgrpGplmux44,
    pinmuxgrp_gplmux45: PinmuxgrpGplmux45,
    pinmuxgrp_gplmux46: PinmuxgrpGplmux46,
    pinmuxgrp_gplmux47: PinmuxgrpGplmux47,
    pinmuxgrp_gplmux48: PinmuxgrpGplmux48,
    pinmuxgrp_gplmux49: PinmuxgrpGplmux49,
    pinmuxgrp_gplmux50: PinmuxgrpGplmux50,
    pinmuxgrp_gplmux51: PinmuxgrpGplmux51,
    pinmuxgrp_gplmux52: PinmuxgrpGplmux52,
    pinmuxgrp_gplmux53: PinmuxgrpGplmux53,
    pinmuxgrp_gplmux54: PinmuxgrpGplmux54,
    pinmuxgrp_gplmux55: PinmuxgrpGplmux55,
    pinmuxgrp_gplmux56: PinmuxgrpGplmux56,
    pinmuxgrp_gplmux57: PinmuxgrpGplmux57,
    pinmuxgrp_gplmux58: PinmuxgrpGplmux58,
    pinmuxgrp_gplmux59: PinmuxgrpGplmux59,
    pinmuxgrp_gplmux60: PinmuxgrpGplmux60,
    pinmuxgrp_gplmux61: PinmuxgrpGplmux61,
    pinmuxgrp_gplmux62: PinmuxgrpGplmux62,
    pinmuxgrp_gplmux63: PinmuxgrpGplmux63,
    pinmuxgrp_gplmux64: PinmuxgrpGplmux64,
    pinmuxgrp_gplmux65: PinmuxgrpGplmux65,
    pinmuxgrp_gplmux66: PinmuxgrpGplmux66,
    pinmuxgrp_gplmux67: PinmuxgrpGplmux67,
    pinmuxgrp_gplmux68: PinmuxgrpGplmux68,
    pinmuxgrp_gplmux69: PinmuxgrpGplmux69,
    pinmuxgrp_gplmux70: PinmuxgrpGplmux70,
    pinmuxgrp_nandusefpga: PinmuxgrpNandusefpga,
    _reserved236: [u8; 0x04],
    pinmuxgrp_rgmii1usefpga: PinmuxgrpRgmii1usefpga,
    _reserved237: [u8; 0x08],
    pinmuxgrp_i2c0usefpga: PinmuxgrpI2c0usefpga,
    _reserved238: [u8; 0x0c],
    pinmuxgrp_rgmii0usefpga: PinmuxgrpRgmii0usefpga,
    _reserved239: [u8; 0x0c],
    pinmuxgrp_i2c3usefpga: PinmuxgrpI2c3usefpga,
    pinmuxgrp_i2c2usefpga: PinmuxgrpI2c2usefpga,
    pinmuxgrp_i2c1usefpga: PinmuxgrpI2c1usefpga,
    pinmuxgrp_spim1usefpga: PinmuxgrpSpim1usefpga,
    _reserved243: [u8; 0x04],
    pinmuxgrp_spim0usefpga: PinmuxgrpSpim0usefpga,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Specifies Silicon ID and revision number."]
    #[inline(always)]
    pub const fn siliconid1(&self) -> &Siliconid1 {
        &self.siliconid1
    }
    #[doc = "0x04 - Reserved for future use."]
    #[inline(always)]
    pub const fn siliconid2(&self) -> &Siliconid2 {
        &self.siliconid2
    }
    #[doc = "0x10 - Controls the behavior of the L4 watchdogs when the CPUs are in debug mode. These control registers are used to drive the pause input signal of the L4 watchdogs. Note that the watchdogs built into the MPU automatically are paused when their associated CPU enters debug mode. Only reset by a cold reset."]
    #[inline(always)]
    pub const fn wddbg(&self) -> &Wddbg {
        &self.wddbg
    }
    #[doc = "0x14 - Provides access to boot configuration information."]
    #[inline(always)]
    pub const fn bootinfo(&self) -> &Bootinfo {
        &self.bootinfo
    }
    #[doc = "0x18 - Provides information about the HPS capabilities."]
    #[inline(always)]
    pub const fn hpsinfo(&self) -> &Hpsinfo {
        &self.hpsinfo
    }
    #[doc = "0x1c - Inject parity failures into the parity-protected RAMs in the MPU. Allows software to test the parity failure interrupt handler. The field array index corresponds to the CPU index. All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn parityinj(&self) -> &Parityinj {
        &self.parityinj
    }
    #[doc = "0x20 - Used to disable all interfaces between the FPGA and HPS."]
    #[inline(always)]
    pub const fn fpgaintfgrp_gbl(&self) -> &FpgaintfgrpGbl {
        &self.fpgaintfgrp_gbl
    }
    #[doc = "0x24 - Used to disable individual interfaces between the FPGA and HPS."]
    #[inline(always)]
    pub const fn fpgaintfgrp_indiv(&self) -> &FpgaintfgrpIndiv {
        &self.fpgaintfgrp_indiv
    }
    #[doc = "0x28 - Used to disable signals from the FPGA fabric to individual HPS modules."]
    #[inline(always)]
    pub const fn fpgaintfgrp_module(&self) -> &FpgaintfgrpModule {
        &self.fpgaintfgrp_module
    }
    #[doc = "0x30 - Controls behaviors of Scan Manager not controlled by registers in the Scan Manager itself."]
    #[inline(always)]
    pub const fn scanmgrgrp_ctrl(&self) -> &ScanmgrgrpCtrl {
        &self.scanmgrgrp_ctrl
    }
    #[doc = "0x40..0x4c - Used to drive freeze signals to HPS VIO banks. The register array index corresponds to the freeze channel. Freeze channel 0 provides freeze signals to VIO bank 0 and 1. Freeze channel 1 provides freeze signals to VIO bank 2 and 3. Only drives freeze signals when SRC.VIO1 is set to SW. Freeze channel 2 provides freeze signals to VIO bank 4. All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration"]
    #[inline(always)]
    pub const fn frzctrl_vioctrl_(&self, n: usize) -> &FrzctrlVioctrl_ {
        &self.frzctrl_vioctrl_[n]
    }
    #[doc = "Iterator for array of:"]
    #[doc = "0x40..0x4c - Used to drive freeze signals to HPS VIO banks. The register array index corresponds to the freeze channel. Freeze channel 0 provides freeze signals to VIO bank 0 and 1. Freeze channel 1 provides freeze signals to VIO bank 2 and 3. Only drives freeze signals when SRC.VIO1 is set to SW. Freeze channel 2 provides freeze signals to VIO bank 4. All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration"]
    #[inline(always)]
    pub fn frzctrl_vioctrl__iter(&self) -> impl Iterator<Item = &FrzctrlVioctrl_> {
        self.frzctrl_vioctrl_.iter()
    }
    #[doc = "0x50 - Used to drive freeze signals to HPS HIO bank (DDR SDRAM). All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration"]
    #[inline(always)]
    pub const fn frzctrl_hioctrl(&self) -> &FrzctrlHioctrl {
        &self.frzctrl_hioctrl
    }
    #[doc = "0x54 - Contains register field to choose between software state machine (vioctrl array index \\[1\\]
register) or hardware state machine in the Freeze Controller as the freeze signal source for VIO channel 1. All fields are only reset by a cold reset (ignore warm reset)."]
    #[inline(always)]
    pub const fn frzctrl_src(&self) -> &FrzctrlSrc {
        &self.frzctrl_src
    }
    #[doc = "0x58 - Activate freeze or thaw operations on VIO channel 1 (HPS IO bank 2 and bank 3) and monitor for completeness and the current state. These fields interact with the hardware state machine in the Freeze Controller. These fields can be accessed independent of the value of SRC1.VIO1 although they only have an effect on the VIO channel 1 freeze signals when SRC1.VIO1 is setup to have the hardware state machine be the freeze signal source. All fields are only reset by a cold reset (ignore warm reset)."]
    #[inline(always)]
    pub const fn frzctrl_hwctrl(&self) -> &FrzctrlHwctrl {
        &self.frzctrl_hwctrl
    }
    #[doc = "0x60 - Registers used by the EMACs. All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn emacgrp_ctrl(&self) -> &EmacgrpCtrl {
        &self.emacgrp_ctrl
    }
    #[doc = "0x64 - Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn emacgrp_l3master(&self) -> &EmacgrpL3master {
        &self.emacgrp_l3master
    }
    #[doc = "0x70 - Registers used by the DMA Controller. All fields are reset by a cold or warm reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation."]
    #[inline(always)]
    pub const fn dmagrp_ctrl(&self) -> &DmagrpCtrl {
        &self.dmagrp_ctrl
    }
    #[doc = "0x74 - Controls the security state of a peripheral request interface. Sampled by the DMA controller when it exits from reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation."]
    #[inline(always)]
    pub const fn dmagrp_persecurity(&self) -> &DmagrpPersecurity {
        &self.dmagrp_persecurity
    }
    #[doc = "0x80..0xa0 - These registers are used to store handoff infomation between the preloader and the OS. These 8 registers can be used to store any information. The contents of these registers have no impact on the state of the HPS hardware."]
    #[inline(always)]
    pub const fn iswgrp_handoff_(&self, n: usize) -> &IswgrpHandoff_ {
        &self.iswgrp_handoff_[n]
    }
    #[doc = "Iterator for array of:"]
    #[doc = "0x80..0xa0 - These registers are used to store handoff infomation between the preloader and the OS. These 8 registers can be used to store any information. The contents of these registers have no impact on the state of the HPS hardware."]
    #[inline(always)]
    pub fn iswgrp_handoff__iter(&self) -> impl Iterator<Item = &IswgrpHandoff_> {
        self.iswgrp_handoff_.iter()
    }
    #[doc = "0xc0 - Contains information used to control Boot ROM code."]
    #[inline(always)]
    pub const fn romcodegrp_ctrl(&self) -> &RomcodegrpCtrl {
        &self.romcodegrp_ctrl
    }
    #[doc = "0xc4 - When CPU1 is released from reset and the Boot ROM is located at the CPU1 reset exception address (the typical case), the Boot ROM reset handler code reads the address stored in this register and jumps it to hand off execution to user software."]
    #[inline(always)]
    pub const fn romcodegrp_cpu1startaddr(&self) -> &RomcodegrpCpu1startaddr {
        &self.romcodegrp_cpu1startaddr
    }
    #[doc = "0xc8 - The preloader software (loaded by the Boot ROM) writes the magic value 0x49535756 (ISWV in ASCII) to this register when it has reached a valid state."]
    #[inline(always)]
    pub const fn romcodegrp_initswstate(&self) -> &RomcodegrpInitswstate {
        &self.romcodegrp_initswstate
    }
    #[doc = "0xcc - Contains the index of the last preloader software image loaded by the Boot ROM from the boot device."]
    #[inline(always)]
    pub const fn romcodegrp_initswlastld(&self) -> &RomcodegrpInitswlastld {
        &self.romcodegrp_initswlastld
    }
    #[doc = "0xd0 - 32-bits general purpose register used by the Boot ROM code. Actual usage is defined in the Boot ROM source code."]
    #[inline(always)]
    pub const fn romcodegrp_bootromswstate(&self) -> &RomcodegrpBootromswstate {
        &self.romcodegrp_bootromswstate
    }
    #[doc = "0xe0 - Enables or disables the warm reset from On-chip RAM feature."]
    #[inline(always)]
    pub const fn romcodegrp_warmramgrp_enable(&self) -> &RomcodegrpWarmramgrpEnable {
        &self.romcodegrp_warmramgrp_enable
    }
    #[doc = "0xe4 - Offset into On-chip RAM of the start of the region for CRC validation"]
    #[inline(always)]
    pub const fn romcodegrp_warmramgrp_datastart(&self) -> &RomcodegrpWarmramgrpDatastart {
        &self.romcodegrp_warmramgrp_datastart
    }
    #[doc = "0xe8 - Length of region in On-chip RAM for CRC validation."]
    #[inline(always)]
    pub const fn romcodegrp_warmramgrp_length(&self) -> &RomcodegrpWarmramgrpLength {
        &self.romcodegrp_warmramgrp_length
    }
    #[doc = "0xec - Offset into On-chip RAM to enter to on a warm boot."]
    #[inline(always)]
    pub const fn romcodegrp_warmramgrp_execution(&self) -> &RomcodegrpWarmramgrpExecution {
        &self.romcodegrp_warmramgrp_execution
    }
    #[doc = "0xf0 - Length of region in On-chip RAM for CRC validation."]
    #[inline(always)]
    pub const fn romcodegrp_warmramgrp_crc(&self) -> &RomcodegrpWarmramgrpCrc {
        &self.romcodegrp_warmramgrp_crc
    }
    #[doc = "0x100 - Controls behavior of Boot ROM hardware. All fields are only reset by a cold reset (ignore warm reset)."]
    #[inline(always)]
    pub const fn romhwgrp_ctrl(&self) -> &RomhwgrpCtrl {
        &self.romhwgrp_ctrl
    }
    #[doc = "0x108 - Registers used by the SDMMC Controller. All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn sdmmcgrp_ctrl(&self) -> &SdmmcgrpCtrl {
        &self.sdmmcgrp_ctrl
    }
    #[doc = "0x10c - Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn sdmmcgrp_l3master(&self) -> &SdmmcgrpL3master {
        &self.sdmmcgrp_l3master
    }
    #[doc = "0x110 - Bootstrap fields sampled by NAND Flash Controller when released from reset. All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn nandgrp_bootstrap(&self) -> &NandgrpBootstrap {
        &self.nandgrp_bootstrap
    }
    #[doc = "0x114 - Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn nandgrp_l3master(&self) -> &NandgrpL3master {
        &self.nandgrp_l3master
    }
    #[doc = "0x118 - Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
    #[inline(always)]
    pub const fn usbgrp_l3master(&self) -> &UsbgrpL3master {
        &self.usbgrp_l3master
    }
    #[doc = "0x140 - This register is used to enable ECC on the L2 Data RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_l2(&self) -> &EccgrpL2 {
        &self.eccgrp_l2
    }
    #[doc = "0x144 - This register is used to enable ECC on the On-chip RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_ocram(&self) -> &EccgrpOcram {
        &self.eccgrp_ocram
    }
    #[doc = "0x148 - This register is used to enable ECC on the USB0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_usb0(&self) -> &EccgrpUsb0 {
        &self.eccgrp_usb0
    }
    #[doc = "0x14c - This register is used to enable ECC on the USB1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_usb1(&self) -> &EccgrpUsb1 {
        &self.eccgrp_usb1
    }
    #[doc = "0x150 - This register is used to enable ECC on the EMAC0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_emac0(&self) -> &EccgrpEmac0 {
        &self.eccgrp_emac0
    }
    #[doc = "0x154 - This register is used to enable ECC on the EMAC1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_emac1(&self) -> &EccgrpEmac1 {
        &self.eccgrp_emac1
    }
    #[doc = "0x158 - This register is used to enable ECC on the DMA RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_dma(&self) -> &EccgrpDma {
        &self.eccgrp_dma
    }
    #[doc = "0x15c - This register is used to enable ECC on the CAN0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_can0(&self) -> &EccgrpCan0 {
        &self.eccgrp_can0
    }
    #[doc = "0x160 - This register is used to enable ECC on the CAN1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_can1(&self) -> &EccgrpCan1 {
        &self.eccgrp_can1
    }
    #[doc = "0x164 - This register is used to enable ECC on the NAND RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_nand(&self) -> &EccgrpNand {
        &self.eccgrp_nand
    }
    #[doc = "0x168 - This register is used to enable ECC on the QSPI RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_qspi(&self) -> &EccgrpQspi {
        &self.eccgrp_qspi
    }
    #[doc = "0x16c - This register is used to enable ECC on the SDMMC RAM.ECC errors can be injected into the write path using bits in this register. Only reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub const fn eccgrp_sdmmc(&self) -> &EccgrpSdmmc {
        &self.eccgrp_sdmmc
    }
    #[doc = "0x400 - This register is used to control the peripherals connected to emac0_tx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio0(&self) -> &PinmuxgrpEmacio0 {
        &self.pinmuxgrp_emacio0
    }
    #[doc = "0x404 - This register is used to control the peripherals connected to emac0_tx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio1(&self) -> &PinmuxgrpEmacio1 {
        &self.pinmuxgrp_emacio1
    }
    #[doc = "0x408 - This register is used to control the peripherals connected to emac0_tx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio2(&self) -> &PinmuxgrpEmacio2 {
        &self.pinmuxgrp_emacio2
    }
    #[doc = "0x40c - This register is used to control the peripherals connected to emac0_tx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio3(&self) -> &PinmuxgrpEmacio3 {
        &self.pinmuxgrp_emacio3
    }
    #[doc = "0x410 - This register is used to control the peripherals connected to emac0_tx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio4(&self) -> &PinmuxgrpEmacio4 {
        &self.pinmuxgrp_emacio4
    }
    #[doc = "0x414 - This register is used to control the peripherals connected to emac0_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio5(&self) -> &PinmuxgrpEmacio5 {
        &self.pinmuxgrp_emacio5
    }
    #[doc = "0x418 - This register is used to control the peripherals connected to emac0_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio6(&self) -> &PinmuxgrpEmacio6 {
        &self.pinmuxgrp_emacio6
    }
    #[doc = "0x41c - This register is used to control the peripherals connected to emac0_mdc Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio7(&self) -> &PinmuxgrpEmacio7 {
        &self.pinmuxgrp_emacio7
    }
    #[doc = "0x420 - This register is used to control the peripherals connected to emac0_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio8(&self) -> &PinmuxgrpEmacio8 {
        &self.pinmuxgrp_emacio8
    }
    #[doc = "0x424 - This register is used to control the peripherals connected to emac0_tx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio9(&self) -> &PinmuxgrpEmacio9 {
        &self.pinmuxgrp_emacio9
    }
    #[doc = "0x428 - This register is used to control the peripherals connected to emac0_rx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio10(&self) -> &PinmuxgrpEmacio10 {
        &self.pinmuxgrp_emacio10
    }
    #[doc = "0x42c - This register is used to control the peripherals connected to emac0_rx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio11(&self) -> &PinmuxgrpEmacio11 {
        &self.pinmuxgrp_emacio11
    }
    #[doc = "0x430 - This register is used to control the peripherals connected to emac0_rx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio12(&self) -> &PinmuxgrpEmacio12 {
        &self.pinmuxgrp_emacio12
    }
    #[doc = "0x434 - This register is used to control the peripherals connected to emac0_rx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio13(&self) -> &PinmuxgrpEmacio13 {
        &self.pinmuxgrp_emacio13
    }
    #[doc = "0x438 - This register is used to control the peripherals connected to emac1_tx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio14(&self) -> &PinmuxgrpEmacio14 {
        &self.pinmuxgrp_emacio14
    }
    #[doc = "0x43c - This register is used to control the peripherals connected to emac1_tx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio15(&self) -> &PinmuxgrpEmacio15 {
        &self.pinmuxgrp_emacio15
    }
    #[doc = "0x440 - This register is used to control the peripherals connected to emac1_tx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio16(&self) -> &PinmuxgrpEmacio16 {
        &self.pinmuxgrp_emacio16
    }
    #[doc = "0x444 - This register is used to control the peripherals connected to emac1_tx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio17(&self) -> &PinmuxgrpEmacio17 {
        &self.pinmuxgrp_emacio17
    }
    #[doc = "0x448 - This register is used to control the peripherals connected to emac1_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio18(&self) -> &PinmuxgrpEmacio18 {
        &self.pinmuxgrp_emacio18
    }
    #[doc = "0x44c - This register is used to control the peripherals connected to emac1_rx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_emacio19(&self) -> &PinmuxgrpEmacio19 {
        &self.pinmuxgrp_emacio19
    }
    #[doc = "0x450 - This register is used to control the peripherals connected to sdmmc_cmd Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio0(&self) -> &PinmuxgrpFlashio0 {
        &self.pinmuxgrp_flashio0
    }
    #[doc = "0x454 - This register is used to control the peripherals connected to sdmmc_pwren Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio1(&self) -> &PinmuxgrpFlashio1 {
        &self.pinmuxgrp_flashio1
    }
    #[doc = "0x458 - This register is used to control the peripherals connected to sdmmc_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio2(&self) -> &PinmuxgrpFlashio2 {
        &self.pinmuxgrp_flashio2
    }
    #[doc = "0x45c - This register is used to control the peripherals connected to sdmmc_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio3(&self) -> &PinmuxgrpFlashio3 {
        &self.pinmuxgrp_flashio3
    }
    #[doc = "0x460 - This register is used to control the peripherals connected to sdmmc_d4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio4(&self) -> &PinmuxgrpFlashio4 {
        &self.pinmuxgrp_flashio4
    }
    #[doc = "0x464 - This register is used to control the peripherals connected to sdmmc_d5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio5(&self) -> &PinmuxgrpFlashio5 {
        &self.pinmuxgrp_flashio5
    }
    #[doc = "0x468 - This register is used to control the peripherals connected to sdmmc_d6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio6(&self) -> &PinmuxgrpFlashio6 {
        &self.pinmuxgrp_flashio6
    }
    #[doc = "0x46c - This register is used to control the peripherals connected to sdmmc_d7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio7(&self) -> &PinmuxgrpFlashio7 {
        &self.pinmuxgrp_flashio7
    }
    #[doc = "0x470 - This register is used to control the peripherals connected to sdmmc_clk_in Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio8(&self) -> &PinmuxgrpFlashio8 {
        &self.pinmuxgrp_flashio8
    }
    #[doc = "0x474 - This register is used to control the peripherals connected to sdmmc_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio9(&self) -> &PinmuxgrpFlashio9 {
        &self.pinmuxgrp_flashio9
    }
    #[doc = "0x478 - This register is used to control the peripherals connected to sdmmc_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio10(&self) -> &PinmuxgrpFlashio10 {
        &self.pinmuxgrp_flashio10
    }
    #[doc = "0x47c - This register is used to control the peripherals connected to sdmmc_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_flashio11(&self) -> &PinmuxgrpFlashio11 {
        &self.pinmuxgrp_flashio11
    }
    #[doc = "0x480 - This register is used to control the peripherals connected to trace_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio0(&self) -> &PinmuxgrpGeneralio0 {
        &self.pinmuxgrp_generalio0
    }
    #[doc = "0x484 - This register is used to control the peripherals connected to trace_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio1(&self) -> &PinmuxgrpGeneralio1 {
        &self.pinmuxgrp_generalio1
    }
    #[doc = "0x488 - This register is used to control the peripherals connected to trace_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio2(&self) -> &PinmuxgrpGeneralio2 {
        &self.pinmuxgrp_generalio2
    }
    #[doc = "0x48c - This register is used to control the peripherals connected to trace_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio3(&self) -> &PinmuxgrpGeneralio3 {
        &self.pinmuxgrp_generalio3
    }
    #[doc = "0x490 - This register is used to control the peripherals connected to trace_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio4(&self) -> &PinmuxgrpGeneralio4 {
        &self.pinmuxgrp_generalio4
    }
    #[doc = "0x494 - This register is used to control the peripherals connected to trace_d4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio5(&self) -> &PinmuxgrpGeneralio5 {
        &self.pinmuxgrp_generalio5
    }
    #[doc = "0x498 - This register is used to control the peripherals connected to trace_d5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio6(&self) -> &PinmuxgrpGeneralio6 {
        &self.pinmuxgrp_generalio6
    }
    #[doc = "0x49c - This register is used to control the peripherals connected to trace_d6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio7(&self) -> &PinmuxgrpGeneralio7 {
        &self.pinmuxgrp_generalio7
    }
    #[doc = "0x4a0 - This register is used to control the peripherals connected to trace_d7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio8(&self) -> &PinmuxgrpGeneralio8 {
        &self.pinmuxgrp_generalio8
    }
    #[doc = "0x4a4 - This register is used to control the peripherals connected to spim0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio9(&self) -> &PinmuxgrpGeneralio9 {
        &self.pinmuxgrp_generalio9
    }
    #[doc = "0x4a8 - This register is used to control the peripherals connected to spim0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio10(&self) -> &PinmuxgrpGeneralio10 {
        &self.pinmuxgrp_generalio10
    }
    #[doc = "0x4ac - This register is used to control the peripherals connected to spim0_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio11(&self) -> &PinmuxgrpGeneralio11 {
        &self.pinmuxgrp_generalio11
    }
    #[doc = "0x4b0 - This register is used to control the peripherals connected to spim0_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio12(&self) -> &PinmuxgrpGeneralio12 {
        &self.pinmuxgrp_generalio12
    }
    #[doc = "0x4b4 - This register is used to control the peripherals connected to uart0_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio13(&self) -> &PinmuxgrpGeneralio13 {
        &self.pinmuxgrp_generalio13
    }
    #[doc = "0x4b8 - This register is used to control the peripherals connected to uart0_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio14(&self) -> &PinmuxgrpGeneralio14 {
        &self.pinmuxgrp_generalio14
    }
    #[doc = "0x4bc - This register is used to control the peripherals connected to i2c0_sda Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio15(&self) -> &PinmuxgrpGeneralio15 {
        &self.pinmuxgrp_generalio15
    }
    #[doc = "0x4c0 - This register is used to control the peripherals connected to i2c0_scl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio16(&self) -> &PinmuxgrpGeneralio16 {
        &self.pinmuxgrp_generalio16
    }
    #[doc = "0x4c4 - This register is used to control the peripherals connected to can0_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio17(&self) -> &PinmuxgrpGeneralio17 {
        &self.pinmuxgrp_generalio17
    }
    #[doc = "0x4c8 - This register is used to control the peripherals connected to can0_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio18(&self) -> &PinmuxgrpGeneralio18 {
        &self.pinmuxgrp_generalio18
    }
    #[doc = "0x4cc - This register is used to control the peripherals connected to spis1_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio19(&self) -> &PinmuxgrpGeneralio19 {
        &self.pinmuxgrp_generalio19
    }
    #[doc = "0x4d0 - This register is used to control the peripherals connected to spis1_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio20(&self) -> &PinmuxgrpGeneralio20 {
        &self.pinmuxgrp_generalio20
    }
    #[doc = "0x4d4 - This register is used to control the peripherals connected to spis1_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio21(&self) -> &PinmuxgrpGeneralio21 {
        &self.pinmuxgrp_generalio21
    }
    #[doc = "0x4d8 - This register is used to control the peripherals connected to spis1_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio22(&self) -> &PinmuxgrpGeneralio22 {
        &self.pinmuxgrp_generalio22
    }
    #[doc = "0x4dc - This register is used to control the peripherals connected to uart1_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio23(&self) -> &PinmuxgrpGeneralio23 {
        &self.pinmuxgrp_generalio23
    }
    #[doc = "0x4e0 - This register is used to control the peripherals connected to uart1_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio24(&self) -> &PinmuxgrpGeneralio24 {
        &self.pinmuxgrp_generalio24
    }
    #[doc = "0x4e4 - This register is used to control the peripherals connected to i2c1_sda Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio25(&self) -> &PinmuxgrpGeneralio25 {
        &self.pinmuxgrp_generalio25
    }
    #[doc = "0x4e8 - This register is used to control the peripherals connected to i2c1_scl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio26(&self) -> &PinmuxgrpGeneralio26 {
        &self.pinmuxgrp_generalio26
    }
    #[doc = "0x4ec - This register is used to control the peripherals connected to spim0_ss0_alt Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio27(&self) -> &PinmuxgrpGeneralio27 {
        &self.pinmuxgrp_generalio27
    }
    #[doc = "0x4f0 - This register is used to control the peripherals connected to spis0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio28(&self) -> &PinmuxgrpGeneralio28 {
        &self.pinmuxgrp_generalio28
    }
    #[doc = "0x4f4 - This register is used to control the peripherals connected to spis0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio29(&self) -> &PinmuxgrpGeneralio29 {
        &self.pinmuxgrp_generalio29
    }
    #[doc = "0x4f8 - This register is used to control the peripherals connected to spis0_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio30(&self) -> &PinmuxgrpGeneralio30 {
        &self.pinmuxgrp_generalio30
    }
    #[doc = "0x4fc - This register is used to control the peripherals connected to spis0_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_generalio31(&self) -> &PinmuxgrpGeneralio31 {
        &self.pinmuxgrp_generalio31
    }
    #[doc = "0x500 - This register is used to control the peripherals connected to nand_ale Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io0(&self) -> &PinmuxgrpMixed1io0 {
        &self.pinmuxgrp_mixed1io0
    }
    #[doc = "0x504 - This register is used to control the peripherals connected to nand_ce Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io1(&self) -> &PinmuxgrpMixed1io1 {
        &self.pinmuxgrp_mixed1io1
    }
    #[doc = "0x508 - This register is used to control the peripherals connected to nand_cle Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io2(&self) -> &PinmuxgrpMixed1io2 {
        &self.pinmuxgrp_mixed1io2
    }
    #[doc = "0x50c - This register is used to control the peripherals connected to nand_re Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io3(&self) -> &PinmuxgrpMixed1io3 {
        &self.pinmuxgrp_mixed1io3
    }
    #[doc = "0x510 - This register is used to control the peripherals connected to nand_rb Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io4(&self) -> &PinmuxgrpMixed1io4 {
        &self.pinmuxgrp_mixed1io4
    }
    #[doc = "0x514 - This register is used to control the peripherals connected to nand_dq0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io5(&self) -> &PinmuxgrpMixed1io5 {
        &self.pinmuxgrp_mixed1io5
    }
    #[doc = "0x518 - This register is used to control the peripherals connected to nand_dq1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io6(&self) -> &PinmuxgrpMixed1io6 {
        &self.pinmuxgrp_mixed1io6
    }
    #[doc = "0x51c - This register is used to control the peripherals connected to nand_dq2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io7(&self) -> &PinmuxgrpMixed1io7 {
        &self.pinmuxgrp_mixed1io7
    }
    #[doc = "0x520 - This register is used to control the peripherals connected to nand_dq3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io8(&self) -> &PinmuxgrpMixed1io8 {
        &self.pinmuxgrp_mixed1io8
    }
    #[doc = "0x524 - This register is used to control the peripherals connected to nand_dq4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io9(&self) -> &PinmuxgrpMixed1io9 {
        &self.pinmuxgrp_mixed1io9
    }
    #[doc = "0x528 - This register is used to control the peripherals connected to nand_dq5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io10(&self) -> &PinmuxgrpMixed1io10 {
        &self.pinmuxgrp_mixed1io10
    }
    #[doc = "0x52c - This register is used to control the peripherals connected to nand_dq6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io11(&self) -> &PinmuxgrpMixed1io11 {
        &self.pinmuxgrp_mixed1io11
    }
    #[doc = "0x530 - This register is used to control the peripherals connected to nand_dq7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io12(&self) -> &PinmuxgrpMixed1io12 {
        &self.pinmuxgrp_mixed1io12
    }
    #[doc = "0x534 - This register is used to control the peripherals connected to nand_wp Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io13(&self) -> &PinmuxgrpMixed1io13 {
        &self.pinmuxgrp_mixed1io13
    }
    #[doc = "0x538 - This register is used to control the peripherals connected to nand_we Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io14(&self) -> &PinmuxgrpMixed1io14 {
        &self.pinmuxgrp_mixed1io14
    }
    #[doc = "0x53c - This register is used to control the peripherals connected to qspi_io0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io15(&self) -> &PinmuxgrpMixed1io15 {
        &self.pinmuxgrp_mixed1io15
    }
    #[doc = "0x540 - This register is used to control the peripherals connected to qspi_io1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io16(&self) -> &PinmuxgrpMixed1io16 {
        &self.pinmuxgrp_mixed1io16
    }
    #[doc = "0x544 - This register is used to control the peripherals connected to qspi_io2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io17(&self) -> &PinmuxgrpMixed1io17 {
        &self.pinmuxgrp_mixed1io17
    }
    #[doc = "0x548 - This register is used to control the peripherals connected to qspi_io3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io18(&self) -> &PinmuxgrpMixed1io18 {
        &self.pinmuxgrp_mixed1io18
    }
    #[doc = "0x54c - This register is used to control the peripherals connected to qspi_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io19(&self) -> &PinmuxgrpMixed1io19 {
        &self.pinmuxgrp_mixed1io19
    }
    #[doc = "0x550 - This register is used to control the peripherals connected to qpsi_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io20(&self) -> &PinmuxgrpMixed1io20 {
        &self.pinmuxgrp_mixed1io20
    }
    #[doc = "0x554 - This register is used to control the peripherals connected to qspi_ss1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed1io21(&self) -> &PinmuxgrpMixed1io21 {
        &self.pinmuxgrp_mixed1io21
    }
    #[doc = "0x558 - This register is used to control the peripherals connected to emac1_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io0(&self) -> &PinmuxgrpMixed2io0 {
        &self.pinmuxgrp_mixed2io0
    }
    #[doc = "0x55c - This register is used to control the peripherals connected to emac1_mdc Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io1(&self) -> &PinmuxgrpMixed2io1 {
        &self.pinmuxgrp_mixed2io1
    }
    #[doc = "0x560 - This register is used to control the peripherals connected to emac1_tx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io2(&self) -> &PinmuxgrpMixed2io2 {
        &self.pinmuxgrp_mixed2io2
    }
    #[doc = "0x564 - This register is used to control the peripherals connected to emac1_tx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io3(&self) -> &PinmuxgrpMixed2io3 {
        &self.pinmuxgrp_mixed2io3
    }
    #[doc = "0x568 - This register is used to control the peripherals connected to emac1_rx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io4(&self) -> &PinmuxgrpMixed2io4 {
        &self.pinmuxgrp_mixed2io4
    }
    #[doc = "0x56c - This register is used to control the peripherals connected to emac1_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io5(&self) -> &PinmuxgrpMixed2io5 {
        &self.pinmuxgrp_mixed2io5
    }
    #[doc = "0x570 - This register is used to control the peripherals connected to emac1_rx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io6(&self) -> &PinmuxgrpMixed2io6 {
        &self.pinmuxgrp_mixed2io6
    }
    #[doc = "0x574 - This register is used to control the peripherals connected to emac1_rx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_mixed2io7(&self) -> &PinmuxgrpMixed2io7 {
        &self.pinmuxgrp_mixed2io7
    }
    #[doc = "0x578 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 48. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux48(&self) -> &PinmuxgrpGplinmux48 {
        &self.pinmuxgrp_gplinmux48
    }
    #[doc = "0x57c - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 49. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux49(&self) -> &PinmuxgrpGplinmux49 {
        &self.pinmuxgrp_gplinmux49
    }
    #[doc = "0x580 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 50. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux50(&self) -> &PinmuxgrpGplinmux50 {
        &self.pinmuxgrp_gplinmux50
    }
    #[doc = "0x584 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 51. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux51(&self) -> &PinmuxgrpGplinmux51 {
        &self.pinmuxgrp_gplinmux51
    }
    #[doc = "0x588 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 52. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux52(&self) -> &PinmuxgrpGplinmux52 {
        &self.pinmuxgrp_gplinmux52
    }
    #[doc = "0x58c - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 53. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux53(&self) -> &PinmuxgrpGplinmux53 {
        &self.pinmuxgrp_gplinmux53
    }
    #[doc = "0x590 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 54. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux54(&self) -> &PinmuxgrpGplinmux54 {
        &self.pinmuxgrp_gplinmux54
    }
    #[doc = "0x594 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 55. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux55(&self) -> &PinmuxgrpGplinmux55 {
        &self.pinmuxgrp_gplinmux55
    }
    #[doc = "0x598 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 56. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux56(&self) -> &PinmuxgrpGplinmux56 {
        &self.pinmuxgrp_gplinmux56
    }
    #[doc = "0x59c - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 57. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux57(&self) -> &PinmuxgrpGplinmux57 {
        &self.pinmuxgrp_gplinmux57
    }
    #[doc = "0x5a0 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 58. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux58(&self) -> &PinmuxgrpGplinmux58 {
        &self.pinmuxgrp_gplinmux58
    }
    #[doc = "0x5a4 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 59. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux59(&self) -> &PinmuxgrpGplinmux59 {
        &self.pinmuxgrp_gplinmux59
    }
    #[doc = "0x5a8 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 60. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux60(&self) -> &PinmuxgrpGplinmux60 {
        &self.pinmuxgrp_gplinmux60
    }
    #[doc = "0x5ac - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 61. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux61(&self) -> &PinmuxgrpGplinmux61 {
        &self.pinmuxgrp_gplinmux61
    }
    #[doc = "0x5b0 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 62. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux62(&self) -> &PinmuxgrpGplinmux62 {
        &self.pinmuxgrp_gplinmux62
    }
    #[doc = "0x5b4 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 63. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux63(&self) -> &PinmuxgrpGplinmux63 {
        &self.pinmuxgrp_gplinmux63
    }
    #[doc = "0x5b8 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 64. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux64(&self) -> &PinmuxgrpGplinmux64 {
        &self.pinmuxgrp_gplinmux64
    }
    #[doc = "0x5bc - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 65. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux65(&self) -> &PinmuxgrpGplinmux65 {
        &self.pinmuxgrp_gplinmux65
    }
    #[doc = "0x5c0 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 66. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux66(&self) -> &PinmuxgrpGplinmux66 {
        &self.pinmuxgrp_gplinmux66
    }
    #[doc = "0x5c4 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 67. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux67(&self) -> &PinmuxgrpGplinmux67 {
        &self.pinmuxgrp_gplinmux67
    }
    #[doc = "0x5c8 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 68. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux68(&self) -> &PinmuxgrpGplinmux68 {
        &self.pinmuxgrp_gplinmux68
    }
    #[doc = "0x5cc - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 69. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux69(&self) -> &PinmuxgrpGplinmux69 {
        &self.pinmuxgrp_gplinmux69
    }
    #[doc = "0x5d0 - Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 70. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplinmux70(&self) -> &PinmuxgrpGplinmux70 {
        &self.pinmuxgrp_gplinmux70
    }
    #[doc = "0x5d4 - Selection between GPIO and LoanIO output and output enable for GPIO0 and LoanIO0. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux0(&self) -> &PinmuxgrpGplmux0 {
        &self.pinmuxgrp_gplmux0
    }
    #[doc = "0x5d8 - Selection between GPIO and LoanIO output and output enable for GPIO1 and LoanIO1. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux1(&self) -> &PinmuxgrpGplmux1 {
        &self.pinmuxgrp_gplmux1
    }
    #[doc = "0x5dc - Selection between GPIO and LoanIO output and output enable for GPIO2 and LoanIO2. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux2(&self) -> &PinmuxgrpGplmux2 {
        &self.pinmuxgrp_gplmux2
    }
    #[doc = "0x5e0 - Selection between GPIO and LoanIO output and output enable for GPIO3 and LoanIO3. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux3(&self) -> &PinmuxgrpGplmux3 {
        &self.pinmuxgrp_gplmux3
    }
    #[doc = "0x5e4 - Selection between GPIO and LoanIO output and output enable for GPIO4 and LoanIO4. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux4(&self) -> &PinmuxgrpGplmux4 {
        &self.pinmuxgrp_gplmux4
    }
    #[doc = "0x5e8 - Selection between GPIO and LoanIO output and output enable for GPIO5 and LoanIO5. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux5(&self) -> &PinmuxgrpGplmux5 {
        &self.pinmuxgrp_gplmux5
    }
    #[doc = "0x5ec - Selection between GPIO and LoanIO output and output enable for GPIO6 and LoanIO6. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux6(&self) -> &PinmuxgrpGplmux6 {
        &self.pinmuxgrp_gplmux6
    }
    #[doc = "0x5f0 - Selection between GPIO and LoanIO output and output enable for GPIO7 and LoanIO7. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux7(&self) -> &PinmuxgrpGplmux7 {
        &self.pinmuxgrp_gplmux7
    }
    #[doc = "0x5f4 - Selection between GPIO and LoanIO output and output enable for GPIO8 and LoanIO8. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux8(&self) -> &PinmuxgrpGplmux8 {
        &self.pinmuxgrp_gplmux8
    }
    #[doc = "0x5f8 - Selection between GPIO and LoanIO output and output enable for GPIO9 and LoanIO9. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux9(&self) -> &PinmuxgrpGplmux9 {
        &self.pinmuxgrp_gplmux9
    }
    #[doc = "0x5fc - Selection between GPIO and LoanIO output and output enable for GPIO10 and LoanIO10. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux10(&self) -> &PinmuxgrpGplmux10 {
        &self.pinmuxgrp_gplmux10
    }
    #[doc = "0x600 - Selection between GPIO and LoanIO output and output enable for GPIO11 and LoanIO11. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux11(&self) -> &PinmuxgrpGplmux11 {
        &self.pinmuxgrp_gplmux11
    }
    #[doc = "0x604 - Selection between GPIO and LoanIO output and output enable for GPIO12 and LoanIO12. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux12(&self) -> &PinmuxgrpGplmux12 {
        &self.pinmuxgrp_gplmux12
    }
    #[doc = "0x608 - Selection between GPIO and LoanIO output and output enable for GPIO13 and LoanIO13. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux13(&self) -> &PinmuxgrpGplmux13 {
        &self.pinmuxgrp_gplmux13
    }
    #[doc = "0x60c - Selection between GPIO and LoanIO output and output enable for GPIO14 and LoanIO14. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux14(&self) -> &PinmuxgrpGplmux14 {
        &self.pinmuxgrp_gplmux14
    }
    #[doc = "0x610 - Selection between GPIO and LoanIO output and output enable for GPIO15 and LoanIO15. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux15(&self) -> &PinmuxgrpGplmux15 {
        &self.pinmuxgrp_gplmux15
    }
    #[doc = "0x614 - Selection between GPIO and LoanIO output and output enable for GPIO16 and LoanIO16. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux16(&self) -> &PinmuxgrpGplmux16 {
        &self.pinmuxgrp_gplmux16
    }
    #[doc = "0x618 - Selection between GPIO and LoanIO output and output enable for GPIO17 and LoanIO17. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux17(&self) -> &PinmuxgrpGplmux17 {
        &self.pinmuxgrp_gplmux17
    }
    #[doc = "0x61c - Selection between GPIO and LoanIO output and output enable for GPIO18 and LoanIO18. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux18(&self) -> &PinmuxgrpGplmux18 {
        &self.pinmuxgrp_gplmux18
    }
    #[doc = "0x620 - Selection between GPIO and LoanIO output and output enable for GPIO19 and LoanIO19. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux19(&self) -> &PinmuxgrpGplmux19 {
        &self.pinmuxgrp_gplmux19
    }
    #[doc = "0x624 - Selection between GPIO and LoanIO output and output enable for GPIO20 and LoanIO20. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux20(&self) -> &PinmuxgrpGplmux20 {
        &self.pinmuxgrp_gplmux20
    }
    #[doc = "0x628 - Selection between GPIO and LoanIO output and output enable for GPIO21 and LoanIO21. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux21(&self) -> &PinmuxgrpGplmux21 {
        &self.pinmuxgrp_gplmux21
    }
    #[doc = "0x62c - Selection between GPIO and LoanIO output and output enable for GPIO22 and LoanIO22. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux22(&self) -> &PinmuxgrpGplmux22 {
        &self.pinmuxgrp_gplmux22
    }
    #[doc = "0x630 - Selection between GPIO and LoanIO output and output enable for GPIO23 and LoanIO23. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux23(&self) -> &PinmuxgrpGplmux23 {
        &self.pinmuxgrp_gplmux23
    }
    #[doc = "0x634 - Selection between GPIO and LoanIO output and output enable for GPIO24 and LoanIO24. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux24(&self) -> &PinmuxgrpGplmux24 {
        &self.pinmuxgrp_gplmux24
    }
    #[doc = "0x638 - Selection between GPIO and LoanIO output and output enable for GPIO25 and LoanIO25. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux25(&self) -> &PinmuxgrpGplmux25 {
        &self.pinmuxgrp_gplmux25
    }
    #[doc = "0x63c - Selection between GPIO and LoanIO output and output enable for GPIO26 and LoanIO26. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux26(&self) -> &PinmuxgrpGplmux26 {
        &self.pinmuxgrp_gplmux26
    }
    #[doc = "0x640 - Selection between GPIO and LoanIO output and output enable for GPIO27 and LoanIO27. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux27(&self) -> &PinmuxgrpGplmux27 {
        &self.pinmuxgrp_gplmux27
    }
    #[doc = "0x644 - Selection between GPIO and LoanIO output and output enable for GPIO28 and LoanIO28. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux28(&self) -> &PinmuxgrpGplmux28 {
        &self.pinmuxgrp_gplmux28
    }
    #[doc = "0x648 - Selection between GPIO and LoanIO output and output enable for GPIO29 and LoanIO29. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux29(&self) -> &PinmuxgrpGplmux29 {
        &self.pinmuxgrp_gplmux29
    }
    #[doc = "0x64c - Selection between GPIO and LoanIO output and output enable for GPIO30 and LoanIO30. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux30(&self) -> &PinmuxgrpGplmux30 {
        &self.pinmuxgrp_gplmux30
    }
    #[doc = "0x650 - Selection between GPIO and LoanIO output and output enable for GPIO31 and LoanIO31. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux31(&self) -> &PinmuxgrpGplmux31 {
        &self.pinmuxgrp_gplmux31
    }
    #[doc = "0x654 - Selection between GPIO and LoanIO output and output enable for GPIO32 and LoanIO32. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux32(&self) -> &PinmuxgrpGplmux32 {
        &self.pinmuxgrp_gplmux32
    }
    #[doc = "0x658 - Selection between GPIO and LoanIO output and output enable for GPIO33 and LoanIO33. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux33(&self) -> &PinmuxgrpGplmux33 {
        &self.pinmuxgrp_gplmux33
    }
    #[doc = "0x65c - Selection between GPIO and LoanIO output and output enable for GPIO34 and LoanIO34. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux34(&self) -> &PinmuxgrpGplmux34 {
        &self.pinmuxgrp_gplmux34
    }
    #[doc = "0x660 - Selection between GPIO and LoanIO output and output enable for GPIO35 and LoanIO35. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux35(&self) -> &PinmuxgrpGplmux35 {
        &self.pinmuxgrp_gplmux35
    }
    #[doc = "0x664 - Selection between GPIO and LoanIO output and output enable for GPIO36 and LoanIO36. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux36(&self) -> &PinmuxgrpGplmux36 {
        &self.pinmuxgrp_gplmux36
    }
    #[doc = "0x668 - Selection between GPIO and LoanIO output and output enable for GPIO37 and LoanIO37. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux37(&self) -> &PinmuxgrpGplmux37 {
        &self.pinmuxgrp_gplmux37
    }
    #[doc = "0x66c - Selection between GPIO and LoanIO output and output enable for GPIO38 and LoanIO38. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux38(&self) -> &PinmuxgrpGplmux38 {
        &self.pinmuxgrp_gplmux38
    }
    #[doc = "0x670 - Selection between GPIO and LoanIO output and output enable for GPIO39 and LoanIO39. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux39(&self) -> &PinmuxgrpGplmux39 {
        &self.pinmuxgrp_gplmux39
    }
    #[doc = "0x674 - Selection between GPIO and LoanIO output and output enable for GPIO40 and LoanIO40. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux40(&self) -> &PinmuxgrpGplmux40 {
        &self.pinmuxgrp_gplmux40
    }
    #[doc = "0x678 - Selection between GPIO and LoanIO output and output enable for GPIO41 and LoanIO41. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux41(&self) -> &PinmuxgrpGplmux41 {
        &self.pinmuxgrp_gplmux41
    }
    #[doc = "0x67c - Selection between GPIO and LoanIO output and output enable for GPIO42 and LoanIO42. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux42(&self) -> &PinmuxgrpGplmux42 {
        &self.pinmuxgrp_gplmux42
    }
    #[doc = "0x680 - Selection between GPIO and LoanIO output and output enable for GPIO43 and LoanIO43. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux43(&self) -> &PinmuxgrpGplmux43 {
        &self.pinmuxgrp_gplmux43
    }
    #[doc = "0x684 - Selection between GPIO and LoanIO output and output enable for GPIO44 and LoanIO44. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux44(&self) -> &PinmuxgrpGplmux44 {
        &self.pinmuxgrp_gplmux44
    }
    #[doc = "0x688 - Selection between GPIO and LoanIO output and output enable for GPIO45 and LoanIO45. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux45(&self) -> &PinmuxgrpGplmux45 {
        &self.pinmuxgrp_gplmux45
    }
    #[doc = "0x68c - Selection between GPIO and LoanIO output and output enable for GPIO46 and LoanIO46. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux46(&self) -> &PinmuxgrpGplmux46 {
        &self.pinmuxgrp_gplmux46
    }
    #[doc = "0x690 - Selection between GPIO and LoanIO output and output enable for GPIO47 and LoanIO47. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux47(&self) -> &PinmuxgrpGplmux47 {
        &self.pinmuxgrp_gplmux47
    }
    #[doc = "0x694 - Selection between GPIO and LoanIO output and output enable for GPIO48 and LoanIO48. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux48(&self) -> &PinmuxgrpGplmux48 {
        &self.pinmuxgrp_gplmux48
    }
    #[doc = "0x698 - Selection between GPIO and LoanIO output and output enable for GPIO49 and LoanIO49. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux49(&self) -> &PinmuxgrpGplmux49 {
        &self.pinmuxgrp_gplmux49
    }
    #[doc = "0x69c - Selection between GPIO and LoanIO output and output enable for GPIO50 and LoanIO50. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux50(&self) -> &PinmuxgrpGplmux50 {
        &self.pinmuxgrp_gplmux50
    }
    #[doc = "0x6a0 - Selection between GPIO and LoanIO output and output enable for GPIO51 and LoanIO51. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux51(&self) -> &PinmuxgrpGplmux51 {
        &self.pinmuxgrp_gplmux51
    }
    #[doc = "0x6a4 - Selection between GPIO and LoanIO output and output enable for GPIO52 and LoanIO52. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux52(&self) -> &PinmuxgrpGplmux52 {
        &self.pinmuxgrp_gplmux52
    }
    #[doc = "0x6a8 - Selection between GPIO and LoanIO output and output enable for GPIO53 and LoanIO53. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux53(&self) -> &PinmuxgrpGplmux53 {
        &self.pinmuxgrp_gplmux53
    }
    #[doc = "0x6ac - Selection between GPIO and LoanIO output and output enable for GPIO54 and LoanIO54. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux54(&self) -> &PinmuxgrpGplmux54 {
        &self.pinmuxgrp_gplmux54
    }
    #[doc = "0x6b0 - Selection between GPIO and LoanIO output and output enable for GPIO55 and LoanIO55. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux55(&self) -> &PinmuxgrpGplmux55 {
        &self.pinmuxgrp_gplmux55
    }
    #[doc = "0x6b4 - Selection between GPIO and LoanIO output and output enable for GPIO56 and LoanIO56. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux56(&self) -> &PinmuxgrpGplmux56 {
        &self.pinmuxgrp_gplmux56
    }
    #[doc = "0x6b8 - Selection between GPIO and LoanIO output and output enable for GPIO57 and LoanIO57. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux57(&self) -> &PinmuxgrpGplmux57 {
        &self.pinmuxgrp_gplmux57
    }
    #[doc = "0x6bc - Selection between GPIO and LoanIO output and output enable for GPIO58 and LoanIO58. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux58(&self) -> &PinmuxgrpGplmux58 {
        &self.pinmuxgrp_gplmux58
    }
    #[doc = "0x6c0 - Selection between GPIO and LoanIO output and output enable for GPIO59 and LoanIO59. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux59(&self) -> &PinmuxgrpGplmux59 {
        &self.pinmuxgrp_gplmux59
    }
    #[doc = "0x6c4 - Selection between GPIO and LoanIO output and output enable for GPIO60 and LoanIO60. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux60(&self) -> &PinmuxgrpGplmux60 {
        &self.pinmuxgrp_gplmux60
    }
    #[doc = "0x6c8 - Selection between GPIO and LoanIO output and output enable for GPIO61 and LoanIO61. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux61(&self) -> &PinmuxgrpGplmux61 {
        &self.pinmuxgrp_gplmux61
    }
    #[doc = "0x6cc - Selection between GPIO and LoanIO output and output enable for GPIO62 and LoanIO62. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux62(&self) -> &PinmuxgrpGplmux62 {
        &self.pinmuxgrp_gplmux62
    }
    #[doc = "0x6d0 - Selection between GPIO and LoanIO output and output enable for GPIO63 and LoanIO63. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux63(&self) -> &PinmuxgrpGplmux63 {
        &self.pinmuxgrp_gplmux63
    }
    #[doc = "0x6d4 - Selection between GPIO and LoanIO output and output enable for GPIO64 and LoanIO64. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux64(&self) -> &PinmuxgrpGplmux64 {
        &self.pinmuxgrp_gplmux64
    }
    #[doc = "0x6d8 - Selection between GPIO and LoanIO output and output enable for GPIO65 and LoanIO65. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux65(&self) -> &PinmuxgrpGplmux65 {
        &self.pinmuxgrp_gplmux65
    }
    #[doc = "0x6dc - Selection between GPIO and LoanIO output and output enable for GPIO66 and LoanIO66. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux66(&self) -> &PinmuxgrpGplmux66 {
        &self.pinmuxgrp_gplmux66
    }
    #[doc = "0x6e0 - Selection between GPIO and LoanIO output and output enable for GPIO67 and LoanIO67. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux67(&self) -> &PinmuxgrpGplmux67 {
        &self.pinmuxgrp_gplmux67
    }
    #[doc = "0x6e4 - Selection between GPIO and LoanIO output and output enable for GPIO68 and LoanIO68. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux68(&self) -> &PinmuxgrpGplmux68 {
        &self.pinmuxgrp_gplmux68
    }
    #[doc = "0x6e8 - Selection between GPIO and LoanIO output and output enable for GPIO69 and LoanIO69. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux69(&self) -> &PinmuxgrpGplmux69 {
        &self.pinmuxgrp_gplmux69
    }
    #[doc = "0x6ec - Selection between GPIO and LoanIO output and output enable for GPIO70 and LoanIO70. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_gplmux70(&self) -> &PinmuxgrpGplmux70 {
        &self.pinmuxgrp_gplmux70
    }
    #[doc = "0x6f0 - Selection between HPS Pins and FPGA Interface for NAND signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_nandusefpga(&self) -> &PinmuxgrpNandusefpga {
        &self.pinmuxgrp_nandusefpga
    }
    #[doc = "0x6f8 - Selection between HPS Pins and FPGA Interface for RGMII1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_rgmii1usefpga(&self) -> &PinmuxgrpRgmii1usefpga {
        &self.pinmuxgrp_rgmii1usefpga
    }
    #[doc = "0x704 - Selection between HPS Pins and FPGA Interface for I2C0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_i2c0usefpga(&self) -> &PinmuxgrpI2c0usefpga {
        &self.pinmuxgrp_i2c0usefpga
    }
    #[doc = "0x714 - Selection between HPS Pins and FPGA Interface for RGMII0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_rgmii0usefpga(&self) -> &PinmuxgrpRgmii0usefpga {
        &self.pinmuxgrp_rgmii0usefpga
    }
    #[doc = "0x724 - Selection between HPS Pins and FPGA Interface for I2C3 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_i2c3usefpga(&self) -> &PinmuxgrpI2c3usefpga {
        &self.pinmuxgrp_i2c3usefpga
    }
    #[doc = "0x728 - Selection between HPS Pins and FPGA Interface for I2C2 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_i2c2usefpga(&self) -> &PinmuxgrpI2c2usefpga {
        &self.pinmuxgrp_i2c2usefpga
    }
    #[doc = "0x72c - Selection between HPS Pins and FPGA Interface for I2C1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_i2c1usefpga(&self) -> &PinmuxgrpI2c1usefpga {
        &self.pinmuxgrp_i2c1usefpga
    }
    #[doc = "0x730 - Selection between HPS Pins and FPGA Interface for SPIM1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_spim1usefpga(&self) -> &PinmuxgrpSpim1usefpga {
        &self.pinmuxgrp_spim1usefpga
    }
    #[doc = "0x738 - Selection between HPS Pins and FPGA Interface for SPIM0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
    #[inline(always)]
    pub const fn pinmuxgrp_spim0usefpga(&self) -> &PinmuxgrpSpim0usefpga {
        &self.pinmuxgrp_spim0usefpga
    }
}
#[doc = "siliconid1 (r) register accessor: Specifies Silicon ID and revision number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`siliconid1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@siliconid1`]
module"]
#[doc(alias = "siliconid1")]
pub type Siliconid1 = crate::Reg<siliconid1::Siliconid1Spec>;
#[doc = "Specifies Silicon ID and revision number."]
pub mod siliconid1;
#[doc = "siliconid2 (r) register accessor: Reserved for future use.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`siliconid2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@siliconid2`]
module"]
#[doc(alias = "siliconid2")]
pub type Siliconid2 = crate::Reg<siliconid2::Siliconid2Spec>;
#[doc = "Reserved for future use."]
pub mod siliconid2;
#[doc = "wddbg (rw) register accessor: Controls the behavior of the L4 watchdogs when the CPUs are in debug mode. These control registers are used to drive the pause input signal of the L4 watchdogs. Note that the watchdogs built into the MPU automatically are paused when their associated CPU enters debug mode. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wddbg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wddbg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wddbg`]
module"]
#[doc(alias = "wddbg")]
pub type Wddbg = crate::Reg<wddbg::WddbgSpec>;
#[doc = "Controls the behavior of the L4 watchdogs when the CPUs are in debug mode. These control registers are used to drive the pause input signal of the L4 watchdogs. Note that the watchdogs built into the MPU automatically are paused when their associated CPU enters debug mode. Only reset by a cold reset."]
pub mod wddbg;
#[doc = "bootinfo (r) register accessor: Provides access to boot configuration information.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bootinfo::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bootinfo`]
module"]
#[doc(alias = "bootinfo")]
pub type Bootinfo = crate::Reg<bootinfo::BootinfoSpec>;
#[doc = "Provides access to boot configuration information."]
pub mod bootinfo;
#[doc = "hpsinfo (r) register accessor: Provides information about the HPS capabilities.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hpsinfo::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hpsinfo`]
module"]
#[doc(alias = "hpsinfo")]
pub type Hpsinfo = crate::Reg<hpsinfo::HpsinfoSpec>;
#[doc = "Provides information about the HPS capabilities."]
pub mod hpsinfo;
#[doc = "parityinj (rw) register accessor: Inject parity failures into the parity-protected RAMs in the MPU. Allows software to test the parity failure interrupt handler. The field array index corresponds to the CPU index. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`parityinj::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`parityinj::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@parityinj`]
module"]
#[doc(alias = "parityinj")]
pub type Parityinj = crate::Reg<parityinj::ParityinjSpec>;
#[doc = "Inject parity failures into the parity-protected RAMs in the MPU. Allows software to test the parity failure interrupt handler. The field array index corresponds to the CPU index. All fields are reset by a cold or warm reset."]
pub mod parityinj;
#[doc = "fpgaintfgrp_gbl (rw) register accessor: Used to disable all interfaces between the FPGA and HPS.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpgaintfgrp_gbl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpgaintfgrp_gbl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fpgaintfgrp_gbl`]
module"]
#[doc(alias = "fpgaintfgrp_gbl")]
pub type FpgaintfgrpGbl = crate::Reg<fpgaintfgrp_gbl::FpgaintfgrpGblSpec>;
#[doc = "Used to disable all interfaces between the FPGA and HPS."]
pub mod fpgaintfgrp_gbl;
#[doc = "fpgaintfgrp_indiv (rw) register accessor: Used to disable individual interfaces between the FPGA and HPS.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpgaintfgrp_indiv::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpgaintfgrp_indiv::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fpgaintfgrp_indiv`]
module"]
#[doc(alias = "fpgaintfgrp_indiv")]
pub type FpgaintfgrpIndiv = crate::Reg<fpgaintfgrp_indiv::FpgaintfgrpIndivSpec>;
#[doc = "Used to disable individual interfaces between the FPGA and HPS."]
pub mod fpgaintfgrp_indiv;
#[doc = "fpgaintfgrp_module (rw) register accessor: Used to disable signals from the FPGA fabric to individual HPS modules.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpgaintfgrp_module::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpgaintfgrp_module::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fpgaintfgrp_module`]
module"]
#[doc(alias = "fpgaintfgrp_module")]
pub type FpgaintfgrpModule = crate::Reg<fpgaintfgrp_module::FpgaintfgrpModuleSpec>;
#[doc = "Used to disable signals from the FPGA fabric to individual HPS modules."]
pub mod fpgaintfgrp_module;
#[doc = "scanmgrgrp_ctrl (rw) register accessor: Controls behaviors of Scan Manager not controlled by registers in the Scan Manager itself.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`scanmgrgrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`scanmgrgrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@scanmgrgrp_ctrl`]
module"]
#[doc(alias = "scanmgrgrp_ctrl")]
pub type ScanmgrgrpCtrl = crate::Reg<scanmgrgrp_ctrl::ScanmgrgrpCtrlSpec>;
#[doc = "Controls behaviors of Scan Manager not controlled by registers in the Scan Manager itself."]
pub mod scanmgrgrp_ctrl;
#[doc = "frzctrl_vioctrl_ (rw) register accessor: Used to drive freeze signals to HPS VIO banks. The register array index corresponds to the freeze channel. Freeze channel 0 provides freeze signals to VIO bank 0 and 1. Freeze channel 1 provides freeze signals to VIO bank 2 and 3. Only drives freeze signals when SRC.VIO1 is set to SW. Freeze channel 2 provides freeze signals to VIO bank 4. All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_vioctrl_::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_vioctrl_::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@frzctrl_vioctrl_`]
module"]
#[doc(alias = "frzctrl_vioctrl_")]
pub type FrzctrlVioctrl_ = crate::Reg<frzctrl_vioctrl_::FrzctrlVioctrl_Spec>;
#[doc = "Used to drive freeze signals to HPS VIO banks. The register array index corresponds to the freeze channel. Freeze channel 0 provides freeze signals to VIO bank 0 and 1. Freeze channel 1 provides freeze signals to VIO bank 2 and 3. Only drives freeze signals when SRC.VIO1 is set to SW. Freeze channel 2 provides freeze signals to VIO bank 4. All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration"]
pub mod frzctrl_vioctrl_;
#[doc = "frzctrl_hioctrl (rw) register accessor: Used to drive freeze signals to HPS HIO bank (DDR SDRAM). All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_hioctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_hioctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@frzctrl_hioctrl`]
module"]
#[doc(alias = "frzctrl_hioctrl")]
pub type FrzctrlHioctrl = crate::Reg<frzctrl_hioctrl::FrzctrlHioctrlSpec>;
#[doc = "Used to drive freeze signals to HPS HIO bank (DDR SDRAM). All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration"]
pub mod frzctrl_hioctrl;
#[doc = "frzctrl_src (rw) register accessor: Contains register field to choose between software state machine (vioctrl array index \\[1\\]
register) or hardware state machine in the Freeze Controller as the freeze signal source for VIO channel 1. All fields are only reset by a cold reset (ignore warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_src::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_src::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@frzctrl_src`]
module"]
#[doc(alias = "frzctrl_src")]
pub type FrzctrlSrc = crate::Reg<frzctrl_src::FrzctrlSrcSpec>;
#[doc = "Contains register field to choose between software state machine (vioctrl array index \\[1\\]
register) or hardware state machine in the Freeze Controller as the freeze signal source for VIO channel 1. All fields are only reset by a cold reset (ignore warm reset)."]
pub mod frzctrl_src;
#[doc = "frzctrl_hwctrl (rw) register accessor: Activate freeze or thaw operations on VIO channel 1 (HPS IO bank 2 and bank 3) and monitor for completeness and the current state. These fields interact with the hardware state machine in the Freeze Controller. These fields can be accessed independent of the value of SRC1.VIO1 although they only have an effect on the VIO channel 1 freeze signals when SRC1.VIO1 is setup to have the hardware state machine be the freeze signal source. All fields are only reset by a cold reset (ignore warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_hwctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_hwctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@frzctrl_hwctrl`]
module"]
#[doc(alias = "frzctrl_hwctrl")]
pub type FrzctrlHwctrl = crate::Reg<frzctrl_hwctrl::FrzctrlHwctrlSpec>;
#[doc = "Activate freeze or thaw operations on VIO channel 1 (HPS IO bank 2 and bank 3) and monitor for completeness and the current state. These fields interact with the hardware state machine in the Freeze Controller. These fields can be accessed independent of the value of SRC1.VIO1 although they only have an effect on the VIO channel 1 freeze signals when SRC1.VIO1 is setup to have the hardware state machine be the freeze signal source. All fields are only reset by a cold reset (ignore warm reset)."]
pub mod frzctrl_hwctrl;
#[doc = "emacgrp_ctrl (rw) register accessor: Registers used by the EMACs. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`emacgrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`emacgrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@emacgrp_ctrl`]
module"]
#[doc(alias = "emacgrp_ctrl")]
pub type EmacgrpCtrl = crate::Reg<emacgrp_ctrl::EmacgrpCtrlSpec>;
#[doc = "Registers used by the EMACs. All fields are reset by a cold or warm reset."]
pub mod emacgrp_ctrl;
#[doc = "emacgrp_l3master (rw) register accessor: Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`emacgrp_l3master::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`emacgrp_l3master::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@emacgrp_l3master`]
module"]
#[doc(alias = "emacgrp_l3master")]
pub type EmacgrpL3master = crate::Reg<emacgrp_l3master::EmacgrpL3masterSpec>;
#[doc = "Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
pub mod emacgrp_l3master;
#[doc = "dmagrp_ctrl (rw) register accessor: Registers used by the DMA Controller. All fields are reset by a cold or warm reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_ctrl`]
module"]
#[doc(alias = "dmagrp_ctrl")]
pub type DmagrpCtrl = crate::Reg<dmagrp_ctrl::DmagrpCtrlSpec>;
#[doc = "Registers used by the DMA Controller. All fields are reset by a cold or warm reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation."]
pub mod dmagrp_ctrl;
#[doc = "dmagrp_persecurity (rw) register accessor: Controls the security state of a peripheral request interface. Sampled by the DMA controller when it exits from reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_persecurity::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_persecurity::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_persecurity`]
module"]
#[doc(alias = "dmagrp_persecurity")]
pub type DmagrpPersecurity = crate::Reg<dmagrp_persecurity::DmagrpPersecuritySpec>;
#[doc = "Controls the security state of a peripheral request interface. Sampled by the DMA controller when it exits from reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation."]
pub mod dmagrp_persecurity;
#[doc = "iswgrp_handoff_ (rw) register accessor: These registers are used to store handoff infomation between the preloader and the OS. These 8 registers can be used to store any information. The contents of these registers have no impact on the state of the HPS hardware.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iswgrp_handoff_::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iswgrp_handoff_::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iswgrp_handoff_`]
module"]
#[doc(alias = "iswgrp_handoff_")]
pub type IswgrpHandoff_ = crate::Reg<iswgrp_handoff_::IswgrpHandoff_Spec>;
#[doc = "These registers are used to store handoff infomation between the preloader and the OS. These 8 registers can be used to store any information. The contents of these registers have no impact on the state of the HPS hardware."]
pub mod iswgrp_handoff_;
#[doc = "romcodegrp_ctrl (rw) register accessor: Contains information used to control Boot ROM code.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_ctrl`]
module"]
#[doc(alias = "romcodegrp_ctrl")]
pub type RomcodegrpCtrl = crate::Reg<romcodegrp_ctrl::RomcodegrpCtrlSpec>;
#[doc = "Contains information used to control Boot ROM code."]
pub mod romcodegrp_ctrl;
#[doc = "romcodegrp_cpu1startaddr (rw) register accessor: When CPU1 is released from reset and the Boot ROM is located at the CPU1 reset exception address (the typical case), the Boot ROM reset handler code reads the address stored in this register and jumps it to hand off execution to user software.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_cpu1startaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_cpu1startaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_cpu1startaddr`]
module"]
#[doc(alias = "romcodegrp_cpu1startaddr")]
pub type RomcodegrpCpu1startaddr =
    crate::Reg<romcodegrp_cpu1startaddr::RomcodegrpCpu1startaddrSpec>;
#[doc = "When CPU1 is released from reset and the Boot ROM is located at the CPU1 reset exception address (the typical case), the Boot ROM reset handler code reads the address stored in this register and jumps it to hand off execution to user software."]
pub mod romcodegrp_cpu1startaddr;
#[doc = "romcodegrp_initswstate (rw) register accessor: The preloader software (loaded by the Boot ROM) writes the magic value 0x49535756 (ISWV in ASCII) to this register when it has reached a valid state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_initswstate::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_initswstate::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_initswstate`]
module"]
#[doc(alias = "romcodegrp_initswstate")]
pub type RomcodegrpInitswstate = crate::Reg<romcodegrp_initswstate::RomcodegrpInitswstateSpec>;
#[doc = "The preloader software (loaded by the Boot ROM) writes the magic value 0x49535756 (ISWV in ASCII) to this register when it has reached a valid state."]
pub mod romcodegrp_initswstate;
#[doc = "romcodegrp_initswlastld (rw) register accessor: Contains the index of the last preloader software image loaded by the Boot ROM from the boot device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_initswlastld::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_initswlastld::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_initswlastld`]
module"]
#[doc(alias = "romcodegrp_initswlastld")]
pub type RomcodegrpInitswlastld = crate::Reg<romcodegrp_initswlastld::RomcodegrpInitswlastldSpec>;
#[doc = "Contains the index of the last preloader software image loaded by the Boot ROM from the boot device."]
pub mod romcodegrp_initswlastld;
#[doc = "romcodegrp_bootromswstate (rw) register accessor: 32-bits general purpose register used by the Boot ROM code. Actual usage is defined in the Boot ROM source code.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_bootromswstate::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_bootromswstate::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_bootromswstate`]
module"]
#[doc(alias = "romcodegrp_bootromswstate")]
pub type RomcodegrpBootromswstate =
    crate::Reg<romcodegrp_bootromswstate::RomcodegrpBootromswstateSpec>;
#[doc = "32-bits general purpose register used by the Boot ROM code. Actual usage is defined in the Boot ROM source code."]
pub mod romcodegrp_bootromswstate;
#[doc = "romcodegrp_warmramgrp_enable (rw) register accessor: Enables or disables the warm reset from On-chip RAM feature.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_warmramgrp_enable`]
module"]
#[doc(alias = "romcodegrp_warmramgrp_enable")]
pub type RomcodegrpWarmramgrpEnable =
    crate::Reg<romcodegrp_warmramgrp_enable::RomcodegrpWarmramgrpEnableSpec>;
#[doc = "Enables or disables the warm reset from On-chip RAM feature."]
pub mod romcodegrp_warmramgrp_enable;
#[doc = "romcodegrp_warmramgrp_datastart (rw) register accessor: Offset into On-chip RAM of the start of the region for CRC validation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_datastart::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_datastart::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_warmramgrp_datastart`]
module"]
#[doc(alias = "romcodegrp_warmramgrp_datastart")]
pub type RomcodegrpWarmramgrpDatastart =
    crate::Reg<romcodegrp_warmramgrp_datastart::RomcodegrpWarmramgrpDatastartSpec>;
#[doc = "Offset into On-chip RAM of the start of the region for CRC validation"]
pub mod romcodegrp_warmramgrp_datastart;
#[doc = "romcodegrp_warmramgrp_length (rw) register accessor: Length of region in On-chip RAM for CRC validation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_length::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_length::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_warmramgrp_length`]
module"]
#[doc(alias = "romcodegrp_warmramgrp_length")]
pub type RomcodegrpWarmramgrpLength =
    crate::Reg<romcodegrp_warmramgrp_length::RomcodegrpWarmramgrpLengthSpec>;
#[doc = "Length of region in On-chip RAM for CRC validation."]
pub mod romcodegrp_warmramgrp_length;
#[doc = "romcodegrp_warmramgrp_execution (rw) register accessor: Offset into On-chip RAM to enter to on a warm boot.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_execution::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_execution::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_warmramgrp_execution`]
module"]
#[doc(alias = "romcodegrp_warmramgrp_execution")]
pub type RomcodegrpWarmramgrpExecution =
    crate::Reg<romcodegrp_warmramgrp_execution::RomcodegrpWarmramgrpExecutionSpec>;
#[doc = "Offset into On-chip RAM to enter to on a warm boot."]
pub mod romcodegrp_warmramgrp_execution;
#[doc = "romcodegrp_warmramgrp_crc (rw) register accessor: Length of region in On-chip RAM for CRC validation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_crc::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_crc::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romcodegrp_warmramgrp_crc`]
module"]
#[doc(alias = "romcodegrp_warmramgrp_crc")]
pub type RomcodegrpWarmramgrpCrc =
    crate::Reg<romcodegrp_warmramgrp_crc::RomcodegrpWarmramgrpCrcSpec>;
#[doc = "Length of region in On-chip RAM for CRC validation."]
pub mod romcodegrp_warmramgrp_crc;
#[doc = "romhwgrp_ctrl (rw) register accessor: Controls behavior of Boot ROM hardware. All fields are only reset by a cold reset (ignore warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romhwgrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romhwgrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@romhwgrp_ctrl`]
module"]
#[doc(alias = "romhwgrp_ctrl")]
pub type RomhwgrpCtrl = crate::Reg<romhwgrp_ctrl::RomhwgrpCtrlSpec>;
#[doc = "Controls behavior of Boot ROM hardware. All fields are only reset by a cold reset (ignore warm reset)."]
pub mod romhwgrp_ctrl;
#[doc = "sdmmcgrp_ctrl (rw) register accessor: Registers used by the SDMMC Controller. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdmmcgrp_ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdmmcgrp_ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdmmcgrp_ctrl`]
module"]
#[doc(alias = "sdmmcgrp_ctrl")]
pub type SdmmcgrpCtrl = crate::Reg<sdmmcgrp_ctrl::SdmmcgrpCtrlSpec>;
#[doc = "Registers used by the SDMMC Controller. All fields are reset by a cold or warm reset."]
pub mod sdmmcgrp_ctrl;
#[doc = "sdmmcgrp_l3master (rw) register accessor: Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdmmcgrp_l3master::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdmmcgrp_l3master::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdmmcgrp_l3master`]
module"]
#[doc(alias = "sdmmcgrp_l3master")]
pub type SdmmcgrpL3master = crate::Reg<sdmmcgrp_l3master::SdmmcgrpL3masterSpec>;
#[doc = "Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
pub mod sdmmcgrp_l3master;
#[doc = "nandgrp_bootstrap (rw) register accessor: Bootstrap fields sampled by NAND Flash Controller when released from reset. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`nandgrp_bootstrap::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`nandgrp_bootstrap::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@nandgrp_bootstrap`]
module"]
#[doc(alias = "nandgrp_bootstrap")]
pub type NandgrpBootstrap = crate::Reg<nandgrp_bootstrap::NandgrpBootstrapSpec>;
#[doc = "Bootstrap fields sampled by NAND Flash Controller when released from reset. All fields are reset by a cold or warm reset."]
pub mod nandgrp_bootstrap;
#[doc = "nandgrp_l3master (rw) register accessor: Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`nandgrp_l3master::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`nandgrp_l3master::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@nandgrp_l3master`]
module"]
#[doc(alias = "nandgrp_l3master")]
pub type NandgrpL3master = crate::Reg<nandgrp_l3master::NandgrpL3masterSpec>;
#[doc = "Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
pub mod nandgrp_l3master;
#[doc = "usbgrp_l3master (rw) register accessor: Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`usbgrp_l3master::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`usbgrp_l3master::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@usbgrp_l3master`]
module"]
#[doc(alias = "usbgrp_l3master")]
pub type UsbgrpL3master = crate::Reg<usbgrp_l3master::UsbgrpL3masterSpec>;
#[doc = "Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset."]
pub mod usbgrp_l3master;
#[doc = "eccgrp_l2 (rw) register accessor: This register is used to enable ECC on the L2 Data RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_l2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_l2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_l2`]
module"]
#[doc(alias = "eccgrp_l2")]
pub type EccgrpL2 = crate::Reg<eccgrp_l2::EccgrpL2Spec>;
#[doc = "This register is used to enable ECC on the L2 Data RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_l2;
#[doc = "eccgrp_ocram (rw) register accessor: This register is used to enable ECC on the On-chip RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_ocram::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_ocram::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_ocram`]
module"]
#[doc(alias = "eccgrp_ocram")]
pub type EccgrpOcram = crate::Reg<eccgrp_ocram::EccgrpOcramSpec>;
#[doc = "This register is used to enable ECC on the On-chip RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_ocram;
#[doc = "eccgrp_usb0 (rw) register accessor: This register is used to enable ECC on the USB0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_usb0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_usb0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_usb0`]
module"]
#[doc(alias = "eccgrp_usb0")]
pub type EccgrpUsb0 = crate::Reg<eccgrp_usb0::EccgrpUsb0Spec>;
#[doc = "This register is used to enable ECC on the USB0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_usb0;
#[doc = "eccgrp_usb1 (rw) register accessor: This register is used to enable ECC on the USB1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_usb1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_usb1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_usb1`]
module"]
#[doc(alias = "eccgrp_usb1")]
pub type EccgrpUsb1 = crate::Reg<eccgrp_usb1::EccgrpUsb1Spec>;
#[doc = "This register is used to enable ECC on the USB1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_usb1;
#[doc = "eccgrp_emac0 (rw) register accessor: This register is used to enable ECC on the EMAC0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_emac0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_emac0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_emac0`]
module"]
#[doc(alias = "eccgrp_emac0")]
pub type EccgrpEmac0 = crate::Reg<eccgrp_emac0::EccgrpEmac0Spec>;
#[doc = "This register is used to enable ECC on the EMAC0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_emac0;
#[doc = "eccgrp_emac1 (rw) register accessor: This register is used to enable ECC on the EMAC1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_emac1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_emac1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_emac1`]
module"]
#[doc(alias = "eccgrp_emac1")]
pub type EccgrpEmac1 = crate::Reg<eccgrp_emac1::EccgrpEmac1Spec>;
#[doc = "This register is used to enable ECC on the EMAC1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_emac1;
#[doc = "eccgrp_dma (rw) register accessor: This register is used to enable ECC on the DMA RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_dma::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_dma::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_dma`]
module"]
#[doc(alias = "eccgrp_dma")]
pub type EccgrpDma = crate::Reg<eccgrp_dma::EccgrpDmaSpec>;
#[doc = "This register is used to enable ECC on the DMA RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_dma;
#[doc = "eccgrp_can0 (rw) register accessor: This register is used to enable ECC on the CAN0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_can0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_can0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_can0`]
module"]
#[doc(alias = "eccgrp_can0")]
pub type EccgrpCan0 = crate::Reg<eccgrp_can0::EccgrpCan0Spec>;
#[doc = "This register is used to enable ECC on the CAN0 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_can0;
#[doc = "eccgrp_can1 (rw) register accessor: This register is used to enable ECC on the CAN1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_can1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_can1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_can1`]
module"]
#[doc(alias = "eccgrp_can1")]
pub type EccgrpCan1 = crate::Reg<eccgrp_can1::EccgrpCan1Spec>;
#[doc = "This register is used to enable ECC on the CAN1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_can1;
#[doc = "eccgrp_nand (rw) register accessor: This register is used to enable ECC on the NAND RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_nand::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_nand::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_nand`]
module"]
#[doc(alias = "eccgrp_nand")]
pub type EccgrpNand = crate::Reg<eccgrp_nand::EccgrpNandSpec>;
#[doc = "This register is used to enable ECC on the NAND RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_nand;
#[doc = "eccgrp_qspi (rw) register accessor: This register is used to enable ECC on the QSPI RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_qspi::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_qspi::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_qspi`]
module"]
#[doc(alias = "eccgrp_qspi")]
pub type EccgrpQspi = crate::Reg<eccgrp_qspi::EccgrpQspiSpec>;
#[doc = "This register is used to enable ECC on the QSPI RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_qspi;
#[doc = "eccgrp_sdmmc (rw) register accessor: This register is used to enable ECC on the SDMMC RAM.ECC errors can be injected into the write path using bits in this register. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_sdmmc::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_sdmmc::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccgrp_sdmmc`]
module"]
#[doc(alias = "eccgrp_sdmmc")]
pub type EccgrpSdmmc = crate::Reg<eccgrp_sdmmc::EccgrpSdmmcSpec>;
#[doc = "This register is used to enable ECC on the SDMMC RAM.ECC errors can be injected into the write path using bits in this register. Only reset by a cold reset (ignores warm reset)."]
pub mod eccgrp_sdmmc;
#[doc = "pinmuxgrp_EMACIO0 (rw) register accessor: This register is used to control the peripherals connected to emac0_tx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio0`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO0")]
pub type PinmuxgrpEmacio0 = crate::Reg<pinmuxgrp_emacio0::PinmuxgrpEmacio0Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_tx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio0;
#[doc = "pinmuxgrp_EMACIO1 (rw) register accessor: This register is used to control the peripherals connected to emac0_tx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio1`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO1")]
pub type PinmuxgrpEmacio1 = crate::Reg<pinmuxgrp_emacio1::PinmuxgrpEmacio1Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_tx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio1;
#[doc = "pinmuxgrp_EMACIO2 (rw) register accessor: This register is used to control the peripherals connected to emac0_tx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio2`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO2")]
pub type PinmuxgrpEmacio2 = crate::Reg<pinmuxgrp_emacio2::PinmuxgrpEmacio2Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_tx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio2;
#[doc = "pinmuxgrp_EMACIO3 (rw) register accessor: This register is used to control the peripherals connected to emac0_tx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio3`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO3")]
pub type PinmuxgrpEmacio3 = crate::Reg<pinmuxgrp_emacio3::PinmuxgrpEmacio3Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_tx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio3;
#[doc = "pinmuxgrp_EMACIO4 (rw) register accessor: This register is used to control the peripherals connected to emac0_tx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio4`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO4")]
pub type PinmuxgrpEmacio4 = crate::Reg<pinmuxgrp_emacio4::PinmuxgrpEmacio4Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_tx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio4;
#[doc = "pinmuxgrp_EMACIO5 (rw) register accessor: This register is used to control the peripherals connected to emac0_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio5`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO5")]
pub type PinmuxgrpEmacio5 = crate::Reg<pinmuxgrp_emacio5::PinmuxgrpEmacio5Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio5;
#[doc = "pinmuxgrp_EMACIO6 (rw) register accessor: This register is used to control the peripherals connected to emac0_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio6`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO6")]
pub type PinmuxgrpEmacio6 = crate::Reg<pinmuxgrp_emacio6::PinmuxgrpEmacio6Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio6;
#[doc = "pinmuxgrp_EMACIO7 (rw) register accessor: This register is used to control the peripherals connected to emac0_mdc Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio7`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO7")]
pub type PinmuxgrpEmacio7 = crate::Reg<pinmuxgrp_emacio7::PinmuxgrpEmacio7Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_mdc Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio7;
#[doc = "pinmuxgrp_EMACIO8 (rw) register accessor: This register is used to control the peripherals connected to emac0_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio8`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO8")]
pub type PinmuxgrpEmacio8 = crate::Reg<pinmuxgrp_emacio8::PinmuxgrpEmacio8Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio8;
#[doc = "pinmuxgrp_EMACIO9 (rw) register accessor: This register is used to control the peripherals connected to emac0_tx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio9`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO9")]
pub type PinmuxgrpEmacio9 = crate::Reg<pinmuxgrp_emacio9::PinmuxgrpEmacio9Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_tx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio9;
#[doc = "pinmuxgrp_EMACIO10 (rw) register accessor: This register is used to control the peripherals connected to emac0_rx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio10`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO10")]
pub type PinmuxgrpEmacio10 = crate::Reg<pinmuxgrp_emacio10::PinmuxgrpEmacio10Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_rx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio10;
#[doc = "pinmuxgrp_EMACIO11 (rw) register accessor: This register is used to control the peripherals connected to emac0_rx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio11`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO11")]
pub type PinmuxgrpEmacio11 = crate::Reg<pinmuxgrp_emacio11::PinmuxgrpEmacio11Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_rx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio11;
#[doc = "pinmuxgrp_EMACIO12 (rw) register accessor: This register is used to control the peripherals connected to emac0_rx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio12`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO12")]
pub type PinmuxgrpEmacio12 = crate::Reg<pinmuxgrp_emacio12::PinmuxgrpEmacio12Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_rx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio12;
#[doc = "pinmuxgrp_EMACIO13 (rw) register accessor: This register is used to control the peripherals connected to emac0_rx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio13`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO13")]
pub type PinmuxgrpEmacio13 = crate::Reg<pinmuxgrp_emacio13::PinmuxgrpEmacio13Spec>;
#[doc = "This register is used to control the peripherals connected to emac0_rx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio13;
#[doc = "pinmuxgrp_EMACIO14 (rw) register accessor: This register is used to control the peripherals connected to emac1_tx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio14`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO14")]
pub type PinmuxgrpEmacio14 = crate::Reg<pinmuxgrp_emacio14::PinmuxgrpEmacio14Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_tx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio14;
#[doc = "pinmuxgrp_EMACIO15 (rw) register accessor: This register is used to control the peripherals connected to emac1_tx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio15`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO15")]
pub type PinmuxgrpEmacio15 = crate::Reg<pinmuxgrp_emacio15::PinmuxgrpEmacio15Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_tx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio15;
#[doc = "pinmuxgrp_EMACIO16 (rw) register accessor: This register is used to control the peripherals connected to emac1_tx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio16::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio16::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio16`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO16")]
pub type PinmuxgrpEmacio16 = crate::Reg<pinmuxgrp_emacio16::PinmuxgrpEmacio16Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_tx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio16;
#[doc = "pinmuxgrp_EMACIO17 (rw) register accessor: This register is used to control the peripherals connected to emac1_tx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio17::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio17::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio17`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO17")]
pub type PinmuxgrpEmacio17 = crate::Reg<pinmuxgrp_emacio17::PinmuxgrpEmacio17Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_tx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio17;
#[doc = "pinmuxgrp_EMACIO18 (rw) register accessor: This register is used to control the peripherals connected to emac1_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio18::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio18::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio18`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO18")]
pub type PinmuxgrpEmacio18 = crate::Reg<pinmuxgrp_emacio18::PinmuxgrpEmacio18Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio18;
#[doc = "pinmuxgrp_EMACIO19 (rw) register accessor: This register is used to control the peripherals connected to emac1_rx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio19::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio19::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_emacio19`]
module"]
#[doc(alias = "pinmuxgrp_EMACIO19")]
pub type PinmuxgrpEmacio19 = crate::Reg<pinmuxgrp_emacio19::PinmuxgrpEmacio19Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_rx_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_emacio19;
#[doc = "pinmuxgrp_FLASHIO0 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_cmd Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio0`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO0")]
pub type PinmuxgrpFlashio0 = crate::Reg<pinmuxgrp_flashio0::PinmuxgrpFlashio0Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_cmd Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio0;
#[doc = "pinmuxgrp_FLASHIO1 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_pwren Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio1`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO1")]
pub type PinmuxgrpFlashio1 = crate::Reg<pinmuxgrp_flashio1::PinmuxgrpFlashio1Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_pwren Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio1;
#[doc = "pinmuxgrp_FLASHIO2 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio2`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO2")]
pub type PinmuxgrpFlashio2 = crate::Reg<pinmuxgrp_flashio2::PinmuxgrpFlashio2Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio2;
#[doc = "pinmuxgrp_FLASHIO3 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio3`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO3")]
pub type PinmuxgrpFlashio3 = crate::Reg<pinmuxgrp_flashio3::PinmuxgrpFlashio3Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio3;
#[doc = "pinmuxgrp_FLASHIO4 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio4`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO4")]
pub type PinmuxgrpFlashio4 = crate::Reg<pinmuxgrp_flashio4::PinmuxgrpFlashio4Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio4;
#[doc = "pinmuxgrp_FLASHIO5 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio5`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO5")]
pub type PinmuxgrpFlashio5 = crate::Reg<pinmuxgrp_flashio5::PinmuxgrpFlashio5Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio5;
#[doc = "pinmuxgrp_FLASHIO6 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio6`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO6")]
pub type PinmuxgrpFlashio6 = crate::Reg<pinmuxgrp_flashio6::PinmuxgrpFlashio6Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio6;
#[doc = "pinmuxgrp_FLASHIO7 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio7`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO7")]
pub type PinmuxgrpFlashio7 = crate::Reg<pinmuxgrp_flashio7::PinmuxgrpFlashio7Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio7;
#[doc = "pinmuxgrp_FLASHIO8 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_clk_in Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio8`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO8")]
pub type PinmuxgrpFlashio8 = crate::Reg<pinmuxgrp_flashio8::PinmuxgrpFlashio8Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_clk_in Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio8;
#[doc = "pinmuxgrp_FLASHIO9 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio9`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO9")]
pub type PinmuxgrpFlashio9 = crate::Reg<pinmuxgrp_flashio9::PinmuxgrpFlashio9Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio9;
#[doc = "pinmuxgrp_FLASHIO10 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio10`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO10")]
pub type PinmuxgrpFlashio10 = crate::Reg<pinmuxgrp_flashio10::PinmuxgrpFlashio10Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio10;
#[doc = "pinmuxgrp_FLASHIO11 (rw) register accessor: This register is used to control the peripherals connected to sdmmc_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_flashio11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_flashio11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_flashio11`]
module"]
#[doc(alias = "pinmuxgrp_FLASHIO11")]
pub type PinmuxgrpFlashio11 = crate::Reg<pinmuxgrp_flashio11::PinmuxgrpFlashio11Spec>;
#[doc = "This register is used to control the peripherals connected to sdmmc_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_flashio11;
#[doc = "pinmuxgrp_GENERALIO0 (rw) register accessor: This register is used to control the peripherals connected to trace_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio0`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO0")]
pub type PinmuxgrpGeneralio0 = crate::Reg<pinmuxgrp_generalio0::PinmuxgrpGeneralio0Spec>;
#[doc = "This register is used to control the peripherals connected to trace_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio0;
#[doc = "pinmuxgrp_GENERALIO1 (rw) register accessor: This register is used to control the peripherals connected to trace_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio1`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO1")]
pub type PinmuxgrpGeneralio1 = crate::Reg<pinmuxgrp_generalio1::PinmuxgrpGeneralio1Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio1;
#[doc = "pinmuxgrp_GENERALIO2 (rw) register accessor: This register is used to control the peripherals connected to trace_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio2`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO2")]
pub type PinmuxgrpGeneralio2 = crate::Reg<pinmuxgrp_generalio2::PinmuxgrpGeneralio2Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio2;
#[doc = "pinmuxgrp_GENERALIO3 (rw) register accessor: This register is used to control the peripherals connected to trace_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio3`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO3")]
pub type PinmuxgrpGeneralio3 = crate::Reg<pinmuxgrp_generalio3::PinmuxgrpGeneralio3Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio3;
#[doc = "pinmuxgrp_GENERALIO4 (rw) register accessor: This register is used to control the peripherals connected to trace_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio4`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO4")]
pub type PinmuxgrpGeneralio4 = crate::Reg<pinmuxgrp_generalio4::PinmuxgrpGeneralio4Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio4;
#[doc = "pinmuxgrp_GENERALIO5 (rw) register accessor: This register is used to control the peripherals connected to trace_d4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio5`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO5")]
pub type PinmuxgrpGeneralio5 = crate::Reg<pinmuxgrp_generalio5::PinmuxgrpGeneralio5Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio5;
#[doc = "pinmuxgrp_GENERALIO6 (rw) register accessor: This register is used to control the peripherals connected to trace_d5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio6`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO6")]
pub type PinmuxgrpGeneralio6 = crate::Reg<pinmuxgrp_generalio6::PinmuxgrpGeneralio6Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio6;
#[doc = "pinmuxgrp_GENERALIO7 (rw) register accessor: This register is used to control the peripherals connected to trace_d6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio7`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO7")]
pub type PinmuxgrpGeneralio7 = crate::Reg<pinmuxgrp_generalio7::PinmuxgrpGeneralio7Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio7;
#[doc = "pinmuxgrp_GENERALIO8 (rw) register accessor: This register is used to control the peripherals connected to trace_d7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio8`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO8")]
pub type PinmuxgrpGeneralio8 = crate::Reg<pinmuxgrp_generalio8::PinmuxgrpGeneralio8Spec>;
#[doc = "This register is used to control the peripherals connected to trace_d7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio8;
#[doc = "pinmuxgrp_GENERALIO9 (rw) register accessor: This register is used to control the peripherals connected to spim0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio9`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO9")]
pub type PinmuxgrpGeneralio9 = crate::Reg<pinmuxgrp_generalio9::PinmuxgrpGeneralio9Spec>;
#[doc = "This register is used to control the peripherals connected to spim0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio9;
#[doc = "pinmuxgrp_GENERALIO10 (rw) register accessor: This register is used to control the peripherals connected to spim0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio10`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO10")]
pub type PinmuxgrpGeneralio10 = crate::Reg<pinmuxgrp_generalio10::PinmuxgrpGeneralio10Spec>;
#[doc = "This register is used to control the peripherals connected to spim0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio10;
#[doc = "pinmuxgrp_GENERALIO11 (rw) register accessor: This register is used to control the peripherals connected to spim0_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio11`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO11")]
pub type PinmuxgrpGeneralio11 = crate::Reg<pinmuxgrp_generalio11::PinmuxgrpGeneralio11Spec>;
#[doc = "This register is used to control the peripherals connected to spim0_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio11;
#[doc = "pinmuxgrp_GENERALIO12 (rw) register accessor: This register is used to control the peripherals connected to spim0_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio12`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO12")]
pub type PinmuxgrpGeneralio12 = crate::Reg<pinmuxgrp_generalio12::PinmuxgrpGeneralio12Spec>;
#[doc = "This register is used to control the peripherals connected to spim0_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio12;
#[doc = "pinmuxgrp_GENERALIO13 (rw) register accessor: This register is used to control the peripherals connected to uart0_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio13`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO13")]
pub type PinmuxgrpGeneralio13 = crate::Reg<pinmuxgrp_generalio13::PinmuxgrpGeneralio13Spec>;
#[doc = "This register is used to control the peripherals connected to uart0_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio13;
#[doc = "pinmuxgrp_GENERALIO14 (rw) register accessor: This register is used to control the peripherals connected to uart0_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio14`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO14")]
pub type PinmuxgrpGeneralio14 = crate::Reg<pinmuxgrp_generalio14::PinmuxgrpGeneralio14Spec>;
#[doc = "This register is used to control the peripherals connected to uart0_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio14;
#[doc = "pinmuxgrp_GENERALIO15 (rw) register accessor: This register is used to control the peripherals connected to i2c0_sda Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio15`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO15")]
pub type PinmuxgrpGeneralio15 = crate::Reg<pinmuxgrp_generalio15::PinmuxgrpGeneralio15Spec>;
#[doc = "This register is used to control the peripherals connected to i2c0_sda Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio15;
#[doc = "pinmuxgrp_GENERALIO16 (rw) register accessor: This register is used to control the peripherals connected to i2c0_scl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio16::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio16::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio16`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO16")]
pub type PinmuxgrpGeneralio16 = crate::Reg<pinmuxgrp_generalio16::PinmuxgrpGeneralio16Spec>;
#[doc = "This register is used to control the peripherals connected to i2c0_scl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio16;
#[doc = "pinmuxgrp_GENERALIO17 (rw) register accessor: This register is used to control the peripherals connected to can0_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio17::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio17::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio17`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO17")]
pub type PinmuxgrpGeneralio17 = crate::Reg<pinmuxgrp_generalio17::PinmuxgrpGeneralio17Spec>;
#[doc = "This register is used to control the peripherals connected to can0_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio17;
#[doc = "pinmuxgrp_GENERALIO18 (rw) register accessor: This register is used to control the peripherals connected to can0_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio18::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio18::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio18`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO18")]
pub type PinmuxgrpGeneralio18 = crate::Reg<pinmuxgrp_generalio18::PinmuxgrpGeneralio18Spec>;
#[doc = "This register is used to control the peripherals connected to can0_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio18;
#[doc = "pinmuxgrp_GENERALIO19 (rw) register accessor: This register is used to control the peripherals connected to spis1_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio19::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio19::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio19`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO19")]
pub type PinmuxgrpGeneralio19 = crate::Reg<pinmuxgrp_generalio19::PinmuxgrpGeneralio19Spec>;
#[doc = "This register is used to control the peripherals connected to spis1_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio19;
#[doc = "pinmuxgrp_GENERALIO20 (rw) register accessor: This register is used to control the peripherals connected to spis1_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio20::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio20::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio20`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO20")]
pub type PinmuxgrpGeneralio20 = crate::Reg<pinmuxgrp_generalio20::PinmuxgrpGeneralio20Spec>;
#[doc = "This register is used to control the peripherals connected to spis1_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio20;
#[doc = "pinmuxgrp_GENERALIO21 (rw) register accessor: This register is used to control the peripherals connected to spis1_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio21::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio21::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio21`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO21")]
pub type PinmuxgrpGeneralio21 = crate::Reg<pinmuxgrp_generalio21::PinmuxgrpGeneralio21Spec>;
#[doc = "This register is used to control the peripherals connected to spis1_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio21;
#[doc = "pinmuxgrp_GENERALIO22 (rw) register accessor: This register is used to control the peripherals connected to spis1_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio22::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio22::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio22`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO22")]
pub type PinmuxgrpGeneralio22 = crate::Reg<pinmuxgrp_generalio22::PinmuxgrpGeneralio22Spec>;
#[doc = "This register is used to control the peripherals connected to spis1_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio22;
#[doc = "pinmuxgrp_GENERALIO23 (rw) register accessor: This register is used to control the peripherals connected to uart1_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio23::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio23::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio23`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO23")]
pub type PinmuxgrpGeneralio23 = crate::Reg<pinmuxgrp_generalio23::PinmuxgrpGeneralio23Spec>;
#[doc = "This register is used to control the peripherals connected to uart1_rx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio23;
#[doc = "pinmuxgrp_GENERALIO24 (rw) register accessor: This register is used to control the peripherals connected to uart1_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio24::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio24::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio24`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO24")]
pub type PinmuxgrpGeneralio24 = crate::Reg<pinmuxgrp_generalio24::PinmuxgrpGeneralio24Spec>;
#[doc = "This register is used to control the peripherals connected to uart1_tx Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio24;
#[doc = "pinmuxgrp_GENERALIO25 (rw) register accessor: This register is used to control the peripherals connected to i2c1_sda Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio25::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio25::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio25`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO25")]
pub type PinmuxgrpGeneralio25 = crate::Reg<pinmuxgrp_generalio25::PinmuxgrpGeneralio25Spec>;
#[doc = "This register is used to control the peripherals connected to i2c1_sda Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio25;
#[doc = "pinmuxgrp_GENERALIO26 (rw) register accessor: This register is used to control the peripherals connected to i2c1_scl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio26::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio26::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio26`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO26")]
pub type PinmuxgrpGeneralio26 = crate::Reg<pinmuxgrp_generalio26::PinmuxgrpGeneralio26Spec>;
#[doc = "This register is used to control the peripherals connected to i2c1_scl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio26;
#[doc = "pinmuxgrp_GENERALIO27 (rw) register accessor: This register is used to control the peripherals connected to spim0_ss0_alt Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio27::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio27::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio27`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO27")]
pub type PinmuxgrpGeneralio27 = crate::Reg<pinmuxgrp_generalio27::PinmuxgrpGeneralio27Spec>;
#[doc = "This register is used to control the peripherals connected to spim0_ss0_alt Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio27;
#[doc = "pinmuxgrp_GENERALIO28 (rw) register accessor: This register is used to control the peripherals connected to spis0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio28::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio28::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio28`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO28")]
pub type PinmuxgrpGeneralio28 = crate::Reg<pinmuxgrp_generalio28::PinmuxgrpGeneralio28Spec>;
#[doc = "This register is used to control the peripherals connected to spis0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio28;
#[doc = "pinmuxgrp_GENERALIO29 (rw) register accessor: This register is used to control the peripherals connected to spis0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio29::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio29::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio29`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO29")]
pub type PinmuxgrpGeneralio29 = crate::Reg<pinmuxgrp_generalio29::PinmuxgrpGeneralio29Spec>;
#[doc = "This register is used to control the peripherals connected to spis0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio29;
#[doc = "pinmuxgrp_GENERALIO30 (rw) register accessor: This register is used to control the peripherals connected to spis0_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio30::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio30::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio30`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO30")]
pub type PinmuxgrpGeneralio30 = crate::Reg<pinmuxgrp_generalio30::PinmuxgrpGeneralio30Spec>;
#[doc = "This register is used to control the peripherals connected to spis0_miso Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio30;
#[doc = "pinmuxgrp_GENERALIO31 (rw) register accessor: This register is used to control the peripherals connected to spis0_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio31::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio31::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_generalio31`]
module"]
#[doc(alias = "pinmuxgrp_GENERALIO31")]
pub type PinmuxgrpGeneralio31 = crate::Reg<pinmuxgrp_generalio31::PinmuxgrpGeneralio31Spec>;
#[doc = "This register is used to control the peripherals connected to spis0_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_generalio31;
#[doc = "pinmuxgrp_MIXED1IO0 (rw) register accessor: This register is used to control the peripherals connected to nand_ale Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io0`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO0")]
pub type PinmuxgrpMixed1io0 = crate::Reg<pinmuxgrp_mixed1io0::PinmuxgrpMixed1io0Spec>;
#[doc = "This register is used to control the peripherals connected to nand_ale Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io0;
#[doc = "pinmuxgrp_MIXED1IO1 (rw) register accessor: This register is used to control the peripherals connected to nand_ce Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io1`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO1")]
pub type PinmuxgrpMixed1io1 = crate::Reg<pinmuxgrp_mixed1io1::PinmuxgrpMixed1io1Spec>;
#[doc = "This register is used to control the peripherals connected to nand_ce Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io1;
#[doc = "pinmuxgrp_MIXED1IO2 (rw) register accessor: This register is used to control the peripherals connected to nand_cle Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io2`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO2")]
pub type PinmuxgrpMixed1io2 = crate::Reg<pinmuxgrp_mixed1io2::PinmuxgrpMixed1io2Spec>;
#[doc = "This register is used to control the peripherals connected to nand_cle Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io2;
#[doc = "pinmuxgrp_MIXED1IO3 (rw) register accessor: This register is used to control the peripherals connected to nand_re Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io3`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO3")]
pub type PinmuxgrpMixed1io3 = crate::Reg<pinmuxgrp_mixed1io3::PinmuxgrpMixed1io3Spec>;
#[doc = "This register is used to control the peripherals connected to nand_re Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io3;
#[doc = "pinmuxgrp_MIXED1IO4 (rw) register accessor: This register is used to control the peripherals connected to nand_rb Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io4`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO4")]
pub type PinmuxgrpMixed1io4 = crate::Reg<pinmuxgrp_mixed1io4::PinmuxgrpMixed1io4Spec>;
#[doc = "This register is used to control the peripherals connected to nand_rb Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io4;
#[doc = "pinmuxgrp_MIXED1IO5 (rw) register accessor: This register is used to control the peripherals connected to nand_dq0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io5`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO5")]
pub type PinmuxgrpMixed1io5 = crate::Reg<pinmuxgrp_mixed1io5::PinmuxgrpMixed1io5Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io5;
#[doc = "pinmuxgrp_MIXED1IO6 (rw) register accessor: This register is used to control the peripherals connected to nand_dq1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io6`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO6")]
pub type PinmuxgrpMixed1io6 = crate::Reg<pinmuxgrp_mixed1io6::PinmuxgrpMixed1io6Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io6;
#[doc = "pinmuxgrp_MIXED1IO7 (rw) register accessor: This register is used to control the peripherals connected to nand_dq2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io7`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO7")]
pub type PinmuxgrpMixed1io7 = crate::Reg<pinmuxgrp_mixed1io7::PinmuxgrpMixed1io7Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io7;
#[doc = "pinmuxgrp_MIXED1IO8 (rw) register accessor: This register is used to control the peripherals connected to nand_dq3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io8`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO8")]
pub type PinmuxgrpMixed1io8 = crate::Reg<pinmuxgrp_mixed1io8::PinmuxgrpMixed1io8Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io8;
#[doc = "pinmuxgrp_MIXED1IO9 (rw) register accessor: This register is used to control the peripherals connected to nand_dq4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io9`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO9")]
pub type PinmuxgrpMixed1io9 = crate::Reg<pinmuxgrp_mixed1io9::PinmuxgrpMixed1io9Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq4 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io9;
#[doc = "pinmuxgrp_MIXED1IO10 (rw) register accessor: This register is used to control the peripherals connected to nand_dq5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io10`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO10")]
pub type PinmuxgrpMixed1io10 = crate::Reg<pinmuxgrp_mixed1io10::PinmuxgrpMixed1io10Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq5 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io10;
#[doc = "pinmuxgrp_MIXED1IO11 (rw) register accessor: This register is used to control the peripherals connected to nand_dq6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io11`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO11")]
pub type PinmuxgrpMixed1io11 = crate::Reg<pinmuxgrp_mixed1io11::PinmuxgrpMixed1io11Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io11;
#[doc = "pinmuxgrp_MIXED1IO12 (rw) register accessor: This register is used to control the peripherals connected to nand_dq7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io12`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO12")]
pub type PinmuxgrpMixed1io12 = crate::Reg<pinmuxgrp_mixed1io12::PinmuxgrpMixed1io12Spec>;
#[doc = "This register is used to control the peripherals connected to nand_dq7 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io12;
#[doc = "pinmuxgrp_MIXED1IO13 (rw) register accessor: This register is used to control the peripherals connected to nand_wp Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io13`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO13")]
pub type PinmuxgrpMixed1io13 = crate::Reg<pinmuxgrp_mixed1io13::PinmuxgrpMixed1io13Spec>;
#[doc = "This register is used to control the peripherals connected to nand_wp Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io13;
#[doc = "pinmuxgrp_MIXED1IO14 (rw) register accessor: This register is used to control the peripherals connected to nand_we Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io14`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO14")]
pub type PinmuxgrpMixed1io14 = crate::Reg<pinmuxgrp_mixed1io14::PinmuxgrpMixed1io14Spec>;
#[doc = "This register is used to control the peripherals connected to nand_we Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io14;
#[doc = "pinmuxgrp_MIXED1IO15 (rw) register accessor: This register is used to control the peripherals connected to qspi_io0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io15`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO15")]
pub type PinmuxgrpMixed1io15 = crate::Reg<pinmuxgrp_mixed1io15::PinmuxgrpMixed1io15Spec>;
#[doc = "This register is used to control the peripherals connected to qspi_io0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io15;
#[doc = "pinmuxgrp_MIXED1IO16 (rw) register accessor: This register is used to control the peripherals connected to qspi_io1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io16::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io16::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io16`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO16")]
pub type PinmuxgrpMixed1io16 = crate::Reg<pinmuxgrp_mixed1io16::PinmuxgrpMixed1io16Spec>;
#[doc = "This register is used to control the peripherals connected to qspi_io1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io16;
#[doc = "pinmuxgrp_MIXED1IO17 (rw) register accessor: This register is used to control the peripherals connected to qspi_io2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io17::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io17::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io17`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO17")]
pub type PinmuxgrpMixed1io17 = crate::Reg<pinmuxgrp_mixed1io17::PinmuxgrpMixed1io17Spec>;
#[doc = "This register is used to control the peripherals connected to qspi_io2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io17;
#[doc = "pinmuxgrp_MIXED1IO18 (rw) register accessor: This register is used to control the peripherals connected to qspi_io3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io18::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io18::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io18`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO18")]
pub type PinmuxgrpMixed1io18 = crate::Reg<pinmuxgrp_mixed1io18::PinmuxgrpMixed1io18Spec>;
#[doc = "This register is used to control the peripherals connected to qspi_io3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io18;
#[doc = "pinmuxgrp_MIXED1IO19 (rw) register accessor: This register is used to control the peripherals connected to qspi_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io19::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io19::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io19`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO19")]
pub type PinmuxgrpMixed1io19 = crate::Reg<pinmuxgrp_mixed1io19::PinmuxgrpMixed1io19Spec>;
#[doc = "This register is used to control the peripherals connected to qspi_ss0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io19;
#[doc = "pinmuxgrp_MIXED1IO20 (rw) register accessor: This register is used to control the peripherals connected to qpsi_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io20::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io20::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io20`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO20")]
pub type PinmuxgrpMixed1io20 = crate::Reg<pinmuxgrp_mixed1io20::PinmuxgrpMixed1io20Spec>;
#[doc = "This register is used to control the peripherals connected to qpsi_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io20;
#[doc = "pinmuxgrp_MIXED1IO21 (rw) register accessor: This register is used to control the peripherals connected to qspi_ss1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io21::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io21::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed1io21`]
module"]
#[doc(alias = "pinmuxgrp_MIXED1IO21")]
pub type PinmuxgrpMixed1io21 = crate::Reg<pinmuxgrp_mixed1io21::PinmuxgrpMixed1io21Spec>;
#[doc = "This register is used to control the peripherals connected to qspi_ss1 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed1io21;
#[doc = "pinmuxgrp_MIXED2IO0 (rw) register accessor: This register is used to control the peripherals connected to emac1_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io0`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO0")]
pub type PinmuxgrpMixed2io0 = crate::Reg<pinmuxgrp_mixed2io0::PinmuxgrpMixed2io0Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io0;
#[doc = "pinmuxgrp_MIXED2IO1 (rw) register accessor: This register is used to control the peripherals connected to emac1_mdc Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io1`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO1")]
pub type PinmuxgrpMixed2io1 = crate::Reg<pinmuxgrp_mixed2io1::PinmuxgrpMixed2io1Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_mdc Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io1;
#[doc = "pinmuxgrp_MIXED2IO2 (rw) register accessor: This register is used to control the peripherals connected to emac1_tx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io2`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO2")]
pub type PinmuxgrpMixed2io2 = crate::Reg<pinmuxgrp_mixed2io2::PinmuxgrpMixed2io2Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_tx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io2;
#[doc = "pinmuxgrp_MIXED2IO3 (rw) register accessor: This register is used to control the peripherals connected to emac1_tx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io3`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO3")]
pub type PinmuxgrpMixed2io3 = crate::Reg<pinmuxgrp_mixed2io3::PinmuxgrpMixed2io3Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_tx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io3;
#[doc = "pinmuxgrp_MIXED2IO4 (rw) register accessor: This register is used to control the peripherals connected to emac1_rx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io4`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO4")]
pub type PinmuxgrpMixed2io4 = crate::Reg<pinmuxgrp_mixed2io4::PinmuxgrpMixed2io4Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_rx_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io4;
#[doc = "pinmuxgrp_MIXED2IO5 (rw) register accessor: This register is used to control the peripherals connected to emac1_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io5`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO5")]
pub type PinmuxgrpMixed2io5 = crate::Reg<pinmuxgrp_mixed2io5::PinmuxgrpMixed2io5Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io5;
#[doc = "pinmuxgrp_MIXED2IO6 (rw) register accessor: This register is used to control the peripherals connected to emac1_rx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io6`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO6")]
pub type PinmuxgrpMixed2io6 = crate::Reg<pinmuxgrp_mixed2io6::PinmuxgrpMixed2io6Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_rx_d2 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io6;
#[doc = "pinmuxgrp_MIXED2IO7 (rw) register accessor: This register is used to control the peripherals connected to emac1_rx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_mixed2io7`]
module"]
#[doc(alias = "pinmuxgrp_MIXED2IO7")]
pub type PinmuxgrpMixed2io7 = crate::Reg<pinmuxgrp_mixed2io7::PinmuxgrpMixed2io7Spec>;
#[doc = "This register is used to control the peripherals connected to emac1_rx_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_mixed2io7;
#[doc = "pinmuxgrp_GPLINMUX48 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 48. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux48::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux48::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux48`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX48")]
pub type PinmuxgrpGplinmux48 = crate::Reg<pinmuxgrp_gplinmux48::PinmuxgrpGplinmux48Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 48. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux48;
#[doc = "pinmuxgrp_GPLINMUX49 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 49. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux49::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux49::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux49`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX49")]
pub type PinmuxgrpGplinmux49 = crate::Reg<pinmuxgrp_gplinmux49::PinmuxgrpGplinmux49Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 49. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux49;
#[doc = "pinmuxgrp_GPLINMUX50 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 50. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux50::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux50::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux50`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX50")]
pub type PinmuxgrpGplinmux50 = crate::Reg<pinmuxgrp_gplinmux50::PinmuxgrpGplinmux50Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 50. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux50;
#[doc = "pinmuxgrp_GPLINMUX51 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 51. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux51::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux51::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux51`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX51")]
pub type PinmuxgrpGplinmux51 = crate::Reg<pinmuxgrp_gplinmux51::PinmuxgrpGplinmux51Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 51. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux51;
#[doc = "pinmuxgrp_GPLINMUX52 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 52. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux52::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux52::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux52`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX52")]
pub type PinmuxgrpGplinmux52 = crate::Reg<pinmuxgrp_gplinmux52::PinmuxgrpGplinmux52Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 52. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux52;
#[doc = "pinmuxgrp_GPLINMUX53 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 53. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux53::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux53::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux53`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX53")]
pub type PinmuxgrpGplinmux53 = crate::Reg<pinmuxgrp_gplinmux53::PinmuxgrpGplinmux53Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 53. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux53;
#[doc = "pinmuxgrp_GPLINMUX54 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 54. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux54::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux54::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux54`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX54")]
pub type PinmuxgrpGplinmux54 = crate::Reg<pinmuxgrp_gplinmux54::PinmuxgrpGplinmux54Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 54. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux54;
#[doc = "pinmuxgrp_GPLINMUX55 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 55. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux55::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux55::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux55`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX55")]
pub type PinmuxgrpGplinmux55 = crate::Reg<pinmuxgrp_gplinmux55::PinmuxgrpGplinmux55Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 55. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux55;
#[doc = "pinmuxgrp_GPLINMUX56 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 56. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux56::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux56::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux56`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX56")]
pub type PinmuxgrpGplinmux56 = crate::Reg<pinmuxgrp_gplinmux56::PinmuxgrpGplinmux56Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 56. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux56;
#[doc = "pinmuxgrp_GPLINMUX57 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 57. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux57::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux57::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux57`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX57")]
pub type PinmuxgrpGplinmux57 = crate::Reg<pinmuxgrp_gplinmux57::PinmuxgrpGplinmux57Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 57. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux57;
#[doc = "pinmuxgrp_GPLINMUX58 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 58. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux58::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux58::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux58`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX58")]
pub type PinmuxgrpGplinmux58 = crate::Reg<pinmuxgrp_gplinmux58::PinmuxgrpGplinmux58Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 58. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux58;
#[doc = "pinmuxgrp_GPLINMUX59 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 59. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux59::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux59::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux59`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX59")]
pub type PinmuxgrpGplinmux59 = crate::Reg<pinmuxgrp_gplinmux59::PinmuxgrpGplinmux59Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 59. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux59;
#[doc = "pinmuxgrp_GPLINMUX60 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 60. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux60::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux60::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux60`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX60")]
pub type PinmuxgrpGplinmux60 = crate::Reg<pinmuxgrp_gplinmux60::PinmuxgrpGplinmux60Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 60. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux60;
#[doc = "pinmuxgrp_GPLINMUX61 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 61. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux61::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux61::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux61`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX61")]
pub type PinmuxgrpGplinmux61 = crate::Reg<pinmuxgrp_gplinmux61::PinmuxgrpGplinmux61Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 61. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux61;
#[doc = "pinmuxgrp_GPLINMUX62 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 62. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux62::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux62::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux62`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX62")]
pub type PinmuxgrpGplinmux62 = crate::Reg<pinmuxgrp_gplinmux62::PinmuxgrpGplinmux62Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 62. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux62;
#[doc = "pinmuxgrp_GPLINMUX63 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 63. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux63::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux63::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux63`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX63")]
pub type PinmuxgrpGplinmux63 = crate::Reg<pinmuxgrp_gplinmux63::PinmuxgrpGplinmux63Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 63. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux63;
#[doc = "pinmuxgrp_GPLINMUX64 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 64. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux64::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux64::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux64`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX64")]
pub type PinmuxgrpGplinmux64 = crate::Reg<pinmuxgrp_gplinmux64::PinmuxgrpGplinmux64Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 64. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux64;
#[doc = "pinmuxgrp_GPLINMUX65 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 65. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux65::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux65::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux65`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX65")]
pub type PinmuxgrpGplinmux65 = crate::Reg<pinmuxgrp_gplinmux65::PinmuxgrpGplinmux65Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 65. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux65;
#[doc = "pinmuxgrp_GPLINMUX66 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 66. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux66::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux66::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux66`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX66")]
pub type PinmuxgrpGplinmux66 = crate::Reg<pinmuxgrp_gplinmux66::PinmuxgrpGplinmux66Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 66. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux66;
#[doc = "pinmuxgrp_GPLINMUX67 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 67. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux67::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux67::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux67`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX67")]
pub type PinmuxgrpGplinmux67 = crate::Reg<pinmuxgrp_gplinmux67::PinmuxgrpGplinmux67Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 67. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux67;
#[doc = "pinmuxgrp_GPLINMUX68 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 68. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux68::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux68::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux68`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX68")]
pub type PinmuxgrpGplinmux68 = crate::Reg<pinmuxgrp_gplinmux68::PinmuxgrpGplinmux68Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 68. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux68;
#[doc = "pinmuxgrp_GPLINMUX69 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 69. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux69::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux69::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux69`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX69")]
pub type PinmuxgrpGplinmux69 = crate::Reg<pinmuxgrp_gplinmux69::PinmuxgrpGplinmux69Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 69. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux69;
#[doc = "pinmuxgrp_GPLINMUX70 (rw) register accessor: Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 70. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux70::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux70::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplinmux70`]
module"]
#[doc(alias = "pinmuxgrp_GPLINMUX70")]
pub type PinmuxgrpGplinmux70 = crate::Reg<pinmuxgrp_gplinmux70::PinmuxgrpGplinmux70Spec>;
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 70. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplinmux70;
#[doc = "pinmuxgrp_GPLMUX0 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO0 and LoanIO0. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux0`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX0")]
pub type PinmuxgrpGplmux0 = crate::Reg<pinmuxgrp_gplmux0::PinmuxgrpGplmux0Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO0 and LoanIO0. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux0;
#[doc = "pinmuxgrp_GPLMUX1 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO1 and LoanIO1. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux1`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX1")]
pub type PinmuxgrpGplmux1 = crate::Reg<pinmuxgrp_gplmux1::PinmuxgrpGplmux1Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO1 and LoanIO1. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux1;
#[doc = "pinmuxgrp_GPLMUX2 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO2 and LoanIO2. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux2`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX2")]
pub type PinmuxgrpGplmux2 = crate::Reg<pinmuxgrp_gplmux2::PinmuxgrpGplmux2Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO2 and LoanIO2. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux2;
#[doc = "pinmuxgrp_GPLMUX3 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO3 and LoanIO3. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux3`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX3")]
pub type PinmuxgrpGplmux3 = crate::Reg<pinmuxgrp_gplmux3::PinmuxgrpGplmux3Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO3 and LoanIO3. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux3;
#[doc = "pinmuxgrp_GPLMUX4 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO4 and LoanIO4. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux4`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX4")]
pub type PinmuxgrpGplmux4 = crate::Reg<pinmuxgrp_gplmux4::PinmuxgrpGplmux4Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO4 and LoanIO4. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux4;
#[doc = "pinmuxgrp_GPLMUX5 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO5 and LoanIO5. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux5`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX5")]
pub type PinmuxgrpGplmux5 = crate::Reg<pinmuxgrp_gplmux5::PinmuxgrpGplmux5Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO5 and LoanIO5. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux5;
#[doc = "pinmuxgrp_GPLMUX6 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO6 and LoanIO6. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux6`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX6")]
pub type PinmuxgrpGplmux6 = crate::Reg<pinmuxgrp_gplmux6::PinmuxgrpGplmux6Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO6 and LoanIO6. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux6;
#[doc = "pinmuxgrp_GPLMUX7 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO7 and LoanIO7. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux7`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX7")]
pub type PinmuxgrpGplmux7 = crate::Reg<pinmuxgrp_gplmux7::PinmuxgrpGplmux7Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO7 and LoanIO7. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux7;
#[doc = "pinmuxgrp_GPLMUX8 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO8 and LoanIO8. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux8`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX8")]
pub type PinmuxgrpGplmux8 = crate::Reg<pinmuxgrp_gplmux8::PinmuxgrpGplmux8Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO8 and LoanIO8. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux8;
#[doc = "pinmuxgrp_GPLMUX9 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO9 and LoanIO9. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux9`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX9")]
pub type PinmuxgrpGplmux9 = crate::Reg<pinmuxgrp_gplmux9::PinmuxgrpGplmux9Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO9 and LoanIO9. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux9;
#[doc = "pinmuxgrp_GPLMUX10 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO10 and LoanIO10. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux10`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX10")]
pub type PinmuxgrpGplmux10 = crate::Reg<pinmuxgrp_gplmux10::PinmuxgrpGplmux10Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO10 and LoanIO10. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux10;
#[doc = "pinmuxgrp_GPLMUX11 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO11 and LoanIO11. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux11`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX11")]
pub type PinmuxgrpGplmux11 = crate::Reg<pinmuxgrp_gplmux11::PinmuxgrpGplmux11Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO11 and LoanIO11. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux11;
#[doc = "pinmuxgrp_GPLMUX12 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO12 and LoanIO12. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux12`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX12")]
pub type PinmuxgrpGplmux12 = crate::Reg<pinmuxgrp_gplmux12::PinmuxgrpGplmux12Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO12 and LoanIO12. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux12;
#[doc = "pinmuxgrp_GPLMUX13 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO13 and LoanIO13. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux13`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX13")]
pub type PinmuxgrpGplmux13 = crate::Reg<pinmuxgrp_gplmux13::PinmuxgrpGplmux13Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO13 and LoanIO13. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux13;
#[doc = "pinmuxgrp_GPLMUX14 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO14 and LoanIO14. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux14`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX14")]
pub type PinmuxgrpGplmux14 = crate::Reg<pinmuxgrp_gplmux14::PinmuxgrpGplmux14Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO14 and LoanIO14. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux14;
#[doc = "pinmuxgrp_GPLMUX15 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO15 and LoanIO15. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux15`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX15")]
pub type PinmuxgrpGplmux15 = crate::Reg<pinmuxgrp_gplmux15::PinmuxgrpGplmux15Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO15 and LoanIO15. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux15;
#[doc = "pinmuxgrp_GPLMUX16 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO16 and LoanIO16. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux16::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux16::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux16`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX16")]
pub type PinmuxgrpGplmux16 = crate::Reg<pinmuxgrp_gplmux16::PinmuxgrpGplmux16Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO16 and LoanIO16. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux16;
#[doc = "pinmuxgrp_GPLMUX17 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO17 and LoanIO17. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux17::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux17::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux17`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX17")]
pub type PinmuxgrpGplmux17 = crate::Reg<pinmuxgrp_gplmux17::PinmuxgrpGplmux17Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO17 and LoanIO17. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux17;
#[doc = "pinmuxgrp_GPLMUX18 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO18 and LoanIO18. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux18::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux18::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux18`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX18")]
pub type PinmuxgrpGplmux18 = crate::Reg<pinmuxgrp_gplmux18::PinmuxgrpGplmux18Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO18 and LoanIO18. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux18;
#[doc = "pinmuxgrp_GPLMUX19 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO19 and LoanIO19. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux19::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux19::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux19`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX19")]
pub type PinmuxgrpGplmux19 = crate::Reg<pinmuxgrp_gplmux19::PinmuxgrpGplmux19Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO19 and LoanIO19. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux19;
#[doc = "pinmuxgrp_GPLMUX20 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO20 and LoanIO20. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux20::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux20::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux20`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX20")]
pub type PinmuxgrpGplmux20 = crate::Reg<pinmuxgrp_gplmux20::PinmuxgrpGplmux20Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO20 and LoanIO20. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux20;
#[doc = "pinmuxgrp_GPLMUX21 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO21 and LoanIO21. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux21::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux21::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux21`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX21")]
pub type PinmuxgrpGplmux21 = crate::Reg<pinmuxgrp_gplmux21::PinmuxgrpGplmux21Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO21 and LoanIO21. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux21;
#[doc = "pinmuxgrp_GPLMUX22 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO22 and LoanIO22. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux22::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux22::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux22`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX22")]
pub type PinmuxgrpGplmux22 = crate::Reg<pinmuxgrp_gplmux22::PinmuxgrpGplmux22Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO22 and LoanIO22. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux22;
#[doc = "pinmuxgrp_GPLMUX23 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO23 and LoanIO23. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux23::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux23::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux23`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX23")]
pub type PinmuxgrpGplmux23 = crate::Reg<pinmuxgrp_gplmux23::PinmuxgrpGplmux23Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO23 and LoanIO23. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux23;
#[doc = "pinmuxgrp_GPLMUX24 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO24 and LoanIO24. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux24::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux24::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux24`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX24")]
pub type PinmuxgrpGplmux24 = crate::Reg<pinmuxgrp_gplmux24::PinmuxgrpGplmux24Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO24 and LoanIO24. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux24;
#[doc = "pinmuxgrp_GPLMUX25 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO25 and LoanIO25. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux25::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux25::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux25`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX25")]
pub type PinmuxgrpGplmux25 = crate::Reg<pinmuxgrp_gplmux25::PinmuxgrpGplmux25Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO25 and LoanIO25. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux25;
#[doc = "pinmuxgrp_GPLMUX26 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO26 and LoanIO26. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux26::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux26::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux26`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX26")]
pub type PinmuxgrpGplmux26 = crate::Reg<pinmuxgrp_gplmux26::PinmuxgrpGplmux26Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO26 and LoanIO26. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux26;
#[doc = "pinmuxgrp_GPLMUX27 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO27 and LoanIO27. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux27::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux27::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux27`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX27")]
pub type PinmuxgrpGplmux27 = crate::Reg<pinmuxgrp_gplmux27::PinmuxgrpGplmux27Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO27 and LoanIO27. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux27;
#[doc = "pinmuxgrp_GPLMUX28 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO28 and LoanIO28. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux28::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux28::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux28`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX28")]
pub type PinmuxgrpGplmux28 = crate::Reg<pinmuxgrp_gplmux28::PinmuxgrpGplmux28Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO28 and LoanIO28. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux28;
#[doc = "pinmuxgrp_GPLMUX29 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO29 and LoanIO29. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux29::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux29::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux29`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX29")]
pub type PinmuxgrpGplmux29 = crate::Reg<pinmuxgrp_gplmux29::PinmuxgrpGplmux29Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO29 and LoanIO29. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux29;
#[doc = "pinmuxgrp_GPLMUX30 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO30 and LoanIO30. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux30::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux30::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux30`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX30")]
pub type PinmuxgrpGplmux30 = crate::Reg<pinmuxgrp_gplmux30::PinmuxgrpGplmux30Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO30 and LoanIO30. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux30;
#[doc = "pinmuxgrp_GPLMUX31 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO31 and LoanIO31. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux31::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux31::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux31`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX31")]
pub type PinmuxgrpGplmux31 = crate::Reg<pinmuxgrp_gplmux31::PinmuxgrpGplmux31Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO31 and LoanIO31. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux31;
#[doc = "pinmuxgrp_GPLMUX32 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO32 and LoanIO32. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux32::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux32::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux32`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX32")]
pub type PinmuxgrpGplmux32 = crate::Reg<pinmuxgrp_gplmux32::PinmuxgrpGplmux32Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO32 and LoanIO32. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux32;
#[doc = "pinmuxgrp_GPLMUX33 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO33 and LoanIO33. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux33::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux33::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux33`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX33")]
pub type PinmuxgrpGplmux33 = crate::Reg<pinmuxgrp_gplmux33::PinmuxgrpGplmux33Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO33 and LoanIO33. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux33;
#[doc = "pinmuxgrp_GPLMUX34 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO34 and LoanIO34. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux34::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux34::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux34`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX34")]
pub type PinmuxgrpGplmux34 = crate::Reg<pinmuxgrp_gplmux34::PinmuxgrpGplmux34Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO34 and LoanIO34. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux34;
#[doc = "pinmuxgrp_GPLMUX35 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO35 and LoanIO35. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux35::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux35::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux35`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX35")]
pub type PinmuxgrpGplmux35 = crate::Reg<pinmuxgrp_gplmux35::PinmuxgrpGplmux35Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO35 and LoanIO35. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux35;
#[doc = "pinmuxgrp_GPLMUX36 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO36 and LoanIO36. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux36::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux36::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux36`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX36")]
pub type PinmuxgrpGplmux36 = crate::Reg<pinmuxgrp_gplmux36::PinmuxgrpGplmux36Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO36 and LoanIO36. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux36;
#[doc = "pinmuxgrp_GPLMUX37 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO37 and LoanIO37. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux37::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux37::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux37`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX37")]
pub type PinmuxgrpGplmux37 = crate::Reg<pinmuxgrp_gplmux37::PinmuxgrpGplmux37Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO37 and LoanIO37. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux37;
#[doc = "pinmuxgrp_GPLMUX38 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO38 and LoanIO38. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux38::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux38::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux38`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX38")]
pub type PinmuxgrpGplmux38 = crate::Reg<pinmuxgrp_gplmux38::PinmuxgrpGplmux38Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO38 and LoanIO38. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux38;
#[doc = "pinmuxgrp_GPLMUX39 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO39 and LoanIO39. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux39::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux39::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux39`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX39")]
pub type PinmuxgrpGplmux39 = crate::Reg<pinmuxgrp_gplmux39::PinmuxgrpGplmux39Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO39 and LoanIO39. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux39;
#[doc = "pinmuxgrp_GPLMUX40 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO40 and LoanIO40. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux40::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux40::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux40`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX40")]
pub type PinmuxgrpGplmux40 = crate::Reg<pinmuxgrp_gplmux40::PinmuxgrpGplmux40Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO40 and LoanIO40. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux40;
#[doc = "pinmuxgrp_GPLMUX41 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO41 and LoanIO41. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux41::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux41::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux41`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX41")]
pub type PinmuxgrpGplmux41 = crate::Reg<pinmuxgrp_gplmux41::PinmuxgrpGplmux41Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO41 and LoanIO41. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux41;
#[doc = "pinmuxgrp_GPLMUX42 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO42 and LoanIO42. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux42::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux42::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux42`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX42")]
pub type PinmuxgrpGplmux42 = crate::Reg<pinmuxgrp_gplmux42::PinmuxgrpGplmux42Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO42 and LoanIO42. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux42;
#[doc = "pinmuxgrp_GPLMUX43 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO43 and LoanIO43. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux43::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux43::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux43`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX43")]
pub type PinmuxgrpGplmux43 = crate::Reg<pinmuxgrp_gplmux43::PinmuxgrpGplmux43Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO43 and LoanIO43. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux43;
#[doc = "pinmuxgrp_GPLMUX44 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO44 and LoanIO44. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux44::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux44::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux44`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX44")]
pub type PinmuxgrpGplmux44 = crate::Reg<pinmuxgrp_gplmux44::PinmuxgrpGplmux44Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO44 and LoanIO44. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux44;
#[doc = "pinmuxgrp_GPLMUX45 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO45 and LoanIO45. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux45::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux45::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux45`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX45")]
pub type PinmuxgrpGplmux45 = crate::Reg<pinmuxgrp_gplmux45::PinmuxgrpGplmux45Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO45 and LoanIO45. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux45;
#[doc = "pinmuxgrp_GPLMUX46 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO46 and LoanIO46. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux46::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux46::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux46`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX46")]
pub type PinmuxgrpGplmux46 = crate::Reg<pinmuxgrp_gplmux46::PinmuxgrpGplmux46Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO46 and LoanIO46. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux46;
#[doc = "pinmuxgrp_GPLMUX47 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO47 and LoanIO47. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux47::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux47::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux47`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX47")]
pub type PinmuxgrpGplmux47 = crate::Reg<pinmuxgrp_gplmux47::PinmuxgrpGplmux47Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO47 and LoanIO47. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux47;
#[doc = "pinmuxgrp_GPLMUX48 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO48 and LoanIO48. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux48::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux48::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux48`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX48")]
pub type PinmuxgrpGplmux48 = crate::Reg<pinmuxgrp_gplmux48::PinmuxgrpGplmux48Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO48 and LoanIO48. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux48;
#[doc = "pinmuxgrp_GPLMUX49 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO49 and LoanIO49. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux49::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux49::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux49`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX49")]
pub type PinmuxgrpGplmux49 = crate::Reg<pinmuxgrp_gplmux49::PinmuxgrpGplmux49Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO49 and LoanIO49. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux49;
#[doc = "pinmuxgrp_GPLMUX50 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO50 and LoanIO50. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux50::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux50::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux50`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX50")]
pub type PinmuxgrpGplmux50 = crate::Reg<pinmuxgrp_gplmux50::PinmuxgrpGplmux50Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO50 and LoanIO50. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux50;
#[doc = "pinmuxgrp_GPLMUX51 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO51 and LoanIO51. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux51::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux51::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux51`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX51")]
pub type PinmuxgrpGplmux51 = crate::Reg<pinmuxgrp_gplmux51::PinmuxgrpGplmux51Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO51 and LoanIO51. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux51;
#[doc = "pinmuxgrp_GPLMUX52 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO52 and LoanIO52. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux52::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux52::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux52`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX52")]
pub type PinmuxgrpGplmux52 = crate::Reg<pinmuxgrp_gplmux52::PinmuxgrpGplmux52Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO52 and LoanIO52. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux52;
#[doc = "pinmuxgrp_GPLMUX53 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO53 and LoanIO53. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux53::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux53::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux53`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX53")]
pub type PinmuxgrpGplmux53 = crate::Reg<pinmuxgrp_gplmux53::PinmuxgrpGplmux53Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO53 and LoanIO53. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux53;
#[doc = "pinmuxgrp_GPLMUX54 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO54 and LoanIO54. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux54::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux54::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux54`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX54")]
pub type PinmuxgrpGplmux54 = crate::Reg<pinmuxgrp_gplmux54::PinmuxgrpGplmux54Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO54 and LoanIO54. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux54;
#[doc = "pinmuxgrp_GPLMUX55 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO55 and LoanIO55. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux55::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux55::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux55`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX55")]
pub type PinmuxgrpGplmux55 = crate::Reg<pinmuxgrp_gplmux55::PinmuxgrpGplmux55Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO55 and LoanIO55. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux55;
#[doc = "pinmuxgrp_GPLMUX56 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO56 and LoanIO56. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux56::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux56::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux56`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX56")]
pub type PinmuxgrpGplmux56 = crate::Reg<pinmuxgrp_gplmux56::PinmuxgrpGplmux56Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO56 and LoanIO56. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux56;
#[doc = "pinmuxgrp_GPLMUX57 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO57 and LoanIO57. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux57::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux57::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux57`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX57")]
pub type PinmuxgrpGplmux57 = crate::Reg<pinmuxgrp_gplmux57::PinmuxgrpGplmux57Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO57 and LoanIO57. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux57;
#[doc = "pinmuxgrp_GPLMUX58 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO58 and LoanIO58. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux58::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux58::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux58`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX58")]
pub type PinmuxgrpGplmux58 = crate::Reg<pinmuxgrp_gplmux58::PinmuxgrpGplmux58Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO58 and LoanIO58. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux58;
#[doc = "pinmuxgrp_GPLMUX59 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO59 and LoanIO59. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux59::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux59::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux59`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX59")]
pub type PinmuxgrpGplmux59 = crate::Reg<pinmuxgrp_gplmux59::PinmuxgrpGplmux59Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO59 and LoanIO59. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux59;
#[doc = "pinmuxgrp_GPLMUX60 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO60 and LoanIO60. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux60::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux60::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux60`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX60")]
pub type PinmuxgrpGplmux60 = crate::Reg<pinmuxgrp_gplmux60::PinmuxgrpGplmux60Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO60 and LoanIO60. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux60;
#[doc = "pinmuxgrp_GPLMUX61 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO61 and LoanIO61. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux61::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux61::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux61`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX61")]
pub type PinmuxgrpGplmux61 = crate::Reg<pinmuxgrp_gplmux61::PinmuxgrpGplmux61Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO61 and LoanIO61. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux61;
#[doc = "pinmuxgrp_GPLMUX62 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO62 and LoanIO62. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux62::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux62::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux62`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX62")]
pub type PinmuxgrpGplmux62 = crate::Reg<pinmuxgrp_gplmux62::PinmuxgrpGplmux62Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO62 and LoanIO62. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux62;
#[doc = "pinmuxgrp_GPLMUX63 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO63 and LoanIO63. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux63::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux63::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux63`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX63")]
pub type PinmuxgrpGplmux63 = crate::Reg<pinmuxgrp_gplmux63::PinmuxgrpGplmux63Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO63 and LoanIO63. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux63;
#[doc = "pinmuxgrp_GPLMUX64 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO64 and LoanIO64. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux64::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux64::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux64`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX64")]
pub type PinmuxgrpGplmux64 = crate::Reg<pinmuxgrp_gplmux64::PinmuxgrpGplmux64Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO64 and LoanIO64. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux64;
#[doc = "pinmuxgrp_GPLMUX65 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO65 and LoanIO65. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux65::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux65::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux65`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX65")]
pub type PinmuxgrpGplmux65 = crate::Reg<pinmuxgrp_gplmux65::PinmuxgrpGplmux65Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO65 and LoanIO65. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux65;
#[doc = "pinmuxgrp_GPLMUX66 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO66 and LoanIO66. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux66::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux66::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux66`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX66")]
pub type PinmuxgrpGplmux66 = crate::Reg<pinmuxgrp_gplmux66::PinmuxgrpGplmux66Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO66 and LoanIO66. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux66;
#[doc = "pinmuxgrp_GPLMUX67 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO67 and LoanIO67. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux67::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux67::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux67`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX67")]
pub type PinmuxgrpGplmux67 = crate::Reg<pinmuxgrp_gplmux67::PinmuxgrpGplmux67Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO67 and LoanIO67. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux67;
#[doc = "pinmuxgrp_GPLMUX68 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO68 and LoanIO68. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux68::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux68::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux68`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX68")]
pub type PinmuxgrpGplmux68 = crate::Reg<pinmuxgrp_gplmux68::PinmuxgrpGplmux68Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO68 and LoanIO68. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux68;
#[doc = "pinmuxgrp_GPLMUX69 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO69 and LoanIO69. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux69::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux69::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux69`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX69")]
pub type PinmuxgrpGplmux69 = crate::Reg<pinmuxgrp_gplmux69::PinmuxgrpGplmux69Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO69 and LoanIO69. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux69;
#[doc = "pinmuxgrp_GPLMUX70 (rw) register accessor: Selection between GPIO and LoanIO output and output enable for GPIO70 and LoanIO70. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux70::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux70::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_gplmux70`]
module"]
#[doc(alias = "pinmuxgrp_GPLMUX70")]
pub type PinmuxgrpGplmux70 = crate::Reg<pinmuxgrp_gplmux70::PinmuxgrpGplmux70Spec>;
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO70 and LoanIO70. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_gplmux70;
#[doc = "pinmuxgrp_NANDUSEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for NAND signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_nandusefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_nandusefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_nandusefpga`]
module"]
#[doc(alias = "pinmuxgrp_NANDUSEFPGA")]
pub type PinmuxgrpNandusefpga = crate::Reg<pinmuxgrp_nandusefpga::PinmuxgrpNandusefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for NAND signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_nandusefpga;
#[doc = "pinmuxgrp_RGMII1USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for RGMII1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_rgmii1usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_rgmii1usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_rgmii1usefpga`]
module"]
#[doc(alias = "pinmuxgrp_RGMII1USEFPGA")]
pub type PinmuxgrpRgmii1usefpga = crate::Reg<pinmuxgrp_rgmii1usefpga::PinmuxgrpRgmii1usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for RGMII1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_rgmii1usefpga;
#[doc = "pinmuxgrp_I2C0USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for I2C0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_i2c0usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_i2c0usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_i2c0usefpga`]
module"]
#[doc(alias = "pinmuxgrp_I2C0USEFPGA")]
pub type PinmuxgrpI2c0usefpga = crate::Reg<pinmuxgrp_i2c0usefpga::PinmuxgrpI2c0usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for I2C0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_i2c0usefpga;
#[doc = "pinmuxgrp_RGMII0USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for RGMII0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_rgmii0usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_rgmii0usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_rgmii0usefpga`]
module"]
#[doc(alias = "pinmuxgrp_RGMII0USEFPGA")]
pub type PinmuxgrpRgmii0usefpga = crate::Reg<pinmuxgrp_rgmii0usefpga::PinmuxgrpRgmii0usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for RGMII0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_rgmii0usefpga;
#[doc = "pinmuxgrp_I2C3USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for I2C3 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_i2c3usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_i2c3usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_i2c3usefpga`]
module"]
#[doc(alias = "pinmuxgrp_I2C3USEFPGA")]
pub type PinmuxgrpI2c3usefpga = crate::Reg<pinmuxgrp_i2c3usefpga::PinmuxgrpI2c3usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for I2C3 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_i2c3usefpga;
#[doc = "pinmuxgrp_I2C2USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for I2C2 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_i2c2usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_i2c2usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_i2c2usefpga`]
module"]
#[doc(alias = "pinmuxgrp_I2C2USEFPGA")]
pub type PinmuxgrpI2c2usefpga = crate::Reg<pinmuxgrp_i2c2usefpga::PinmuxgrpI2c2usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for I2C2 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_i2c2usefpga;
#[doc = "pinmuxgrp_I2C1USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for I2C1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_i2c1usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_i2c1usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_i2c1usefpga`]
module"]
#[doc(alias = "pinmuxgrp_I2C1USEFPGA")]
pub type PinmuxgrpI2c1usefpga = crate::Reg<pinmuxgrp_i2c1usefpga::PinmuxgrpI2c1usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for I2C1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_i2c1usefpga;
#[doc = "pinmuxgrp_SPIM1USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for SPIM1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_spim1usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_spim1usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_spim1usefpga`]
module"]
#[doc(alias = "pinmuxgrp_SPIM1USEFPGA")]
pub type PinmuxgrpSpim1usefpga = crate::Reg<pinmuxgrp_spim1usefpga::PinmuxgrpSpim1usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for SPIM1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_spim1usefpga;
#[doc = "pinmuxgrp_SPIM0USEFPGA (rw) register accessor: Selection between HPS Pins and FPGA Interface for SPIM0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_spim0usefpga::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_spim0usefpga::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pinmuxgrp_spim0usefpga`]
module"]
#[doc(alias = "pinmuxgrp_SPIM0USEFPGA")]
pub type PinmuxgrpSpim0usefpga = crate::Reg<pinmuxgrp_spim0usefpga::PinmuxgrpSpim0usefpgaSpec>;
#[doc = "Selection between HPS Pins and FPGA Interface for SPIM0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections."]
pub mod pinmuxgrp_spim0usefpga;
