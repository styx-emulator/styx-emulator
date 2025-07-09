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
#[doc = "Register `globgrp_grstctl` reader"]
pub type R = crate::R<GlobgrpGrstctlSpec>;
#[doc = "Register `globgrp_grstctl` writer"]
pub type W = crate::W<GlobgrpGrstctlSpec>;
#[doc = "Mode:Host and Device. Resets the hclk and phy_clock domains as follows:Clears the interrupts and all the CSR registers except the following register bits: - PCGCCTL.RstPdwnModule - PCGCCTL.GateHclk - PCGCCTL.PwrClmp - PCGCCTL.StopPPhyLPwrClkSelclk - GUSBCFG.PhyLPwrClkSel - GUSBCFG.DDRSel - GUSBCFG.PHYSel - GUSBCFG.FSIntf - GUSBCFG.ULPI_UTMI_Sel - GUSBCFG.PHYIf - HCFG.FSLSPclkSel - DCFG.DevSpd - GGPIO - GPWRDN - GADPCTL All module state machines (except the AHB Slave Unit) are reset to the IDLE state, and all the transmit FIFOs and the receive FIFO are flushed. Any transactions on the AHB Master are terminated as soonas possible, after gracefully completing the last data phase of an AHB transfer. Any transactions on the USB are terminated immediately. When Hibernation or ADP feature is enabled, the PMU module is not reset by the Core Soft Reset.The application can write to this bit any time it wants to reset the core. This is a self-clearing bit and the core clears this bit after all the necessary logic is reset in the core, which can take several clocks, depending on the current state of the core. Once this bit is cleared software must wait at least 3 PHY clocks before doing any access to the PHY domain (synchronization delay). Software must also must check that bit 31 of this register is 1 (AHB Master is IDLE) before starting any operation.Typically software reset is used during software development and also when you dynamically change the PHY selection bits in the USB configuration registers listed above. When you change the PHY, the corresponding clock for the PHY is selected and used in the PHY domain. Once a new clock is selected, the PHY domain has to be reset for proper operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Csftrst {
    #[doc = "0: `0`"]
    Notactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Csftrst> for bool {
    #[inline(always)]
    fn from(variant: Csftrst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `csftrst` reader - Mode:Host and Device. Resets the hclk and phy_clock domains as follows:Clears the interrupts and all the CSR registers except the following register bits: - PCGCCTL.RstPdwnModule - PCGCCTL.GateHclk - PCGCCTL.PwrClmp - PCGCCTL.StopPPhyLPwrClkSelclk - GUSBCFG.PhyLPwrClkSel - GUSBCFG.DDRSel - GUSBCFG.PHYSel - GUSBCFG.FSIntf - GUSBCFG.ULPI_UTMI_Sel - GUSBCFG.PHYIf - HCFG.FSLSPclkSel - DCFG.DevSpd - GGPIO - GPWRDN - GADPCTL All module state machines (except the AHB Slave Unit) are reset to the IDLE state, and all the transmit FIFOs and the receive FIFO are flushed. Any transactions on the AHB Master are terminated as soonas possible, after gracefully completing the last data phase of an AHB transfer. Any transactions on the USB are terminated immediately. When Hibernation or ADP feature is enabled, the PMU module is not reset by the Core Soft Reset.The application can write to this bit any time it wants to reset the core. This is a self-clearing bit and the core clears this bit after all the necessary logic is reset in the core, which can take several clocks, depending on the current state of the core. Once this bit is cleared software must wait at least 3 PHY clocks before doing any access to the PHY domain (synchronization delay). Software must also must check that bit 31 of this register is 1 (AHB Master is IDLE) before starting any operation.Typically software reset is used during software development and also when you dynamically change the PHY selection bits in the USB configuration registers listed above. When you change the PHY, the corresponding clock for the PHY is selected and used in the PHY domain. Once a new clock is selected, the PHY domain has to be reset for proper operation."]
pub type CsftrstR = crate::BitReader<Csftrst>;
impl CsftrstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Csftrst {
        match self.bits {
            false => Csftrst::Notactive,
            true => Csftrst::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notactive(&self) -> bool {
        *self == Csftrst::Notactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Csftrst::Active
    }
}
#[doc = "Field `csftrst` writer - Mode:Host and Device. Resets the hclk and phy_clock domains as follows:Clears the interrupts and all the CSR registers except the following register bits: - PCGCCTL.RstPdwnModule - PCGCCTL.GateHclk - PCGCCTL.PwrClmp - PCGCCTL.StopPPhyLPwrClkSelclk - GUSBCFG.PhyLPwrClkSel - GUSBCFG.DDRSel - GUSBCFG.PHYSel - GUSBCFG.FSIntf - GUSBCFG.ULPI_UTMI_Sel - GUSBCFG.PHYIf - HCFG.FSLSPclkSel - DCFG.DevSpd - GGPIO - GPWRDN - GADPCTL All module state machines (except the AHB Slave Unit) are reset to the IDLE state, and all the transmit FIFOs and the receive FIFO are flushed. Any transactions on the AHB Master are terminated as soonas possible, after gracefully completing the last data phase of an AHB transfer. Any transactions on the USB are terminated immediately. When Hibernation or ADP feature is enabled, the PMU module is not reset by the Core Soft Reset.The application can write to this bit any time it wants to reset the core. This is a self-clearing bit and the core clears this bit after all the necessary logic is reset in the core, which can take several clocks, depending on the current state of the core. Once this bit is cleared software must wait at least 3 PHY clocks before doing any access to the PHY domain (synchronization delay). Software must also must check that bit 31 of this register is 1 (AHB Master is IDLE) before starting any operation.Typically software reset is used during software development and also when you dynamically change the PHY selection bits in the USB configuration registers listed above. When you change the PHY, the corresponding clock for the PHY is selected and used in the PHY domain. Once a new clock is selected, the PHY domain has to be reset for proper operation."]
pub type CsftrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host only. The application writes this bit to reset the (micro)frame number counter inside the core. When the (micro)frame counter is reset, the subsequent SOF sent out by the core has a (micro)frame number of 0. When application writes 1 to the bit, it might not be able to read back the value as it will get cleared by the core in a few clock cycles.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frmcntrrst {
    #[doc = "0: `0`"]
    Notactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Frmcntrrst> for bool {
    #[inline(always)]
    fn from(variant: Frmcntrrst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `frmcntrrst` reader - Mode:Host only. The application writes this bit to reset the (micro)frame number counter inside the core. When the (micro)frame counter is reset, the subsequent SOF sent out by the core has a (micro)frame number of 0. When application writes 1 to the bit, it might not be able to read back the value as it will get cleared by the core in a few clock cycles."]
pub type FrmcntrrstR = crate::BitReader<Frmcntrrst>;
impl FrmcntrrstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Frmcntrrst {
        match self.bits {
            false => Frmcntrrst::Notactive,
            true => Frmcntrrst::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notactive(&self) -> bool {
        *self == Frmcntrrst::Notactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Frmcntrrst::Active
    }
}
#[doc = "Field `frmcntrrst` writer - Mode:Host only. The application writes this bit to reset the (micro)frame number counter inside the core. When the (micro)frame counter is reset, the subsequent SOF sent out by the core has a (micro)frame number of 0. When application writes 1 to the bit, it might not be able to read back the value as it will get cleared by the core in a few clock cycles."]
pub type FrmcntrrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The application can flush the entire RxFIFO using this bit, but must first ensure that the core is not in the middle of a transaction. The application must only write to this bit after checking that the core is neither reading from the RxFIFO nor writing to the RxFIFO. The application must wait until the bit is cleared before performing any other operations. This bit requires 8 clocks (slowest of PHY or AHB clock) to clear.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfflsh {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxfflsh> for bool {
    #[inline(always)]
    fn from(variant: Rxfflsh) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfflsh` reader - Mode:Host and Device. The application can flush the entire RxFIFO using this bit, but must first ensure that the core is not in the middle of a transaction. The application must only write to this bit after checking that the core is neither reading from the RxFIFO nor writing to the RxFIFO. The application must wait until the bit is cleared before performing any other operations. This bit requires 8 clocks (slowest of PHY or AHB clock) to clear."]
pub type RxfflshR = crate::BitReader<Rxfflsh>;
impl RxfflshR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfflsh {
        match self.bits {
            false => Rxfflsh::Inactive,
            true => Rxfflsh::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxfflsh::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxfflsh::Active
    }
}
#[doc = "Field `rxfflsh` writer - Mode:Host and Device. The application can flush the entire RxFIFO using this bit, but must first ensure that the core is not in the middle of a transaction. The application must only write to this bit after checking that the core is neither reading from the RxFIFO nor writing to the RxFIFO. The application must wait until the bit is cleared before performing any other operations. This bit requires 8 clocks (slowest of PHY or AHB clock) to clear."]
pub type RxfflshW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. This bit selectively flushes a single or all transmit FIFOs, but cannot do so If the core is in the midst of a transaction. The application must write this bit only after checking that the core is neither writing to the TxFIFO nor reading from the TxFIFO. Verify using these registers: ReadNAK Effective Interrupt ensures the core is notreading from the FIFO WriteGRSTCTL.AHBIdle ensures the core is not writinganything to the FIFO. Flushing is normally recommended when FIFOs are reconfigured or when switching between Shared FIFO and Dedicated Transmit FIFO operation. FIFO flushing is also recommended during device endpoint disable. The application must wait until the core clears this bit before performing any operations. This bit takes eight clocks to clear, using the slower clock of phy_clk or hclk.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfflsh {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txfflsh> for bool {
    #[inline(always)]
    fn from(variant: Txfflsh) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfflsh` reader - Mode:Host and Device. This bit selectively flushes a single or all transmit FIFOs, but cannot do so If the core is in the midst of a transaction. The application must write this bit only after checking that the core is neither writing to the TxFIFO nor reading from the TxFIFO. Verify using these registers: ReadNAK Effective Interrupt ensures the core is notreading from the FIFO WriteGRSTCTL.AHBIdle ensures the core is not writinganything to the FIFO. Flushing is normally recommended when FIFOs are reconfigured or when switching between Shared FIFO and Dedicated Transmit FIFO operation. FIFO flushing is also recommended during device endpoint disable. The application must wait until the core clears this bit before performing any operations. This bit takes eight clocks to clear, using the slower clock of phy_clk or hclk."]
pub type TxfflshR = crate::BitReader<Txfflsh>;
impl TxfflshR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfflsh {
        match self.bits {
            false => Txfflsh::Inactive,
            true => Txfflsh::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txfflsh::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txfflsh::Active
    }
}
#[doc = "Field `txfflsh` writer - Mode:Host and Device. This bit selectively flushes a single or all transmit FIFOs, but cannot do so If the core is in the midst of a transaction. The application must write this bit only after checking that the core is neither writing to the TxFIFO nor reading from the TxFIFO. Verify using these registers: ReadNAK Effective Interrupt ensures the core is notreading from the FIFO WriteGRSTCTL.AHBIdle ensures the core is not writinganything to the FIFO. Flushing is normally recommended when FIFOs are reconfigured or when switching between Shared FIFO and Dedicated Transmit FIFO operation. FIFO flushing is also recommended during device endpoint disable. The application must wait until the core clears this bit before performing any operations. This bit takes eight clocks to clear, using the slower clock of phy_clk or hclk."]
pub type TxfflshW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. This is the FIFO number that must be flushed using the TxFIFO Flush bit. This field must not be changed until the core clears the TxFIFO Flush bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Txfnum {
    #[doc = "0: `0`"]
    Txf0 = 0,
    #[doc = "1: `1`"]
    Txf1 = 1,
    #[doc = "2: `10`"]
    Txf2 = 2,
    #[doc = "15: `1111`"]
    Txf15 = 15,
    #[doc = "16: `10000`"]
    Txf16 = 16,
}
impl From<Txfnum> for u8 {
    #[inline(always)]
    fn from(variant: Txfnum) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Txfnum {
    type Ux = u8;
}
#[doc = "Field `txfnum` reader - Mode:Host and Device. This is the FIFO number that must be flushed using the TxFIFO Flush bit. This field must not be changed until the core clears the TxFIFO Flush bit."]
pub type TxfnumR = crate::FieldReader<Txfnum>;
impl TxfnumR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Txfnum> {
        match self.bits {
            0 => Some(Txfnum::Txf0),
            1 => Some(Txfnum::Txf1),
            2 => Some(Txfnum::Txf2),
            15 => Some(Txfnum::Txf15),
            16 => Some(Txfnum::Txf16),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_txf0(&self) -> bool {
        *self == Txfnum::Txf0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_txf1(&self) -> bool {
        *self == Txfnum::Txf1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_txf2(&self) -> bool {
        *self == Txfnum::Txf2
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_txf15(&self) -> bool {
        *self == Txfnum::Txf15
    }
    #[doc = "`10000`"]
    #[inline(always)]
    pub fn is_txf16(&self) -> bool {
        *self == Txfnum::Txf16
    }
}
#[doc = "Field `txfnum` writer - Mode:Host and Device. This is the FIFO number that must be flushed using the TxFIFO Flush bit. This field must not be changed until the core clears the TxFIFO Flush bit."]
pub type TxfnumW<'a, REG> = crate::FieldWriter<'a, REG, 5, Txfnum>;
impl<'a, REG> TxfnumW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn txf0(self) -> &'a mut crate::W<REG> {
        self.variant(Txfnum::Txf0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn txf1(self) -> &'a mut crate::W<REG> {
        self.variant(Txfnum::Txf1)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn txf2(self) -> &'a mut crate::W<REG> {
        self.variant(Txfnum::Txf2)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn txf15(self) -> &'a mut crate::W<REG> {
        self.variant(Txfnum::Txf15)
    }
    #[doc = "`10000`"]
    #[inline(always)]
    pub fn txf16(self) -> &'a mut crate::W<REG> {
        self.variant(Txfnum::Txf16)
    }
}
#[doc = "Mode:Host and Device. Indicates that the DMA request is in progress. Used for debug.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmareq {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Dmareq> for bool {
    #[inline(always)]
    fn from(variant: Dmareq) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dmareq` reader - Mode:Host and Device. Indicates that the DMA request is in progress. Used for debug."]
pub type DmareqR = crate::BitReader<Dmareq>;
impl DmareqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dmareq {
        match self.bits {
            false => Dmareq::Inactive,
            true => Dmareq::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Dmareq::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Dmareq::Active
    }
}
#[doc = "Field `dmareq` writer - Mode:Host and Device. Indicates that the DMA request is in progress. Used for debug."]
pub type DmareqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. Indicates that the AHB Master State Machine is in the IDLE condition.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ahbidle {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ahbidle> for bool {
    #[inline(always)]
    fn from(variant: Ahbidle) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ahbidle` reader - Mode:Host and Device. Indicates that the AHB Master State Machine is in the IDLE condition."]
pub type AhbidleR = crate::BitReader<Ahbidle>;
impl AhbidleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ahbidle {
        match self.bits {
            false => Ahbidle::Inactive,
            true => Ahbidle::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ahbidle::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ahbidle::Active
    }
}
#[doc = "Field `ahbidle` writer - Mode:Host and Device. Indicates that the AHB Master State Machine is in the IDLE condition."]
pub type AhbidleW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Mode:Host and Device. Resets the hclk and phy_clock domains as follows:Clears the interrupts and all the CSR registers except the following register bits: - PCGCCTL.RstPdwnModule - PCGCCTL.GateHclk - PCGCCTL.PwrClmp - PCGCCTL.StopPPhyLPwrClkSelclk - GUSBCFG.PhyLPwrClkSel - GUSBCFG.DDRSel - GUSBCFG.PHYSel - GUSBCFG.FSIntf - GUSBCFG.ULPI_UTMI_Sel - GUSBCFG.PHYIf - HCFG.FSLSPclkSel - DCFG.DevSpd - GGPIO - GPWRDN - GADPCTL All module state machines (except the AHB Slave Unit) are reset to the IDLE state, and all the transmit FIFOs and the receive FIFO are flushed. Any transactions on the AHB Master are terminated as soonas possible, after gracefully completing the last data phase of an AHB transfer. Any transactions on the USB are terminated immediately. When Hibernation or ADP feature is enabled, the PMU module is not reset by the Core Soft Reset.The application can write to this bit any time it wants to reset the core. This is a self-clearing bit and the core clears this bit after all the necessary logic is reset in the core, which can take several clocks, depending on the current state of the core. Once this bit is cleared software must wait at least 3 PHY clocks before doing any access to the PHY domain (synchronization delay). Software must also must check that bit 31 of this register is 1 (AHB Master is IDLE) before starting any operation.Typically software reset is used during software development and also when you dynamically change the PHY selection bits in the USB configuration registers listed above. When you change the PHY, the corresponding clock for the PHY is selected and used in the PHY domain. Once a new clock is selected, the PHY domain has to be reset for proper operation."]
    #[inline(always)]
    pub fn csftrst(&self) -> CsftrstR {
        CsftrstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - Mode:Host only. The application writes this bit to reset the (micro)frame number counter inside the core. When the (micro)frame counter is reset, the subsequent SOF sent out by the core has a (micro)frame number of 0. When application writes 1 to the bit, it might not be able to read back the value as it will get cleared by the core in a few clock cycles."]
    #[inline(always)]
    pub fn frmcntrrst(&self) -> FrmcntrrstR {
        FrmcntrrstR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - Mode:Host and Device. The application can flush the entire RxFIFO using this bit, but must first ensure that the core is not in the middle of a transaction. The application must only write to this bit after checking that the core is neither reading from the RxFIFO nor writing to the RxFIFO. The application must wait until the bit is cleared before performing any other operations. This bit requires 8 clocks (slowest of PHY or AHB clock) to clear."]
    #[inline(always)]
    pub fn rxfflsh(&self) -> RxfflshR {
        RxfflshR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Mode:Host and Device. This bit selectively flushes a single or all transmit FIFOs, but cannot do so If the core is in the midst of a transaction. The application must write this bit only after checking that the core is neither writing to the TxFIFO nor reading from the TxFIFO. Verify using these registers: ReadNAK Effective Interrupt ensures the core is notreading from the FIFO WriteGRSTCTL.AHBIdle ensures the core is not writinganything to the FIFO. Flushing is normally recommended when FIFOs are reconfigured or when switching between Shared FIFO and Dedicated Transmit FIFO operation. FIFO flushing is also recommended during device endpoint disable. The application must wait until the core clears this bit before performing any operations. This bit takes eight clocks to clear, using the slower clock of phy_clk or hclk."]
    #[inline(always)]
    pub fn txfflsh(&self) -> TxfflshR {
        TxfflshR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:10 - Mode:Host and Device. This is the FIFO number that must be flushed using the TxFIFO Flush bit. This field must not be changed until the core clears the TxFIFO Flush bit."]
    #[inline(always)]
    pub fn txfnum(&self) -> TxfnumR {
        TxfnumR::new(((self.bits >> 6) & 0x1f) as u8)
    }
    #[doc = "Bit 30 - Mode:Host and Device. Indicates that the DMA request is in progress. Used for debug."]
    #[inline(always)]
    pub fn dmareq(&self) -> DmareqR {
        DmareqR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Mode:Host and Device. Indicates that the AHB Master State Machine is in the IDLE condition."]
    #[inline(always)]
    pub fn ahbidle(&self) -> AhbidleR {
        AhbidleR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Mode:Host and Device. Resets the hclk and phy_clock domains as follows:Clears the interrupts and all the CSR registers except the following register bits: - PCGCCTL.RstPdwnModule - PCGCCTL.GateHclk - PCGCCTL.PwrClmp - PCGCCTL.StopPPhyLPwrClkSelclk - GUSBCFG.PhyLPwrClkSel - GUSBCFG.DDRSel - GUSBCFG.PHYSel - GUSBCFG.FSIntf - GUSBCFG.ULPI_UTMI_Sel - GUSBCFG.PHYIf - HCFG.FSLSPclkSel - DCFG.DevSpd - GGPIO - GPWRDN - GADPCTL All module state machines (except the AHB Slave Unit) are reset to the IDLE state, and all the transmit FIFOs and the receive FIFO are flushed. Any transactions on the AHB Master are terminated as soonas possible, after gracefully completing the last data phase of an AHB transfer. Any transactions on the USB are terminated immediately. When Hibernation or ADP feature is enabled, the PMU module is not reset by the Core Soft Reset.The application can write to this bit any time it wants to reset the core. This is a self-clearing bit and the core clears this bit after all the necessary logic is reset in the core, which can take several clocks, depending on the current state of the core. Once this bit is cleared software must wait at least 3 PHY clocks before doing any access to the PHY domain (synchronization delay). Software must also must check that bit 31 of this register is 1 (AHB Master is IDLE) before starting any operation.Typically software reset is used during software development and also when you dynamically change the PHY selection bits in the USB configuration registers listed above. When you change the PHY, the corresponding clock for the PHY is selected and used in the PHY domain. Once a new clock is selected, the PHY domain has to be reset for proper operation."]
    #[inline(always)]
    #[must_use]
    pub fn csftrst(&mut self) -> CsftrstW<GlobgrpGrstctlSpec> {
        CsftrstW::new(self, 0)
    }
    #[doc = "Bit 2 - Mode:Host only. The application writes this bit to reset the (micro)frame number counter inside the core. When the (micro)frame counter is reset, the subsequent SOF sent out by the core has a (micro)frame number of 0. When application writes 1 to the bit, it might not be able to read back the value as it will get cleared by the core in a few clock cycles."]
    #[inline(always)]
    #[must_use]
    pub fn frmcntrrst(&mut self) -> FrmcntrrstW<GlobgrpGrstctlSpec> {
        FrmcntrrstW::new(self, 2)
    }
    #[doc = "Bit 4 - Mode:Host and Device. The application can flush the entire RxFIFO using this bit, but must first ensure that the core is not in the middle of a transaction. The application must only write to this bit after checking that the core is neither reading from the RxFIFO nor writing to the RxFIFO. The application must wait until the bit is cleared before performing any other operations. This bit requires 8 clocks (slowest of PHY or AHB clock) to clear."]
    #[inline(always)]
    #[must_use]
    pub fn rxfflsh(&mut self) -> RxfflshW<GlobgrpGrstctlSpec> {
        RxfflshW::new(self, 4)
    }
    #[doc = "Bit 5 - Mode:Host and Device. This bit selectively flushes a single or all transmit FIFOs, but cannot do so If the core is in the midst of a transaction. The application must write this bit only after checking that the core is neither writing to the TxFIFO nor reading from the TxFIFO. Verify using these registers: ReadNAK Effective Interrupt ensures the core is notreading from the FIFO WriteGRSTCTL.AHBIdle ensures the core is not writinganything to the FIFO. Flushing is normally recommended when FIFOs are reconfigured or when switching between Shared FIFO and Dedicated Transmit FIFO operation. FIFO flushing is also recommended during device endpoint disable. The application must wait until the core clears this bit before performing any operations. This bit takes eight clocks to clear, using the slower clock of phy_clk or hclk."]
    #[inline(always)]
    #[must_use]
    pub fn txfflsh(&mut self) -> TxfflshW<GlobgrpGrstctlSpec> {
        TxfflshW::new(self, 5)
    }
    #[doc = "Bits 6:10 - Mode:Host and Device. This is the FIFO number that must be flushed using the TxFIFO Flush bit. This field must not be changed until the core clears the TxFIFO Flush bit."]
    #[inline(always)]
    #[must_use]
    pub fn txfnum(&mut self) -> TxfnumW<GlobgrpGrstctlSpec> {
        TxfnumW::new(self, 6)
    }
    #[doc = "Bit 30 - Mode:Host and Device. Indicates that the DMA request is in progress. Used for debug."]
    #[inline(always)]
    #[must_use]
    pub fn dmareq(&mut self) -> DmareqW<GlobgrpGrstctlSpec> {
        DmareqW::new(self, 30)
    }
    #[doc = "Bit 31 - Mode:Host and Device. Indicates that the AHB Master State Machine is in the IDLE condition."]
    #[inline(always)]
    #[must_use]
    pub fn ahbidle(&mut self) -> AhbidleW<GlobgrpGrstctlSpec> {
        AhbidleW::new(self, 31)
    }
}
#[doc = "The application uses this register to reset various hardware features inside the core\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grstctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_grstctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGrstctlSpec;
impl crate::RegisterSpec for GlobgrpGrstctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`globgrp_grstctl::R`](R) reader structure"]
impl crate::Readable for GlobgrpGrstctlSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_grstctl::W`](W) writer structure"]
impl crate::Writable for GlobgrpGrstctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_grstctl to value 0x8000_0000"]
impl crate::Resettable for GlobgrpGrstctlSpec {
    const RESET_VALUE: u32 = 0x8000_0000;
}
