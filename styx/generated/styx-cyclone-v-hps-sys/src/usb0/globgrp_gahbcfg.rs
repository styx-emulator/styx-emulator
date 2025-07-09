// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_gahbcfg` reader"]
pub type R = crate::R<GlobgrpGahbcfgSpec>;
#[doc = "Register `globgrp_gahbcfg` writer"]
pub type W = crate::W<GlobgrpGahbcfgSpec>;
#[doc = "Mode: Host and device. The application uses this bit to mask or unmask the interrupt line assertion to itself. Irrespective of this bits setting, the interrupt status registers are updated by the core.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glblintrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Glblintrmsk> for bool {
    #[inline(always)]
    fn from(variant: Glblintrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `glblintrmsk` reader - Mode: Host and device. The application uses this bit to mask or unmask the interrupt line assertion to itself. Irrespective of this bits setting, the interrupt status registers are updated by the core."]
pub type GlblintrmskR = crate::BitReader<Glblintrmsk>;
impl GlblintrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Glblintrmsk {
        match self.bits {
            false => Glblintrmsk::Mask,
            true => Glblintrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Glblintrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Glblintrmsk::Nomask
    }
}
#[doc = "Field `glblintrmsk` writer - Mode: Host and device. The application uses this bit to mask or unmask the interrupt line assertion to itself. Irrespective of this bits setting, the interrupt status registers are updated by the core."]
pub type GlblintrmskW<'a, REG> = crate::BitWriter<'a, REG, Glblintrmsk>;
impl<'a, REG> GlblintrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Glblintrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Glblintrmsk::Nomask)
    }
}
#[doc = "Mode:Host and device. This field is used in Internal DMA modes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Hbstlen {
    #[doc = "0: `0`"]
    Word1orsingle = 0,
    #[doc = "1: `1`"]
    Word4orincr = 1,
    #[doc = "2: `10`"]
    Word8 = 2,
    #[doc = "3: `11`"]
    Word16orincr4 = 3,
    #[doc = "4: `100`"]
    Word32 = 4,
    #[doc = "5: `101`"]
    Word64orincr8 = 5,
    #[doc = "6: `110`"]
    Word128 = 6,
    #[doc = "7: `111`"]
    Word256orincr16 = 7,
    #[doc = "8: `1000`"]
    Wordx = 8,
}
impl From<Hbstlen> for u8 {
    #[inline(always)]
    fn from(variant: Hbstlen) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Hbstlen {
    type Ux = u8;
}
#[doc = "Field `hbstlen` reader - Mode:Host and device. This field is used in Internal DMA modes."]
pub type HbstlenR = crate::FieldReader<Hbstlen>;
impl HbstlenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Hbstlen> {
        match self.bits {
            0 => Some(Hbstlen::Word1orsingle),
            1 => Some(Hbstlen::Word4orincr),
            2 => Some(Hbstlen::Word8),
            3 => Some(Hbstlen::Word16orincr4),
            4 => Some(Hbstlen::Word32),
            5 => Some(Hbstlen::Word64orincr8),
            6 => Some(Hbstlen::Word128),
            7 => Some(Hbstlen::Word256orincr16),
            8 => Some(Hbstlen::Wordx),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_word1orsingle(&self) -> bool {
        *self == Hbstlen::Word1orsingle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_word4orincr(&self) -> bool {
        *self == Hbstlen::Word4orincr
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_word8(&self) -> bool {
        *self == Hbstlen::Word8
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_word16orincr4(&self) -> bool {
        *self == Hbstlen::Word16orincr4
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_word32(&self) -> bool {
        *self == Hbstlen::Word32
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_word64orincr8(&self) -> bool {
        *self == Hbstlen::Word64orincr8
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_word128(&self) -> bool {
        *self == Hbstlen::Word128
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_word256orincr16(&self) -> bool {
        *self == Hbstlen::Word256orincr16
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_wordx(&self) -> bool {
        *self == Hbstlen::Wordx
    }
}
#[doc = "Field `hbstlen` writer - Mode:Host and device. This field is used in Internal DMA modes."]
pub type HbstlenW<'a, REG> = crate::FieldWriter<'a, REG, 4, Hbstlen>;
impl<'a, REG> HbstlenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn word1orsingle(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word1orsingle)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn word4orincr(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word4orincr)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn word8(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word8)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn word16orincr4(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word16orincr4)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn word32(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word32)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn word64orincr8(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word64orincr8)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn word128(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word128)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn word256orincr16(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Word256orincr16)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn wordx(self) -> &'a mut crate::W<REG> {
        self.variant(Hbstlen::Wordx)
    }
}
#[doc = "Mode:Host and device. Enables switching from DMA mode to slave mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmaen {
    #[doc = "0: `0`"]
    Slavemode = 0,
    #[doc = "1: `1`"]
    Dmamode = 1,
}
impl From<Dmaen> for bool {
    #[inline(always)]
    fn from(variant: Dmaen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dmaen` reader - Mode:Host and device. Enables switching from DMA mode to slave mode."]
pub type DmaenR = crate::BitReader<Dmaen>;
impl DmaenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dmaen {
        match self.bits {
            false => Dmaen::Slavemode,
            true => Dmaen::Dmamode,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_slavemode(&self) -> bool {
        *self == Dmaen::Slavemode
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dmamode(&self) -> bool {
        *self == Dmaen::Dmamode
    }
}
#[doc = "Field `dmaen` writer - Mode:Host and device. Enables switching from DMA mode to slave mode."]
pub type DmaenW<'a, REG> = crate::BitWriter<'a, REG, Dmaen>;
impl<'a, REG> DmaenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn slavemode(self) -> &'a mut crate::W<REG> {
        self.variant(Dmaen::Slavemode)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dmamode(self) -> &'a mut crate::W<REG> {
        self.variant(Dmaen::Dmamode)
    }
}
#[doc = "Mode:Host and device. This bit is used only in Slave mode. In host mode and with Shared FIFO with device mode, this bit indicates when the Non-Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.NPTxFEmp) is triggered. With dedicated FIFO in device mode, this bit indicates when IN endpoint Transmit FIFO empty interrupt (DIEPINTn.TxFEmp) is triggered. Host mode and with Shared FIFO with device mode:\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nptxfemplvl {
    #[doc = "0: `0`"]
    Halfempty = 0,
    #[doc = "1: `1`"]
    Empty = 1,
}
impl From<Nptxfemplvl> for bool {
    #[inline(always)]
    fn from(variant: Nptxfemplvl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nptxfemplvl` reader - Mode:Host and device. This bit is used only in Slave mode. In host mode and with Shared FIFO with device mode, this bit indicates when the Non-Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.NPTxFEmp) is triggered. With dedicated FIFO in device mode, this bit indicates when IN endpoint Transmit FIFO empty interrupt (DIEPINTn.TxFEmp) is triggered. Host mode and with Shared FIFO with device mode:"]
pub type NptxfemplvlR = crate::BitReader<Nptxfemplvl>;
impl NptxfemplvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nptxfemplvl {
        match self.bits {
            false => Nptxfemplvl::Halfempty,
            true => Nptxfemplvl::Empty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_halfempty(&self) -> bool {
        *self == Nptxfemplvl::Halfempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Nptxfemplvl::Empty
    }
}
#[doc = "Field `nptxfemplvl` writer - Mode:Host and device. This bit is used only in Slave mode. In host mode and with Shared FIFO with device mode, this bit indicates when the Non-Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.NPTxFEmp) is triggered. With dedicated FIFO in device mode, this bit indicates when IN endpoint Transmit FIFO empty interrupt (DIEPINTn.TxFEmp) is triggered. Host mode and with Shared FIFO with device mode:"]
pub type NptxfemplvlW<'a, REG> = crate::BitWriter<'a, REG, Nptxfemplvl>;
impl<'a, REG> NptxfemplvlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn halfempty(self) -> &'a mut crate::W<REG> {
        self.variant(Nptxfemplvl::Halfempty)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn empty(self) -> &'a mut crate::W<REG> {
        self.variant(Nptxfemplvl::Empty)
    }
}
#[doc = "Mode:Host only. Indicates when the Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.PTxFEmp) is triggered. This bit is used only in Slave mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ptxfemplvl {
    #[doc = "0: `0`"]
    Halfempty = 0,
    #[doc = "1: `1`"]
    Empty = 1,
}
impl From<Ptxfemplvl> for bool {
    #[inline(always)]
    fn from(variant: Ptxfemplvl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ptxfemplvl` reader - Mode:Host only. Indicates when the Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.PTxFEmp) is triggered. This bit is used only in Slave mode."]
pub type PtxfemplvlR = crate::BitReader<Ptxfemplvl>;
impl PtxfemplvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ptxfemplvl {
        match self.bits {
            false => Ptxfemplvl::Halfempty,
            true => Ptxfemplvl::Empty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_halfempty(&self) -> bool {
        *self == Ptxfemplvl::Halfempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Ptxfemplvl::Empty
    }
}
#[doc = "Field `ptxfemplvl` writer - Mode:Host only. Indicates when the Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.PTxFEmp) is triggered. This bit is used only in Slave mode."]
pub type PtxfemplvlW<'a, REG> = crate::BitWriter<'a, REG, Ptxfemplvl>;
impl<'a, REG> PtxfemplvlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn halfempty(self) -> &'a mut crate::W<REG> {
        self.variant(Ptxfemplvl::Halfempty)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn empty(self) -> &'a mut crate::W<REG> {
        self.variant(Ptxfemplvl::Empty)
    }
}
#[doc = "This bit is programmed to enable/disable the functionality to wait for the system DMA Done Signal for the DMA Write Transfers. -The int_dma_req output signal is asserted when HSOTG DMA starts write transfer to the external memory. When the core is done with the Transfers it asserts int_dma_done signal to flag the completion of DMA writes from HSOTG. The core then waits for sys_dma_done signal from the system to proceed further and complete the Data Transfer corresponding to a particular Channel/Endpoint. -The int_dma_req and int_dma_done signals are not asserted and the core proceeds with the assertion of the XferComp interrupt as soon as wait for the system DMA Done Signal for the DMA Write Transfers the DMA write transfer is done at the HSOTG Core Boundary and it doesn't wait for the sys_dma_done signal to complete the DATA\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remmemsupp {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Remmemsupp> for bool {
    #[inline(always)]
    fn from(variant: Remmemsupp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `remmemsupp` reader - This bit is programmed to enable/disable the functionality to wait for the system DMA Done Signal for the DMA Write Transfers. -The int_dma_req output signal is asserted when HSOTG DMA starts write transfer to the external memory. When the core is done with the Transfers it asserts int_dma_done signal to flag the completion of DMA writes from HSOTG. The core then waits for sys_dma_done signal from the system to proceed further and complete the Data Transfer corresponding to a particular Channel/Endpoint. -The int_dma_req and int_dma_done signals are not asserted and the core proceeds with the assertion of the XferComp interrupt as soon as wait for the system DMA Done Signal for the DMA Write Transfers the DMA write transfer is done at the HSOTG Core Boundary and it doesn't wait for the sys_dma_done signal to complete the DATA"]
pub type RemmemsuppR = crate::BitReader<Remmemsupp>;
impl RemmemsuppR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Remmemsupp {
        match self.bits {
            false => Remmemsupp::Disabled,
            true => Remmemsupp::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Remmemsupp::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Remmemsupp::Enabled
    }
}
#[doc = "Field `remmemsupp` writer - This bit is programmed to enable/disable the functionality to wait for the system DMA Done Signal for the DMA Write Transfers. -The int_dma_req output signal is asserted when HSOTG DMA starts write transfer to the external memory. When the core is done with the Transfers it asserts int_dma_done signal to flag the completion of DMA writes from HSOTG. The core then waits for sys_dma_done signal from the system to proceed further and complete the Data Transfer corresponding to a particular Channel/Endpoint. -The int_dma_req and int_dma_done signals are not asserted and the core proceeds with the assertion of the XferComp interrupt as soon as wait for the system DMA Done Signal for the DMA Write Transfers the DMA write transfer is done at the HSOTG Core Boundary and it doesn't wait for the sys_dma_done signal to complete the DATA"]
pub type RemmemsuppW<'a, REG> = crate::BitWriter<'a, REG, Remmemsupp>;
impl<'a, REG> RemmemsuppW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Remmemsupp::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Remmemsupp::Enabled)
    }
}
#[doc = "This bit is programmed to enable the System DMA Done functionality for all the DMA write Transactions corresponding to the Channel/Endpoint. This bit is valid only when GAHBCFG.RemMemSupp is set to 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notialldmawrit {
    #[doc = "1: `1`"]
    Alltrans = 1,
    #[doc = "0: `0`"]
    Lasttrans = 0,
}
impl From<Notialldmawrit> for bool {
    #[inline(always)]
    fn from(variant: Notialldmawrit) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `notialldmawrit` reader - This bit is programmed to enable the System DMA Done functionality for all the DMA write Transactions corresponding to the Channel/Endpoint. This bit is valid only when GAHBCFG.RemMemSupp is set to 1."]
pub type NotialldmawritR = crate::BitReader<Notialldmawrit>;
impl NotialldmawritR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Notialldmawrit {
        match self.bits {
            true => Notialldmawrit::Alltrans,
            false => Notialldmawrit::Lasttrans,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_alltrans(&self) -> bool {
        *self == Notialldmawrit::Alltrans
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_lasttrans(&self) -> bool {
        *self == Notialldmawrit::Lasttrans
    }
}
#[doc = "Field `notialldmawrit` writer - This bit is programmed to enable the System DMA Done functionality for all the DMA write Transactions corresponding to the Channel/Endpoint. This bit is valid only when GAHBCFG.RemMemSupp is set to 1."]
pub type NotialldmawritW<'a, REG> = crate::BitWriter<'a, REG, Notialldmawrit>;
impl<'a, REG> NotialldmawritW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn alltrans(self) -> &'a mut crate::W<REG> {
        self.variant(Notialldmawrit::Alltrans)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn lasttrans(self) -> &'a mut crate::W<REG> {
        self.variant(Notialldmawrit::Lasttrans)
    }
}
impl R {
    #[doc = "Bit 0 - Mode: Host and device. The application uses this bit to mask or unmask the interrupt line assertion to itself. Irrespective of this bits setting, the interrupt status registers are updated by the core."]
    #[inline(always)]
    pub fn glblintrmsk(&self) -> GlblintrmskR {
        GlblintrmskR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:4 - Mode:Host and device. This field is used in Internal DMA modes."]
    #[inline(always)]
    pub fn hbstlen(&self) -> HbstlenR {
        HbstlenR::new(((self.bits >> 1) & 0x0f) as u8)
    }
    #[doc = "Bit 5 - Mode:Host and device. Enables switching from DMA mode to slave mode."]
    #[inline(always)]
    pub fn dmaen(&self) -> DmaenR {
        DmaenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 7 - Mode:Host and device. This bit is used only in Slave mode. In host mode and with Shared FIFO with device mode, this bit indicates when the Non-Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.NPTxFEmp) is triggered. With dedicated FIFO in device mode, this bit indicates when IN endpoint Transmit FIFO empty interrupt (DIEPINTn.TxFEmp) is triggered. Host mode and with Shared FIFO with device mode:"]
    #[inline(always)]
    pub fn nptxfemplvl(&self) -> NptxfemplvlR {
        NptxfemplvlR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Mode:Host only. Indicates when the Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.PTxFEmp) is triggered. This bit is used only in Slave mode."]
    #[inline(always)]
    pub fn ptxfemplvl(&self) -> PtxfemplvlR {
        PtxfemplvlR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 21 - This bit is programmed to enable/disable the functionality to wait for the system DMA Done Signal for the DMA Write Transfers. -The int_dma_req output signal is asserted when HSOTG DMA starts write transfer to the external memory. When the core is done with the Transfers it asserts int_dma_done signal to flag the completion of DMA writes from HSOTG. The core then waits for sys_dma_done signal from the system to proceed further and complete the Data Transfer corresponding to a particular Channel/Endpoint. -The int_dma_req and int_dma_done signals are not asserted and the core proceeds with the assertion of the XferComp interrupt as soon as wait for the system DMA Done Signal for the DMA Write Transfers the DMA write transfer is done at the HSOTG Core Boundary and it doesn't wait for the sys_dma_done signal to complete the DATA"]
    #[inline(always)]
    pub fn remmemsupp(&self) -> RemmemsuppR {
        RemmemsuppR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - This bit is programmed to enable the System DMA Done functionality for all the DMA write Transactions corresponding to the Channel/Endpoint. This bit is valid only when GAHBCFG.RemMemSupp is set to 1."]
    #[inline(always)]
    pub fn notialldmawrit(&self) -> NotialldmawritR {
        NotialldmawritR::new(((self.bits >> 22) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Mode: Host and device. The application uses this bit to mask or unmask the interrupt line assertion to itself. Irrespective of this bits setting, the interrupt status registers are updated by the core."]
    #[inline(always)]
    #[must_use]
    pub fn glblintrmsk(&mut self) -> GlblintrmskW<GlobgrpGahbcfgSpec> {
        GlblintrmskW::new(self, 0)
    }
    #[doc = "Bits 1:4 - Mode:Host and device. This field is used in Internal DMA modes."]
    #[inline(always)]
    #[must_use]
    pub fn hbstlen(&mut self) -> HbstlenW<GlobgrpGahbcfgSpec> {
        HbstlenW::new(self, 1)
    }
    #[doc = "Bit 5 - Mode:Host and device. Enables switching from DMA mode to slave mode."]
    #[inline(always)]
    #[must_use]
    pub fn dmaen(&mut self) -> DmaenW<GlobgrpGahbcfgSpec> {
        DmaenW::new(self, 5)
    }
    #[doc = "Bit 7 - Mode:Host and device. This bit is used only in Slave mode. In host mode and with Shared FIFO with device mode, this bit indicates when the Non-Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.NPTxFEmp) is triggered. With dedicated FIFO in device mode, this bit indicates when IN endpoint Transmit FIFO empty interrupt (DIEPINTn.TxFEmp) is triggered. Host mode and with Shared FIFO with device mode:"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfemplvl(&mut self) -> NptxfemplvlW<GlobgrpGahbcfgSpec> {
        NptxfemplvlW::new(self, 7)
    }
    #[doc = "Bit 8 - Mode:Host only. Indicates when the Periodic TxFIFO Empty Interrupt bit in the Core Interrupt register (GINTSTS.PTxFEmp) is triggered. This bit is used only in Slave mode."]
    #[inline(always)]
    #[must_use]
    pub fn ptxfemplvl(&mut self) -> PtxfemplvlW<GlobgrpGahbcfgSpec> {
        PtxfemplvlW::new(self, 8)
    }
    #[doc = "Bit 21 - This bit is programmed to enable/disable the functionality to wait for the system DMA Done Signal for the DMA Write Transfers. -The int_dma_req output signal is asserted when HSOTG DMA starts write transfer to the external memory. When the core is done with the Transfers it asserts int_dma_done signal to flag the completion of DMA writes from HSOTG. The core then waits for sys_dma_done signal from the system to proceed further and complete the Data Transfer corresponding to a particular Channel/Endpoint. -The int_dma_req and int_dma_done signals are not asserted and the core proceeds with the assertion of the XferComp interrupt as soon as wait for the system DMA Done Signal for the DMA Write Transfers the DMA write transfer is done at the HSOTG Core Boundary and it doesn't wait for the sys_dma_done signal to complete the DATA"]
    #[inline(always)]
    #[must_use]
    pub fn remmemsupp(&mut self) -> RemmemsuppW<GlobgrpGahbcfgSpec> {
        RemmemsuppW::new(self, 21)
    }
    #[doc = "Bit 22 - This bit is programmed to enable the System DMA Done functionality for all the DMA write Transactions corresponding to the Channel/Endpoint. This bit is valid only when GAHBCFG.RemMemSupp is set to 1."]
    #[inline(always)]
    #[must_use]
    pub fn notialldmawrit(&mut self) -> NotialldmawritW<GlobgrpGahbcfgSpec> {
        NotialldmawritW::new(self, 22)
    }
}
#[doc = "This register can be used to configure the core after power-on or a change in mode. This register mainly contains AHB system-related configuration parameters. Do not change this register after the initial programming. The application must program this register before starting any transactions on either the AHB or the USB.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gahbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gahbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGahbcfgSpec;
impl crate::RegisterSpec for GlobgrpGahbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`globgrp_gahbcfg::R`](R) reader structure"]
impl crate::Readable for GlobgrpGahbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gahbcfg::W`](W) writer structure"]
impl crate::Writable for GlobgrpGahbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gahbcfg to value 0"]
impl crate::Resettable for GlobgrpGahbcfgSpec {
    const RESET_VALUE: u32 = 0;
}
