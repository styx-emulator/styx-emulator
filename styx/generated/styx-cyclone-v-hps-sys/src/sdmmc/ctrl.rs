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
#[doc = "Register `ctrl` reader"]
pub type R = crate::R<CtrlSpec>;
#[doc = "Register `ctrl` writer"]
pub type W = crate::W<CtrlSpec>;
#[doc = "This bit resets the controller. This bit is auto-cleared after two l4_mp_clk and two sdmmc_clk clock cycles. This resets: - BIU/CIU interface - CIU and state machines - abort_read_data, send_irq_response, and read_wait bits of control register -start_cmd bit of command register Does not affect any registers, DMA interface, FIFO or host interrupts.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerReset {
    #[doc = "0: `0`"]
    Nochange = 0,
    #[doc = "1: `1`"]
    Activate = 1,
}
impl From<ControllerReset> for bool {
    #[inline(always)]
    fn from(variant: ControllerReset) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `controller_reset` reader - This bit resets the controller. This bit is auto-cleared after two l4_mp_clk and two sdmmc_clk clock cycles. This resets: - BIU/CIU interface - CIU and state machines - abort_read_data, send_irq_response, and read_wait bits of control register -start_cmd bit of command register Does not affect any registers, DMA interface, FIFO or host interrupts."]
pub type ControllerResetR = crate::BitReader<ControllerReset>;
impl ControllerResetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ControllerReset {
        match self.bits {
            false => ControllerReset::Nochange,
            true => ControllerReset::Activate,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochange(&self) -> bool {
        *self == ControllerReset::Nochange
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_activate(&self) -> bool {
        *self == ControllerReset::Activate
    }
}
#[doc = "Field `controller_reset` writer - This bit resets the controller. This bit is auto-cleared after two l4_mp_clk and two sdmmc_clk clock cycles. This resets: - BIU/CIU interface - CIU and state machines - abort_read_data, send_irq_response, and read_wait bits of control register -start_cmd bit of command register Does not affect any registers, DMA interface, FIFO or host interrupts."]
pub type ControllerResetW<'a, REG> = crate::BitWriter<'a, REG, ControllerReset>;
impl<'a, REG> ControllerResetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nochange(self) -> &'a mut crate::W<REG> {
        self.variant(ControllerReset::Nochange)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn activate(self) -> &'a mut crate::W<REG> {
        self.variant(ControllerReset::Activate)
    }
}
#[doc = "This bit resets the FIFO. This bit is auto-cleared after completion of reset operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoReset {
    #[doc = "0: `0`"]
    Nochange = 0,
    #[doc = "1: `1`"]
    Activate = 1,
}
impl From<FifoReset> for bool {
    #[inline(always)]
    fn from(variant: FifoReset) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_reset` reader - This bit resets the FIFO. This bit is auto-cleared after completion of reset operation."]
pub type FifoResetR = crate::BitReader<FifoReset>;
impl FifoResetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> FifoReset {
        match self.bits {
            false => FifoReset::Nochange,
            true => FifoReset::Activate,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochange(&self) -> bool {
        *self == FifoReset::Nochange
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_activate(&self) -> bool {
        *self == FifoReset::Activate
    }
}
#[doc = "Field `fifo_reset` writer - This bit resets the FIFO. This bit is auto-cleared after completion of reset operation."]
pub type FifoResetW<'a, REG> = crate::BitWriter<'a, REG, FifoReset>;
impl<'a, REG> FifoResetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nochange(self) -> &'a mut crate::W<REG> {
        self.variant(FifoReset::Nochange)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn activate(self) -> &'a mut crate::W<REG> {
        self.variant(FifoReset::Activate)
    }
}
#[doc = "This bit resets the DMA interface control logic\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaReset {
    #[doc = "0: `0`"]
    Nochange = 0,
    #[doc = "1: `1`"]
    Activate = 1,
}
impl From<DmaReset> for bool {
    #[inline(always)]
    fn from(variant: DmaReset) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dma_reset` reader - This bit resets the DMA interface control logic"]
pub type DmaResetR = crate::BitReader<DmaReset>;
impl DmaResetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DmaReset {
        match self.bits {
            false => DmaReset::Nochange,
            true => DmaReset::Activate,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochange(&self) -> bool {
        *self == DmaReset::Nochange
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_activate(&self) -> bool {
        *self == DmaReset::Activate
    }
}
#[doc = "Field `dma_reset` writer - This bit resets the DMA interface control logic"]
pub type DmaResetW<'a, REG> = crate::BitWriter<'a, REG, DmaReset>;
impl<'a, REG> DmaResetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nochange(self) -> &'a mut crate::W<REG> {
        self.variant(DmaReset::Nochange)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn activate(self) -> &'a mut crate::W<REG> {
        self.variant(DmaReset::Activate)
    }
}
#[doc = "This bit enables and disable interrupts if one or more unmasked interrupts are set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntEnable {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<IntEnable> for bool {
    #[inline(always)]
    fn from(variant: IntEnable) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `int_enable` reader - This bit enables and disable interrupts if one or more unmasked interrupts are set."]
pub type IntEnableR = crate::BitReader<IntEnable>;
impl IntEnableR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntEnable {
        match self.bits {
            false => IntEnable::Disabled,
            true => IntEnable::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == IntEnable::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == IntEnable::Enabled
    }
}
#[doc = "Field `int_enable` writer - This bit enables and disable interrupts if one or more unmasked interrupts are set."]
pub type IntEnableW<'a, REG> = crate::BitWriter<'a, REG, IntEnable>;
impl<'a, REG> IntEnableW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(IntEnable::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(IntEnable::Enabled)
    }
}
#[doc = "For sending read-wait to SDIO cards.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadWait {
    #[doc = "0: `0`"]
    Deassert = 0,
    #[doc = "1: `1`"]
    Assert = 1,
}
impl From<ReadWait> for bool {
    #[inline(always)]
    fn from(variant: ReadWait) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `read_wait` reader - For sending read-wait to SDIO cards."]
pub type ReadWaitR = crate::BitReader<ReadWait>;
impl ReadWaitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ReadWait {
        match self.bits {
            false => ReadWait::Deassert,
            true => ReadWait::Assert,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_deassert(&self) -> bool {
        *self == ReadWait::Deassert
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_assert(&self) -> bool {
        *self == ReadWait::Assert
    }
}
#[doc = "Field `read_wait` writer - For sending read-wait to SDIO cards."]
pub type ReadWaitW<'a, REG> = crate::BitWriter<'a, REG, ReadWait>;
impl<'a, REG> ReadWaitW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn deassert(self) -> &'a mut crate::W<REG> {
        self.variant(ReadWait::Deassert)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn assert(self) -> &'a mut crate::W<REG> {
        self.variant(ReadWait::Assert)
    }
}
#[doc = "Bit automatically clears once response is sent. To wait for MMC card interrupts, host issues CMD40, and SD/MMC waits for interrupt response from MMC card(s). In meantime, if host wants SD/MMC to exit waiting for interrupt state, it can set this bit, at which time SD/MMC command state-machine sends CMD40 response on bus and returns to idle state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendIrqResponse {
    #[doc = "0: `0`"]
    Nochange = 0,
    #[doc = "1: `1`"]
    Activate = 1,
}
impl From<SendIrqResponse> for bool {
    #[inline(always)]
    fn from(variant: SendIrqResponse) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `send_irq_response` reader - Bit automatically clears once response is sent. To wait for MMC card interrupts, host issues CMD40, and SD/MMC waits for interrupt response from MMC card(s). In meantime, if host wants SD/MMC to exit waiting for interrupt state, it can set this bit, at which time SD/MMC command state-machine sends CMD40 response on bus and returns to idle state."]
pub type SendIrqResponseR = crate::BitReader<SendIrqResponse>;
impl SendIrqResponseR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SendIrqResponse {
        match self.bits {
            false => SendIrqResponse::Nochange,
            true => SendIrqResponse::Activate,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochange(&self) -> bool {
        *self == SendIrqResponse::Nochange
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_activate(&self) -> bool {
        *self == SendIrqResponse::Activate
    }
}
#[doc = "Field `send_irq_response` writer - Bit automatically clears once response is sent. To wait for MMC card interrupts, host issues CMD40, and SD/MMC waits for interrupt response from MMC card(s). In meantime, if host wants SD/MMC to exit waiting for interrupt state, it can set this bit, at which time SD/MMC command state-machine sends CMD40 response on bus and returns to idle state."]
pub type SendIrqResponseW<'a, REG> = crate::BitWriter<'a, REG, SendIrqResponse>;
impl<'a, REG> SendIrqResponseW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nochange(self) -> &'a mut crate::W<REG> {
        self.variant(SendIrqResponse::Nochange)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn activate(self) -> &'a mut crate::W<REG> {
        self.variant(SendIrqResponse::Activate)
    }
}
#[doc = "After suspend command is issued during read-transfer, software polls card to find when suspend happened. Once suspend occurs software sets bit to reset data state-machine, which is waiting for next block of data. Bit automatically clears once data statemachine resets to idle. Used in SDIO card suspend sequence.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReadData {
    #[doc = "0: `0`"]
    Nochange = 0,
    #[doc = "1: `1`"]
    Activate = 1,
}
impl From<AbortReadData> for bool {
    #[inline(always)]
    fn from(variant: AbortReadData) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `abort_read_data` reader - After suspend command is issued during read-transfer, software polls card to find when suspend happened. Once suspend occurs software sets bit to reset data state-machine, which is waiting for next block of data. Bit automatically clears once data statemachine resets to idle. Used in SDIO card suspend sequence."]
pub type AbortReadDataR = crate::BitReader<AbortReadData>;
impl AbortReadDataR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> AbortReadData {
        match self.bits {
            false => AbortReadData::Nochange,
            true => AbortReadData::Activate,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochange(&self) -> bool {
        *self == AbortReadData::Nochange
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_activate(&self) -> bool {
        *self == AbortReadData::Activate
    }
}
#[doc = "Field `abort_read_data` writer - After suspend command is issued during read-transfer, software polls card to find when suspend happened. Once suspend occurs software sets bit to reset data state-machine, which is waiting for next block of data. Bit automatically clears once data statemachine resets to idle. Used in SDIO card suspend sequence."]
pub type AbortReadDataW<'a, REG> = crate::BitWriter<'a, REG, AbortReadData>;
impl<'a, REG> AbortReadDataW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nochange(self) -> &'a mut crate::W<REG> {
        self.variant(AbortReadData::Nochange)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn activate(self) -> &'a mut crate::W<REG> {
        self.variant(AbortReadData::Activate)
    }
}
#[doc = "When set, SD/MMC sends CCSD to CE-ATA device. Software sets this bit only if current command is expecting CCS (that is, RW_BLK) and interrupts are enabled in CE-ATA device. Once the CCSD pattern is sent to device, SD/MMC automatically clears send_ccsd bit. It also sets Command Done (CD) bit in RINTSTS register and generates interrupt to host if Command Done interrupt is not masked. NOTE: Once send_ccsd bit is set, it takes two card clock cycles to drive the CCSD on the CMD line. Due to this, during the boundary conditions it may happen that CCSD is sent to the CE-ATA device, even if the device signalled CCS.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendCcsd {
    #[doc = "0: `0`"]
    Deassert = 0,
    #[doc = "1: `1`"]
    Assert = 1,
}
impl From<SendCcsd> for bool {
    #[inline(always)]
    fn from(variant: SendCcsd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `send_ccsd` reader - When set, SD/MMC sends CCSD to CE-ATA device. Software sets this bit only if current command is expecting CCS (that is, RW_BLK) and interrupts are enabled in CE-ATA device. Once the CCSD pattern is sent to device, SD/MMC automatically clears send_ccsd bit. It also sets Command Done (CD) bit in RINTSTS register and generates interrupt to host if Command Done interrupt is not masked. NOTE: Once send_ccsd bit is set, it takes two card clock cycles to drive the CCSD on the CMD line. Due to this, during the boundary conditions it may happen that CCSD is sent to the CE-ATA device, even if the device signalled CCS."]
pub type SendCcsdR = crate::BitReader<SendCcsd>;
impl SendCcsdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SendCcsd {
        match self.bits {
            false => SendCcsd::Deassert,
            true => SendCcsd::Assert,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_deassert(&self) -> bool {
        *self == SendCcsd::Deassert
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_assert(&self) -> bool {
        *self == SendCcsd::Assert
    }
}
#[doc = "Field `send_ccsd` writer - When set, SD/MMC sends CCSD to CE-ATA device. Software sets this bit only if current command is expecting CCS (that is, RW_BLK) and interrupts are enabled in CE-ATA device. Once the CCSD pattern is sent to device, SD/MMC automatically clears send_ccsd bit. It also sets Command Done (CD) bit in RINTSTS register and generates interrupt to host if Command Done interrupt is not masked. NOTE: Once send_ccsd bit is set, it takes two card clock cycles to drive the CCSD on the CMD line. Due to this, during the boundary conditions it may happen that CCSD is sent to the CE-ATA device, even if the device signalled CCS."]
pub type SendCcsdW<'a, REG> = crate::BitWriter<'a, REG, SendCcsd>;
impl<'a, REG> SendCcsdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn deassert(self) -> &'a mut crate::W<REG> {
        self.variant(SendCcsd::Deassert)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn assert(self) -> &'a mut crate::W<REG> {
        self.variant(SendCcsd::Assert)
    }
}
#[doc = "Always set send_auto_stop_ccsd and send_ccsd bits together; send_auto_stop_ccsd should not be set independent of send_ccsd. When set, SD/MMC automatically sends internally generated STOP command (CMD12) to CE-ATA device. After sending internally-generated STOP command, Auto Command Done (ACD) bit in RINTSTS is set and generates interrupt to host if Auto CommandDone interrupt is not masked. After sending the CCSD, SD/MMC automatically clears send_auto_stop_ccsd bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendAutoStopCcsd {
    #[doc = "0: `0`"]
    Deassert = 0,
    #[doc = "1: `1`"]
    Assert = 1,
}
impl From<SendAutoStopCcsd> for bool {
    #[inline(always)]
    fn from(variant: SendAutoStopCcsd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `send_auto_stop_ccsd` reader - Always set send_auto_stop_ccsd and send_ccsd bits together; send_auto_stop_ccsd should not be set independent of send_ccsd. When set, SD/MMC automatically sends internally generated STOP command (CMD12) to CE-ATA device. After sending internally-generated STOP command, Auto Command Done (ACD) bit in RINTSTS is set and generates interrupt to host if Auto CommandDone interrupt is not masked. After sending the CCSD, SD/MMC automatically clears send_auto_stop_ccsd bit."]
pub type SendAutoStopCcsdR = crate::BitReader<SendAutoStopCcsd>;
impl SendAutoStopCcsdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SendAutoStopCcsd {
        match self.bits {
            false => SendAutoStopCcsd::Deassert,
            true => SendAutoStopCcsd::Assert,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_deassert(&self) -> bool {
        *self == SendAutoStopCcsd::Deassert
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_assert(&self) -> bool {
        *self == SendAutoStopCcsd::Assert
    }
}
#[doc = "Field `send_auto_stop_ccsd` writer - Always set send_auto_stop_ccsd and send_ccsd bits together; send_auto_stop_ccsd should not be set independent of send_ccsd. When set, SD/MMC automatically sends internally generated STOP command (CMD12) to CE-ATA device. After sending internally-generated STOP command, Auto Command Done (ACD) bit in RINTSTS is set and generates interrupt to host if Auto CommandDone interrupt is not masked. After sending the CCSD, SD/MMC automatically clears send_auto_stop_ccsd bit."]
pub type SendAutoStopCcsdW<'a, REG> = crate::BitWriter<'a, REG, SendAutoStopCcsd>;
impl<'a, REG> SendAutoStopCcsdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn deassert(self) -> &'a mut crate::W<REG> {
        self.variant(SendAutoStopCcsd::Deassert)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn assert(self) -> &'a mut crate::W<REG> {
        self.variant(SendAutoStopCcsd::Assert)
    }
}
#[doc = "Software should appropriately write to this bit after power-on reset or any other reset to CE-ATA device. After reset, usually CE-ATA device interrupt is disabled (nIEN = 1). If the host enables CE-ATA device interrupt, then software should set this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeataDeviceInterruptStatus {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<CeataDeviceInterruptStatus> for bool {
    #[inline(always)]
    fn from(variant: CeataDeviceInterruptStatus) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ceata_device_interrupt_status` reader - Software should appropriately write to this bit after power-on reset or any other reset to CE-ATA device. After reset, usually CE-ATA device interrupt is disabled (nIEN = 1). If the host enables CE-ATA device interrupt, then software should set this bit."]
pub type CeataDeviceInterruptStatusR = crate::BitReader<CeataDeviceInterruptStatus>;
impl CeataDeviceInterruptStatusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CeataDeviceInterruptStatus {
        match self.bits {
            false => CeataDeviceInterruptStatus::Disabled,
            true => CeataDeviceInterruptStatus::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == CeataDeviceInterruptStatus::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == CeataDeviceInterruptStatus::Enabled
    }
}
#[doc = "Field `ceata_device_interrupt_status` writer - Software should appropriately write to this bit after power-on reset or any other reset to CE-ATA device. After reset, usually CE-ATA device interrupt is disabled (nIEN = 1). If the host enables CE-ATA device interrupt, then software should set this bit."]
pub type CeataDeviceInterruptStatusW<'a, REG> =
    crate::BitWriter<'a, REG, CeataDeviceInterruptStatus>;
impl<'a, REG> CeataDeviceInterruptStatusW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(CeataDeviceInterruptStatus::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(CeataDeviceInterruptStatus::Enabled)
    }
}
#[doc = "Enable and Disable Internal DMA transfers.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UseInternalDmac {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<UseInternalDmac> for bool {
    #[inline(always)]
    fn from(variant: UseInternalDmac) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `use_internal_dmac` reader - Enable and Disable Internal DMA transfers."]
pub type UseInternalDmacR = crate::BitReader<UseInternalDmac>;
impl UseInternalDmacR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> UseInternalDmac {
        match self.bits {
            false => UseInternalDmac::Disabled,
            true => UseInternalDmac::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == UseInternalDmac::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == UseInternalDmac::Enabled
    }
}
#[doc = "Field `use_internal_dmac` writer - Enable and Disable Internal DMA transfers."]
pub type UseInternalDmacW<'a, REG> = crate::BitWriter<'a, REG, UseInternalDmac>;
impl<'a, REG> UseInternalDmacW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(UseInternalDmac::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(UseInternalDmac::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This bit resets the controller. This bit is auto-cleared after two l4_mp_clk and two sdmmc_clk clock cycles. This resets: - BIU/CIU interface - CIU and state machines - abort_read_data, send_irq_response, and read_wait bits of control register -start_cmd bit of command register Does not affect any registers, DMA interface, FIFO or host interrupts."]
    #[inline(always)]
    pub fn controller_reset(&self) -> ControllerResetR {
        ControllerResetR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit resets the FIFO. This bit is auto-cleared after completion of reset operation."]
    #[inline(always)]
    pub fn fifo_reset(&self) -> FifoResetR {
        FifoResetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit resets the DMA interface control logic"]
    #[inline(always)]
    pub fn dma_reset(&self) -> DmaResetR {
        DmaResetR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit enables and disable interrupts if one or more unmasked interrupts are set."]
    #[inline(always)]
    pub fn int_enable(&self) -> IntEnableR {
        IntEnableR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - For sending read-wait to SDIO cards."]
    #[inline(always)]
    pub fn read_wait(&self) -> ReadWaitR {
        ReadWaitR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Bit automatically clears once response is sent. To wait for MMC card interrupts, host issues CMD40, and SD/MMC waits for interrupt response from MMC card(s). In meantime, if host wants SD/MMC to exit waiting for interrupt state, it can set this bit, at which time SD/MMC command state-machine sends CMD40 response on bus and returns to idle state."]
    #[inline(always)]
    pub fn send_irq_response(&self) -> SendIrqResponseR {
        SendIrqResponseR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - After suspend command is issued during read-transfer, software polls card to find when suspend happened. Once suspend occurs software sets bit to reset data state-machine, which is waiting for next block of data. Bit automatically clears once data statemachine resets to idle. Used in SDIO card suspend sequence."]
    #[inline(always)]
    pub fn abort_read_data(&self) -> AbortReadDataR {
        AbortReadDataR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - When set, SD/MMC sends CCSD to CE-ATA device. Software sets this bit only if current command is expecting CCS (that is, RW_BLK) and interrupts are enabled in CE-ATA device. Once the CCSD pattern is sent to device, SD/MMC automatically clears send_ccsd bit. It also sets Command Done (CD) bit in RINTSTS register and generates interrupt to host if Command Done interrupt is not masked. NOTE: Once send_ccsd bit is set, it takes two card clock cycles to drive the CCSD on the CMD line. Due to this, during the boundary conditions it may happen that CCSD is sent to the CE-ATA device, even if the device signalled CCS."]
    #[inline(always)]
    pub fn send_ccsd(&self) -> SendCcsdR {
        SendCcsdR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Always set send_auto_stop_ccsd and send_ccsd bits together; send_auto_stop_ccsd should not be set independent of send_ccsd. When set, SD/MMC automatically sends internally generated STOP command (CMD12) to CE-ATA device. After sending internally-generated STOP command, Auto Command Done (ACD) bit in RINTSTS is set and generates interrupt to host if Auto CommandDone interrupt is not masked. After sending the CCSD, SD/MMC automatically clears send_auto_stop_ccsd bit."]
    #[inline(always)]
    pub fn send_auto_stop_ccsd(&self) -> SendAutoStopCcsdR {
        SendAutoStopCcsdR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Software should appropriately write to this bit after power-on reset or any other reset to CE-ATA device. After reset, usually CE-ATA device interrupt is disabled (nIEN = 1). If the host enables CE-ATA device interrupt, then software should set this bit."]
    #[inline(always)]
    pub fn ceata_device_interrupt_status(&self) -> CeataDeviceInterruptStatusR {
        CeataDeviceInterruptStatusR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 25 - Enable and Disable Internal DMA transfers."]
    #[inline(always)]
    pub fn use_internal_dmac(&self) -> UseInternalDmacR {
        UseInternalDmacR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit resets the controller. This bit is auto-cleared after two l4_mp_clk and two sdmmc_clk clock cycles. This resets: - BIU/CIU interface - CIU and state machines - abort_read_data, send_irq_response, and read_wait bits of control register -start_cmd bit of command register Does not affect any registers, DMA interface, FIFO or host interrupts."]
    #[inline(always)]
    #[must_use]
    pub fn controller_reset(&mut self) -> ControllerResetW<CtrlSpec> {
        ControllerResetW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit resets the FIFO. This bit is auto-cleared after completion of reset operation."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_reset(&mut self) -> FifoResetW<CtrlSpec> {
        FifoResetW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit resets the DMA interface control logic"]
    #[inline(always)]
    #[must_use]
    pub fn dma_reset(&mut self) -> DmaResetW<CtrlSpec> {
        DmaResetW::new(self, 2)
    }
    #[doc = "Bit 4 - This bit enables and disable interrupts if one or more unmasked interrupts are set."]
    #[inline(always)]
    #[must_use]
    pub fn int_enable(&mut self) -> IntEnableW<CtrlSpec> {
        IntEnableW::new(self, 4)
    }
    #[doc = "Bit 6 - For sending read-wait to SDIO cards."]
    #[inline(always)]
    #[must_use]
    pub fn read_wait(&mut self) -> ReadWaitW<CtrlSpec> {
        ReadWaitW::new(self, 6)
    }
    #[doc = "Bit 7 - Bit automatically clears once response is sent. To wait for MMC card interrupts, host issues CMD40, and SD/MMC waits for interrupt response from MMC card(s). In meantime, if host wants SD/MMC to exit waiting for interrupt state, it can set this bit, at which time SD/MMC command state-machine sends CMD40 response on bus and returns to idle state."]
    #[inline(always)]
    #[must_use]
    pub fn send_irq_response(&mut self) -> SendIrqResponseW<CtrlSpec> {
        SendIrqResponseW::new(self, 7)
    }
    #[doc = "Bit 8 - After suspend command is issued during read-transfer, software polls card to find when suspend happened. Once suspend occurs software sets bit to reset data state-machine, which is waiting for next block of data. Bit automatically clears once data statemachine resets to idle. Used in SDIO card suspend sequence."]
    #[inline(always)]
    #[must_use]
    pub fn abort_read_data(&mut self) -> AbortReadDataW<CtrlSpec> {
        AbortReadDataW::new(self, 8)
    }
    #[doc = "Bit 9 - When set, SD/MMC sends CCSD to CE-ATA device. Software sets this bit only if current command is expecting CCS (that is, RW_BLK) and interrupts are enabled in CE-ATA device. Once the CCSD pattern is sent to device, SD/MMC automatically clears send_ccsd bit. It also sets Command Done (CD) bit in RINTSTS register and generates interrupt to host if Command Done interrupt is not masked. NOTE: Once send_ccsd bit is set, it takes two card clock cycles to drive the CCSD on the CMD line. Due to this, during the boundary conditions it may happen that CCSD is sent to the CE-ATA device, even if the device signalled CCS."]
    #[inline(always)]
    #[must_use]
    pub fn send_ccsd(&mut self) -> SendCcsdW<CtrlSpec> {
        SendCcsdW::new(self, 9)
    }
    #[doc = "Bit 10 - Always set send_auto_stop_ccsd and send_ccsd bits together; send_auto_stop_ccsd should not be set independent of send_ccsd. When set, SD/MMC automatically sends internally generated STOP command (CMD12) to CE-ATA device. After sending internally-generated STOP command, Auto Command Done (ACD) bit in RINTSTS is set and generates interrupt to host if Auto CommandDone interrupt is not masked. After sending the CCSD, SD/MMC automatically clears send_auto_stop_ccsd bit."]
    #[inline(always)]
    #[must_use]
    pub fn send_auto_stop_ccsd(&mut self) -> SendAutoStopCcsdW<CtrlSpec> {
        SendAutoStopCcsdW::new(self, 10)
    }
    #[doc = "Bit 11 - Software should appropriately write to this bit after power-on reset or any other reset to CE-ATA device. After reset, usually CE-ATA device interrupt is disabled (nIEN = 1). If the host enables CE-ATA device interrupt, then software should set this bit."]
    #[inline(always)]
    #[must_use]
    pub fn ceata_device_interrupt_status(&mut self) -> CeataDeviceInterruptStatusW<CtrlSpec> {
        CeataDeviceInterruptStatusW::new(self, 11)
    }
    #[doc = "Bit 25 - Enable and Disable Internal DMA transfers."]
    #[inline(always)]
    #[must_use]
    pub fn use_internal_dmac(&mut self) -> UseInternalDmacW<CtrlSpec> {
        UseInternalDmacW::new(self, 25)
    }
}
#[doc = "Sets various operating condiitions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlSpec;
impl crate::RegisterSpec for CtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`ctrl::R`](R) reader structure"]
impl crate::Readable for CtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrl::W`](W) writer structure"]
impl crate::Writable for CtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrl to value 0"]
impl crate::Resettable for CtrlSpec {
    const RESET_VALUE: u32 = 0;
}
