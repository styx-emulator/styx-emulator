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
#[doc = "Register `ier_dlh` reader"]
pub type R = crate::R<IerDlhSpec>;
#[doc = "Register `ier_dlh` writer"]
pub type W = crate::W<IerDlhSpec>;
#[doc = "Divisor Latch High Register: Bit 0 of DLH value. Interrupt Enable Register: Used to enable/disable the generation of the Receive Data Available Interrupt and the Character Timeout Interrupt(if FIFO's enabled). These are the second highest priority interrupts.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErbfiDlh0 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<ErbfiDlh0> for bool {
    #[inline(always)]
    fn from(variant: ErbfiDlh0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `erbfi_dlh0` reader - Divisor Latch High Register: Bit 0 of DLH value. Interrupt Enable Register: Used to enable/disable the generation of the Receive Data Available Interrupt and the Character Timeout Interrupt(if FIFO's enabled). These are the second highest priority interrupts."]
pub type ErbfiDlh0R = crate::BitReader<ErbfiDlh0>;
impl ErbfiDlh0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ErbfiDlh0 {
        match self.bits {
            false => ErbfiDlh0::Disabled,
            true => ErbfiDlh0::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == ErbfiDlh0::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == ErbfiDlh0::Enabled
    }
}
#[doc = "Field `erbfi_dlh0` writer - Divisor Latch High Register: Bit 0 of DLH value. Interrupt Enable Register: Used to enable/disable the generation of the Receive Data Available Interrupt and the Character Timeout Interrupt(if FIFO's enabled). These are the second highest priority interrupts."]
pub type ErbfiDlh0W<'a, REG> = crate::BitWriter<'a, REG, ErbfiDlh0>;
impl<'a, REG> ErbfiDlh0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(ErbfiDlh0::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(ErbfiDlh0::Enabled)
    }
}
#[doc = "Divisor Latch High Register: Bit 1 of DLH value. Interrupt Enable Register: Enable Transmit Holding Register Empty Interrupt. This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtbeiDlhl {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<EtbeiDlhl> for bool {
    #[inline(always)]
    fn from(variant: EtbeiDlhl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `etbei_dlhl` reader - Divisor Latch High Register: Bit 1 of DLH value. Interrupt Enable Register: Enable Transmit Holding Register Empty Interrupt. This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt."]
pub type EtbeiDlhlR = crate::BitReader<EtbeiDlhl>;
impl EtbeiDlhlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> EtbeiDlhl {
        match self.bits {
            false => EtbeiDlhl::Disabled,
            true => EtbeiDlhl::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == EtbeiDlhl::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == EtbeiDlhl::Enabled
    }
}
#[doc = "Field `etbei_dlhl` writer - Divisor Latch High Register: Bit 1 of DLH value. Interrupt Enable Register: Enable Transmit Holding Register Empty Interrupt. This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt."]
pub type EtbeiDlhlW<'a, REG> = crate::BitWriter<'a, REG, EtbeiDlhl>;
impl<'a, REG> EtbeiDlhlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(EtbeiDlhl::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(EtbeiDlhl::Enabled)
    }
}
#[doc = "Divisor Latch High Register: Bit 2 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Receiver Line Status Interrupt. This is the highest priority interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElsiDhl2 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<ElsiDhl2> for bool {
    #[inline(always)]
    fn from(variant: ElsiDhl2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `elsi_dhl2` reader - Divisor Latch High Register: Bit 2 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Receiver Line Status Interrupt. This is the highest priority interrupt."]
pub type ElsiDhl2R = crate::BitReader<ElsiDhl2>;
impl ElsiDhl2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ElsiDhl2 {
        match self.bits {
            false => ElsiDhl2::Disabled,
            true => ElsiDhl2::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == ElsiDhl2::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == ElsiDhl2::Enabled
    }
}
#[doc = "Field `elsi_dhl2` writer - Divisor Latch High Register: Bit 2 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Receiver Line Status Interrupt. This is the highest priority interrupt."]
pub type ElsiDhl2W<'a, REG> = crate::BitWriter<'a, REG, ElsiDhl2>;
impl<'a, REG> ElsiDhl2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(ElsiDhl2::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(ElsiDhl2::Enabled)
    }
}
#[doc = "Divisor Latch High Register: Bit 3 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Modem Status Interrupts. This is the fourth highest priority interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdssiDhl3 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<EdssiDhl3> for bool {
    #[inline(always)]
    fn from(variant: EdssiDhl3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `edssi_dhl3` reader - Divisor Latch High Register: Bit 3 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Modem Status Interrupts. This is the fourth highest priority interrupt."]
pub type EdssiDhl3R = crate::BitReader<EdssiDhl3>;
impl EdssiDhl3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> EdssiDhl3 {
        match self.bits {
            false => EdssiDhl3::Disabled,
            true => EdssiDhl3::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == EdssiDhl3::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == EdssiDhl3::Enabled
    }
}
#[doc = "Field `edssi_dhl3` writer - Divisor Latch High Register: Bit 3 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Modem Status Interrupts. This is the fourth highest priority interrupt."]
pub type EdssiDhl3W<'a, REG> = crate::BitWriter<'a, REG, EdssiDhl3>;
impl<'a, REG> EdssiDhl3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(EdssiDhl3::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(EdssiDhl3::Enabled)
    }
}
#[doc = "Field `dlh4` reader - Bit 4 of DLH value."]
pub type Dlh4R = crate::BitReader;
#[doc = "Field `dlh4` writer - Bit 4 of DLH value."]
pub type Dlh4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dlh5` reader - Bit 5 of DLH value."]
pub type Dlh5R = crate::BitReader;
#[doc = "Field `dlh5` writer - Bit 5 of DLH value."]
pub type Dlh5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dlh6` reader - Bit 6 of DLH value."]
pub type Dlh6R = crate::BitReader;
#[doc = "Field `dlh6` writer - Bit 6 of DLH value."]
pub type Dlh6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Divisor Latch High Register: Bit 7 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of THRE Interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtimeDlh7 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<PtimeDlh7> for bool {
    #[inline(always)]
    fn from(variant: PtimeDlh7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ptime_dlh7` reader - Divisor Latch High Register: Bit 7 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of THRE Interrupt."]
pub type PtimeDlh7R = crate::BitReader<PtimeDlh7>;
impl PtimeDlh7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> PtimeDlh7 {
        match self.bits {
            false => PtimeDlh7::Disabled,
            true => PtimeDlh7::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == PtimeDlh7::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == PtimeDlh7::Enabled
    }
}
#[doc = "Field `ptime_dlh7` writer - Divisor Latch High Register: Bit 7 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of THRE Interrupt."]
pub type PtimeDlh7W<'a, REG> = crate::BitWriter<'a, REG, PtimeDlh7>;
impl<'a, REG> PtimeDlh7W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(PtimeDlh7::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(PtimeDlh7::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Divisor Latch High Register: Bit 0 of DLH value. Interrupt Enable Register: Used to enable/disable the generation of the Receive Data Available Interrupt and the Character Timeout Interrupt(if FIFO's enabled). These are the second highest priority interrupts."]
    #[inline(always)]
    pub fn erbfi_dlh0(&self) -> ErbfiDlh0R {
        ErbfiDlh0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Divisor Latch High Register: Bit 1 of DLH value. Interrupt Enable Register: Enable Transmit Holding Register Empty Interrupt. This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt."]
    #[inline(always)]
    pub fn etbei_dlhl(&self) -> EtbeiDlhlR {
        EtbeiDlhlR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Divisor Latch High Register: Bit 2 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Receiver Line Status Interrupt. This is the highest priority interrupt."]
    #[inline(always)]
    pub fn elsi_dhl2(&self) -> ElsiDhl2R {
        ElsiDhl2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Divisor Latch High Register: Bit 3 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Modem Status Interrupts. This is the fourth highest priority interrupt."]
    #[inline(always)]
    pub fn edssi_dhl3(&self) -> EdssiDhl3R {
        EdssiDhl3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Bit 4 of DLH value."]
    #[inline(always)]
    pub fn dlh4(&self) -> Dlh4R {
        Dlh4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Bit 5 of DLH value."]
    #[inline(always)]
    pub fn dlh5(&self) -> Dlh5R {
        Dlh5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Bit 6 of DLH value."]
    #[inline(always)]
    pub fn dlh6(&self) -> Dlh6R {
        Dlh6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Divisor Latch High Register: Bit 7 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of THRE Interrupt."]
    #[inline(always)]
    pub fn ptime_dlh7(&self) -> PtimeDlh7R {
        PtimeDlh7R::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Divisor Latch High Register: Bit 0 of DLH value. Interrupt Enable Register: Used to enable/disable the generation of the Receive Data Available Interrupt and the Character Timeout Interrupt(if FIFO's enabled). These are the second highest priority interrupts."]
    #[inline(always)]
    #[must_use]
    pub fn erbfi_dlh0(&mut self) -> ErbfiDlh0W<IerDlhSpec> {
        ErbfiDlh0W::new(self, 0)
    }
    #[doc = "Bit 1 - Divisor Latch High Register: Bit 1 of DLH value. Interrupt Enable Register: Enable Transmit Holding Register Empty Interrupt. This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn etbei_dlhl(&mut self) -> EtbeiDlhlW<IerDlhSpec> {
        EtbeiDlhlW::new(self, 1)
    }
    #[doc = "Bit 2 - Divisor Latch High Register: Bit 2 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Receiver Line Status Interrupt. This is the highest priority interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn elsi_dhl2(&mut self) -> ElsiDhl2W<IerDlhSpec> {
        ElsiDhl2W::new(self, 2)
    }
    #[doc = "Bit 3 - Divisor Latch High Register: Bit 3 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of Modem Status Interrupts. This is the fourth highest priority interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn edssi_dhl3(&mut self) -> EdssiDhl3W<IerDlhSpec> {
        EdssiDhl3W::new(self, 3)
    }
    #[doc = "Bit 4 - Bit 4 of DLH value."]
    #[inline(always)]
    #[must_use]
    pub fn dlh4(&mut self) -> Dlh4W<IerDlhSpec> {
        Dlh4W::new(self, 4)
    }
    #[doc = "Bit 5 - Bit 5 of DLH value."]
    #[inline(always)]
    #[must_use]
    pub fn dlh5(&mut self) -> Dlh5W<IerDlhSpec> {
        Dlh5W::new(self, 5)
    }
    #[doc = "Bit 6 - Bit 6 of DLH value."]
    #[inline(always)]
    #[must_use]
    pub fn dlh6(&mut self) -> Dlh6W<IerDlhSpec> {
        Dlh6W::new(self, 6)
    }
    #[doc = "Bit 7 - Divisor Latch High Register: Bit 7 of DLH value. Interrupt Enable Register: This is used to enable/disable the generation of THRE Interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ptime_dlh7(&mut self) -> PtimeDlh7W<IerDlhSpec> {
        PtimeDlh7W::new(self, 7)
    }
}
#[doc = "This is a multi-function register. This register enables/disables receive and transmit interrupts and also controls the most-significant 8-bits of the baud rate divisor. Divisor Latch High Register: This register is accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1.Bits\\[7:0\\]
contain the high order 8-bits of the baud rate divisor.The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor): Note that with the Divisor Latch Registers (DLLand DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data. Interrupt Enable Register: This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 0.Allows control of the Interrupt Enables for transmit and receive functions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ier_dlh::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ier_dlh::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IerDlhSpec;
impl crate::RegisterSpec for IerDlhSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ier_dlh::R`](R) reader structure"]
impl crate::Readable for IerDlhSpec {}
#[doc = "`write(|w| ..)` method takes [`ier_dlh::W`](W) writer structure"]
impl crate::Writable for IerDlhSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ier_dlh to value 0"]
impl crate::Resettable for IerDlhSpec {
    const RESET_VALUE: u32 = 0;
}
