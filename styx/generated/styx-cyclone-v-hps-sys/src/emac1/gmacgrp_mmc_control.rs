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
#[doc = "Register `gmacgrp_MMC_Control` reader"]
pub type R = crate::R<GmacgrpMmcControlSpec>;
#[doc = "Register `gmacgrp_MMC_Control` writer"]
pub type W = crate::W<GmacgrpMmcControlSpec>;
#[doc = "When this bit is set, all counters are reset. This bit is cleared automatically after one clock cycle.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cntrst {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Cntrst> for bool {
    #[inline(always)]
    fn from(variant: Cntrst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cntrst` reader - When this bit is set, all counters are reset. This bit is cleared automatically after one clock cycle."]
pub type CntrstR = crate::BitReader<Cntrst>;
impl CntrstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cntrst {
        match self.bits {
            false => Cntrst::Disabled,
            true => Cntrst::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Cntrst::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Cntrst::Enabled
    }
}
#[doc = "Field `cntrst` writer - When this bit is set, all counters are reset. This bit is cleared automatically after one clock cycle."]
pub type CntrstW<'a, REG> = crate::BitWriter<'a, REG, Cntrst>;
impl<'a, REG> CntrstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntrst::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntrst::Enabled)
    }
}
#[doc = "When this bit is set, after reaching maximum value, the counter does not roll over to zero.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cntstopro {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Cntstopro> for bool {
    #[inline(always)]
    fn from(variant: Cntstopro) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cntstopro` reader - When this bit is set, after reaching maximum value, the counter does not roll over to zero."]
pub type CntstoproR = crate::BitReader<Cntstopro>;
impl CntstoproR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cntstopro {
        match self.bits {
            false => Cntstopro::Disabled,
            true => Cntstopro::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Cntstopro::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Cntstopro::Enabled
    }
}
#[doc = "Field `cntstopro` writer - When this bit is set, after reaching maximum value, the counter does not roll over to zero."]
pub type CntstoproW<'a, REG> = crate::BitWriter<'a, REG, Cntstopro>;
impl<'a, REG> CntstoproW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntstopro::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntstopro::Enabled)
    }
}
#[doc = "When this bit is set, the MMC counters are reset to zero after Read (self-clearing after reset). The counters are cleared when the least significant byte lane (bits\\[7:0\\]) is read.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rstonrd {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rstonrd> for bool {
    #[inline(always)]
    fn from(variant: Rstonrd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rstonrd` reader - When this bit is set, the MMC counters are reset to zero after Read (self-clearing after reset). The counters are cleared when the least significant byte lane (bits\\[7:0\\]) is read."]
pub type RstonrdR = crate::BitReader<Rstonrd>;
impl RstonrdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rstonrd {
        match self.bits {
            false => Rstonrd::Disabled,
            true => Rstonrd::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rstonrd::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rstonrd::Enabled
    }
}
#[doc = "Field `rstonrd` writer - When this bit is set, the MMC counters are reset to zero after Read (self-clearing after reset). The counters are cleared when the least significant byte lane (bits\\[7:0\\]) is read."]
pub type RstonrdW<'a, REG> = crate::BitWriter<'a, REG, Rstonrd>;
impl<'a, REG> RstonrdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rstonrd::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rstonrd::Enabled)
    }
}
#[doc = "When this bit is set, it freezes all MMC counters to their current value. Until this bit is reset to 0, no MMC counter is updated because of any transmitted or received frame. If any MMC counter is read with the Reset on Read bit set, then that counter is also cleared in this mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cntfreez {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Cntfreez> for bool {
    #[inline(always)]
    fn from(variant: Cntfreez) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cntfreez` reader - When this bit is set, it freezes all MMC counters to their current value. Until this bit is reset to 0, no MMC counter is updated because of any transmitted or received frame. If any MMC counter is read with the Reset on Read bit set, then that counter is also cleared in this mode."]
pub type CntfreezR = crate::BitReader<Cntfreez>;
impl CntfreezR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cntfreez {
        match self.bits {
            false => Cntfreez::Disabled,
            true => Cntfreez::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Cntfreez::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Cntfreez::Enabled
    }
}
#[doc = "Field `cntfreez` writer - When this bit is set, it freezes all MMC counters to their current value. Until this bit is reset to 0, no MMC counter is updated because of any transmitted or received frame. If any MMC counter is read with the Reset on Read bit set, then that counter is also cleared in this mode."]
pub type CntfreezW<'a, REG> = crate::BitWriter<'a, REG, Cntfreez>;
impl<'a, REG> CntfreezW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntfreez::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntfreez::Enabled)
    }
}
#[doc = "When this bit is set, all counters are initialized or preset to almost full or almost half according to bit 5. This bit is cleared automatically after 1 clock cycle. This bit, along with bit 5, is useful for debugging and testing the assertion of interrupts because of MMC counter becoming half-full or full.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cntprst {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Cntprst> for bool {
    #[inline(always)]
    fn from(variant: Cntprst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cntprst` reader - When this bit is set, all counters are initialized or preset to almost full or almost half according to bit 5. This bit is cleared automatically after 1 clock cycle. This bit, along with bit 5, is useful for debugging and testing the assertion of interrupts because of MMC counter becoming half-full or full."]
pub type CntprstR = crate::BitReader<Cntprst>;
impl CntprstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cntprst {
        match self.bits {
            false => Cntprst::Disabled,
            true => Cntprst::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Cntprst::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Cntprst::Enabled
    }
}
#[doc = "Field `cntprst` writer - When this bit is set, all counters are initialized or preset to almost full or almost half according to bit 5. This bit is cleared automatically after 1 clock cycle. This bit, along with bit 5, is useful for debugging and testing the assertion of interrupts because of MMC counter becoming half-full or full."]
pub type CntprstW<'a, REG> = crate::BitWriter<'a, REG, Cntprst>;
impl<'a, REG> CntprstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntprst::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cntprst::Enabled)
    }
}
#[doc = "When low and bit 4 is set, all MMC counters get preset to almost-half value. All octet counters get preset to 0x7FFF_F800 (half - 2KBytes) and all frame-counters gets preset to 0x7FFF_FFF0 (half - 16). When this bit is high and bit 4 is set, all MMC counters get preset to almost-full value. All octet counters get preset to 0xFFFF_F800 (full - 2KBytes) and all frame-counters gets preset to 0xFFFF_FFF0 (full - 16). For 16-bit counters, the almost-half preset values are 0x7800 and 0x7FF0 for the respective octet and frame counters. Similarly, the almost-full preset values for the 16-bit counters are 0xF800 and 0xFFF0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cntprstlvl {
    #[doc = "0: `0`"]
    Almosthalf = 0,
    #[doc = "1: `1`"]
    Almostfull = 1,
}
impl From<Cntprstlvl> for bool {
    #[inline(always)]
    fn from(variant: Cntprstlvl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cntprstlvl` reader - When low and bit 4 is set, all MMC counters get preset to almost-half value. All octet counters get preset to 0x7FFF_F800 (half - 2KBytes) and all frame-counters gets preset to 0x7FFF_FFF0 (half - 16). When this bit is high and bit 4 is set, all MMC counters get preset to almost-full value. All octet counters get preset to 0xFFFF_F800 (full - 2KBytes) and all frame-counters gets preset to 0xFFFF_FFF0 (full - 16). For 16-bit counters, the almost-half preset values are 0x7800 and 0x7FF0 for the respective octet and frame counters. Similarly, the almost-full preset values for the 16-bit counters are 0xF800 and 0xFFF0."]
pub type CntprstlvlR = crate::BitReader<Cntprstlvl>;
impl CntprstlvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cntprstlvl {
        match self.bits {
            false => Cntprstlvl::Almosthalf,
            true => Cntprstlvl::Almostfull,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_almosthalf(&self) -> bool {
        *self == Cntprstlvl::Almosthalf
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_almostfull(&self) -> bool {
        *self == Cntprstlvl::Almostfull
    }
}
#[doc = "Field `cntprstlvl` writer - When low and bit 4 is set, all MMC counters get preset to almost-half value. All octet counters get preset to 0x7FFF_F800 (half - 2KBytes) and all frame-counters gets preset to 0x7FFF_FFF0 (half - 16). When this bit is high and bit 4 is set, all MMC counters get preset to almost-full value. All octet counters get preset to 0xFFFF_F800 (full - 2KBytes) and all frame-counters gets preset to 0xFFFF_FFF0 (full - 16). For 16-bit counters, the almost-half preset values are 0x7800 and 0x7FF0 for the respective octet and frame counters. Similarly, the almost-full preset values for the 16-bit counters are 0xF800 and 0xFFF0."]
pub type CntprstlvlW<'a, REG> = crate::BitWriter<'a, REG, Cntprstlvl>;
impl<'a, REG> CntprstlvlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn almosthalf(self) -> &'a mut crate::W<REG> {
        self.variant(Cntprstlvl::Almosthalf)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn almostfull(self) -> &'a mut crate::W<REG> {
        self.variant(Cntprstlvl::Almostfull)
    }
}
#[doc = "Field `ucdbc` reader - When set, this bit enables MAC to update all the related MMC Counters for Broadcast frames dropped due to setting of DBF bit (Disable Broadcast Frames) of MAC Filter Register at offset 0x0004. When reset, MMC Counters are not updated for dropped Broadcast frames."]
pub type UcdbcR = crate::BitReader;
#[doc = "Field `ucdbc` writer - When set, this bit enables MAC to update all the related MMC Counters for Broadcast frames dropped due to setting of DBF bit (Disable Broadcast Frames) of MAC Filter Register at offset 0x0004. When reset, MMC Counters are not updated for dropped Broadcast frames."]
pub type UcdbcW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When this bit is set, all counters are reset. This bit is cleared automatically after one clock cycle."]
    #[inline(always)]
    pub fn cntrst(&self) -> CntrstR {
        CntrstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When this bit is set, after reaching maximum value, the counter does not roll over to zero."]
    #[inline(always)]
    pub fn cntstopro(&self) -> CntstoproR {
        CntstoproR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When this bit is set, the MMC counters are reset to zero after Read (self-clearing after reset). The counters are cleared when the least significant byte lane (bits\\[7:0\\]) is read."]
    #[inline(always)]
    pub fn rstonrd(&self) -> RstonrdR {
        RstonrdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When this bit is set, it freezes all MMC counters to their current value. Until this bit is reset to 0, no MMC counter is updated because of any transmitted or received frame. If any MMC counter is read with the Reset on Read bit set, then that counter is also cleared in this mode."]
    #[inline(always)]
    pub fn cntfreez(&self) -> CntfreezR {
        CntfreezR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When this bit is set, all counters are initialized or preset to almost full or almost half according to bit 5. This bit is cleared automatically after 1 clock cycle. This bit, along with bit 5, is useful for debugging and testing the assertion of interrupts because of MMC counter becoming half-full or full."]
    #[inline(always)]
    pub fn cntprst(&self) -> CntprstR {
        CntprstR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When low and bit 4 is set, all MMC counters get preset to almost-half value. All octet counters get preset to 0x7FFF_F800 (half - 2KBytes) and all frame-counters gets preset to 0x7FFF_FFF0 (half - 16). When this bit is high and bit 4 is set, all MMC counters get preset to almost-full value. All octet counters get preset to 0xFFFF_F800 (full - 2KBytes) and all frame-counters gets preset to 0xFFFF_FFF0 (full - 16). For 16-bit counters, the almost-half preset values are 0x7800 and 0x7FF0 for the respective octet and frame counters. Similarly, the almost-full preset values for the 16-bit counters are 0xF800 and 0xFFF0."]
    #[inline(always)]
    pub fn cntprstlvl(&self) -> CntprstlvlR {
        CntprstlvlR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - When set, this bit enables MAC to update all the related MMC Counters for Broadcast frames dropped due to setting of DBF bit (Disable Broadcast Frames) of MAC Filter Register at offset 0x0004. When reset, MMC Counters are not updated for dropped Broadcast frames."]
    #[inline(always)]
    pub fn ucdbc(&self) -> UcdbcR {
        UcdbcR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is set, all counters are reset. This bit is cleared automatically after one clock cycle."]
    #[inline(always)]
    #[must_use]
    pub fn cntrst(&mut self) -> CntrstW<GmacgrpMmcControlSpec> {
        CntrstW::new(self, 0)
    }
    #[doc = "Bit 1 - When this bit is set, after reaching maximum value, the counter does not roll over to zero."]
    #[inline(always)]
    #[must_use]
    pub fn cntstopro(&mut self) -> CntstoproW<GmacgrpMmcControlSpec> {
        CntstoproW::new(self, 1)
    }
    #[doc = "Bit 2 - When this bit is set, the MMC counters are reset to zero after Read (self-clearing after reset). The counters are cleared when the least significant byte lane (bits\\[7:0\\]) is read."]
    #[inline(always)]
    #[must_use]
    pub fn rstonrd(&mut self) -> RstonrdW<GmacgrpMmcControlSpec> {
        RstonrdW::new(self, 2)
    }
    #[doc = "Bit 3 - When this bit is set, it freezes all MMC counters to their current value. Until this bit is reset to 0, no MMC counter is updated because of any transmitted or received frame. If any MMC counter is read with the Reset on Read bit set, then that counter is also cleared in this mode."]
    #[inline(always)]
    #[must_use]
    pub fn cntfreez(&mut self) -> CntfreezW<GmacgrpMmcControlSpec> {
        CntfreezW::new(self, 3)
    }
    #[doc = "Bit 4 - When this bit is set, all counters are initialized or preset to almost full or almost half according to bit 5. This bit is cleared automatically after 1 clock cycle. This bit, along with bit 5, is useful for debugging and testing the assertion of interrupts because of MMC counter becoming half-full or full."]
    #[inline(always)]
    #[must_use]
    pub fn cntprst(&mut self) -> CntprstW<GmacgrpMmcControlSpec> {
        CntprstW::new(self, 4)
    }
    #[doc = "Bit 5 - When low and bit 4 is set, all MMC counters get preset to almost-half value. All octet counters get preset to 0x7FFF_F800 (half - 2KBytes) and all frame-counters gets preset to 0x7FFF_FFF0 (half - 16). When this bit is high and bit 4 is set, all MMC counters get preset to almost-full value. All octet counters get preset to 0xFFFF_F800 (full - 2KBytes) and all frame-counters gets preset to 0xFFFF_FFF0 (full - 16). For 16-bit counters, the almost-half preset values are 0x7800 and 0x7FF0 for the respective octet and frame counters. Similarly, the almost-full preset values for the 16-bit counters are 0xF800 and 0xFFF0."]
    #[inline(always)]
    #[must_use]
    pub fn cntprstlvl(&mut self) -> CntprstlvlW<GmacgrpMmcControlSpec> {
        CntprstlvlW::new(self, 5)
    }
    #[doc = "Bit 8 - When set, this bit enables MAC to update all the related MMC Counters for Broadcast frames dropped due to setting of DBF bit (Disable Broadcast Frames) of MAC Filter Register at offset 0x0004. When reset, MMC Counters are not updated for dropped Broadcast frames."]
    #[inline(always)]
    #[must_use]
    pub fn ucdbc(&mut self) -> UcdbcW<GmacgrpMmcControlSpec> {
        UcdbcW::new(self, 8)
    }
}
#[doc = "The MMC Control register establishes the operating mode of the management counters. Note: The bit 0 (Counters Reset) has higher priority than bit 4 (Counter Preset). Therefore, when the Software tries to set both bits in the same write cycle, all counters are cleared and the bit 4 is not set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_control::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_control::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcControlSpec;
impl crate::RegisterSpec for GmacgrpMmcControlSpec {
    type Ux = u32;
    const OFFSET: u64 = 256u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_control::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcControlSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mmc_control::W`](W) writer structure"]
impl crate::Writable for GmacgrpMmcControlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MMC_Control to value 0"]
impl crate::Resettable for GmacgrpMmcControlSpec {
    const RESET_VALUE: u32 = 0;
}
