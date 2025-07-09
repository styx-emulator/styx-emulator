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
#[doc = "Register `OTG_FS_DCTL` reader"]
pub type R = crate::R<OtgFsDctlSpec>;
#[doc = "Register `OTG_FS_DCTL` writer"]
pub type W = crate::W<OtgFsDctlSpec>;
#[doc = "Field `RWUSIG` reader - Remote wakeup signaling"]
pub type RwusigR = crate::BitReader;
#[doc = "Field `RWUSIG` writer - Remote wakeup signaling"]
pub type RwusigW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDIS` reader - Soft disconnect"]
pub type SdisR = crate::BitReader;
#[doc = "Field `SDIS` writer - Soft disconnect"]
pub type SdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GINSTS` reader - Global IN NAK status"]
pub type GinstsR = crate::BitReader;
#[doc = "Field `GINSTS` writer - Global IN NAK status"]
pub type GinstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GONSTS` reader - Global OUT NAK status"]
pub type GonstsR = crate::BitReader;
#[doc = "Field `GONSTS` writer - Global OUT NAK status"]
pub type GonstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCTL` reader - Test control"]
pub type TctlR = crate::FieldReader;
#[doc = "Field `TCTL` writer - Test control"]
pub type TctlW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `SGINAK` reader - Set global IN NAK"]
pub type SginakR = crate::BitReader;
#[doc = "Field `SGINAK` writer - Set global IN NAK"]
pub type SginakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CGINAK` reader - Clear global IN NAK"]
pub type CginakR = crate::BitReader;
#[doc = "Field `CGINAK` writer - Clear global IN NAK"]
pub type CginakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SGONAK` reader - Set global OUT NAK"]
pub type SgonakR = crate::BitReader;
#[doc = "Field `SGONAK` writer - Set global OUT NAK"]
pub type SgonakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CGONAK` reader - Clear global OUT NAK"]
pub type CgonakR = crate::BitReader;
#[doc = "Field `CGONAK` writer - Clear global OUT NAK"]
pub type CgonakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `POPRGDNE` reader - Power-on programming done"]
pub type PoprgdneR = crate::BitReader;
#[doc = "Field `POPRGDNE` writer - Power-on programming done"]
pub type PoprgdneW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Remote wakeup signaling"]
    #[inline(always)]
    pub fn rwusig(&self) -> RwusigR {
        RwusigR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Soft disconnect"]
    #[inline(always)]
    pub fn sdis(&self) -> SdisR {
        SdisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Global IN NAK status"]
    #[inline(always)]
    pub fn ginsts(&self) -> GinstsR {
        GinstsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Global OUT NAK status"]
    #[inline(always)]
    pub fn gonsts(&self) -> GonstsR {
        GonstsR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:6 - Test control"]
    #[inline(always)]
    pub fn tctl(&self) -> TctlR {
        TctlR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bit 7 - Set global IN NAK"]
    #[inline(always)]
    pub fn sginak(&self) -> SginakR {
        SginakR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Clear global IN NAK"]
    #[inline(always)]
    pub fn cginak(&self) -> CginakR {
        CginakR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Set global OUT NAK"]
    #[inline(always)]
    pub fn sgonak(&self) -> SgonakR {
        SgonakR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Clear global OUT NAK"]
    #[inline(always)]
    pub fn cgonak(&self) -> CgonakR {
        CgonakR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Power-on programming done"]
    #[inline(always)]
    pub fn poprgdne(&self) -> PoprgdneR {
        PoprgdneR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Remote wakeup signaling"]
    #[inline(always)]
    #[must_use]
    pub fn rwusig(&mut self) -> RwusigW<OtgFsDctlSpec> {
        RwusigW::new(self, 0)
    }
    #[doc = "Bit 1 - Soft disconnect"]
    #[inline(always)]
    #[must_use]
    pub fn sdis(&mut self) -> SdisW<OtgFsDctlSpec> {
        SdisW::new(self, 1)
    }
    #[doc = "Bit 2 - Global IN NAK status"]
    #[inline(always)]
    #[must_use]
    pub fn ginsts(&mut self) -> GinstsW<OtgFsDctlSpec> {
        GinstsW::new(self, 2)
    }
    #[doc = "Bit 3 - Global OUT NAK status"]
    #[inline(always)]
    #[must_use]
    pub fn gonsts(&mut self) -> GonstsW<OtgFsDctlSpec> {
        GonstsW::new(self, 3)
    }
    #[doc = "Bits 4:6 - Test control"]
    #[inline(always)]
    #[must_use]
    pub fn tctl(&mut self) -> TctlW<OtgFsDctlSpec> {
        TctlW::new(self, 4)
    }
    #[doc = "Bit 7 - Set global IN NAK"]
    #[inline(always)]
    #[must_use]
    pub fn sginak(&mut self) -> SginakW<OtgFsDctlSpec> {
        SginakW::new(self, 7)
    }
    #[doc = "Bit 8 - Clear global IN NAK"]
    #[inline(always)]
    #[must_use]
    pub fn cginak(&mut self) -> CginakW<OtgFsDctlSpec> {
        CginakW::new(self, 8)
    }
    #[doc = "Bit 9 - Set global OUT NAK"]
    #[inline(always)]
    #[must_use]
    pub fn sgonak(&mut self) -> SgonakW<OtgFsDctlSpec> {
        SgonakW::new(self, 9)
    }
    #[doc = "Bit 10 - Clear global OUT NAK"]
    #[inline(always)]
    #[must_use]
    pub fn cgonak(&mut self) -> CgonakW<OtgFsDctlSpec> {
        CgonakW::new(self, 10)
    }
    #[doc = "Bit 11 - Power-on programming done"]
    #[inline(always)]
    #[must_use]
    pub fn poprgdne(&mut self) -> PoprgdneW<OtgFsDctlSpec> {
        PoprgdneW::new(self, 11)
    }
}
#[doc = "OTG_FS device control register (OTG_FS_DCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDctlSpec;
impl crate::RegisterSpec for OtgFsDctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`otg_fs_dctl::R`](R) reader structure"]
impl crate::Readable for OtgFsDctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_dctl::W`](W) writer structure"]
impl crate::Writable for OtgFsDctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DCTL to value 0"]
impl crate::Resettable for OtgFsDctlSpec {
    const RESET_VALUE: u32 = 0;
}
