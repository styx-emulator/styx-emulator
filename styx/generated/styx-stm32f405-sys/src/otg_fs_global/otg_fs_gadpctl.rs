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
#[doc = "Register `OTG_FS_GADPCTL` reader"]
pub type R = crate::R<OtgFsGadpctlSpec>;
#[doc = "Register `OTG_FS_GADPCTL` writer"]
pub type W = crate::W<OtgFsGadpctlSpec>;
#[doc = "Field `PRBDSCHG` reader - Probe discharge"]
pub type PrbdschgR = crate::FieldReader;
#[doc = "Field `PRBDSCHG` writer - Probe discharge"]
pub type PrbdschgW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PRBDELTA` reader - Probe delta"]
pub type PrbdeltaR = crate::FieldReader;
#[doc = "Field `PRBDELTA` writer - Probe delta"]
pub type PrbdeltaW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PRBPER` reader - Probe period"]
pub type PrbperR = crate::FieldReader;
#[doc = "Field `PRBPER` writer - Probe period"]
pub type PrbperW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `RTIM` reader - Ramp time"]
pub type RtimR = crate::FieldReader<u16>;
#[doc = "Field `RTIM` writer - Ramp time"]
pub type RtimW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `ENAPRB` reader - Enable probe"]
pub type EnaprbR = crate::BitReader;
#[doc = "Field `ENAPRB` writer - Enable probe"]
pub type EnaprbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ENASNS` reader - Enable sense"]
pub type EnasnsR = crate::BitReader;
#[doc = "Field `ENASNS` writer - Enable sense"]
pub type EnasnsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPRST` reader - ADP reset"]
pub type AdprstR = crate::BitReader;
#[doc = "Field `ADPRST` writer - ADP reset"]
pub type AdprstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPEN` reader - ADP enable"]
pub type AdpenR = crate::BitReader;
#[doc = "Field `ADPEN` writer - ADP enable"]
pub type AdpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPPRBIF` reader - ADP probe interrupt flag"]
pub type AdpprbifR = crate::BitReader;
#[doc = "Field `ADPPRBIF` writer - ADP probe interrupt flag"]
pub type AdpprbifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPSNSIF` reader - ADP sense interrupt flag"]
pub type AdpsnsifR = crate::BitReader;
#[doc = "Field `ADPSNSIF` writer - ADP sense interrupt flag"]
pub type AdpsnsifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPTOIF` reader - ADP timeout interrupt flag"]
pub type AdptoifR = crate::BitReader;
#[doc = "Field `ADPTOIF` writer - ADP timeout interrupt flag"]
pub type AdptoifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPPRBIM` reader - ADP probe interrupt mask"]
pub type AdpprbimR = crate::BitReader;
#[doc = "Field `ADPPRBIM` writer - ADP probe interrupt mask"]
pub type AdpprbimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPSNSIM` reader - ADP sense interrupt mask"]
pub type AdpsnsimR = crate::BitReader;
#[doc = "Field `ADPSNSIM` writer - ADP sense interrupt mask"]
pub type AdpsnsimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPTOIM` reader - ADP timeout interrupt mask"]
pub type AdptoimR = crate::BitReader;
#[doc = "Field `ADPTOIM` writer - ADP timeout interrupt mask"]
pub type AdptoimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AR` reader - Access request"]
pub type ArR = crate::FieldReader;
#[doc = "Field `AR` writer - Access request"]
pub type ArW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Probe discharge"]
    #[inline(always)]
    pub fn prbdschg(&self) -> PrbdschgR {
        PrbdschgR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Probe delta"]
    #[inline(always)]
    pub fn prbdelta(&self) -> PrbdeltaR {
        PrbdeltaR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - Probe period"]
    #[inline(always)]
    pub fn prbper(&self) -> PrbperR {
        PrbperR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bits 6:16 - Ramp time"]
    #[inline(always)]
    pub fn rtim(&self) -> RtimR {
        RtimR::new(((self.bits >> 6) & 0x07ff) as u16)
    }
    #[doc = "Bit 17 - Enable probe"]
    #[inline(always)]
    pub fn enaprb(&self) -> EnaprbR {
        EnaprbR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Enable sense"]
    #[inline(always)]
    pub fn enasns(&self) -> EnasnsR {
        EnasnsR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - ADP reset"]
    #[inline(always)]
    pub fn adprst(&self) -> AdprstR {
        AdprstR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - ADP enable"]
    #[inline(always)]
    pub fn adpen(&self) -> AdpenR {
        AdpenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - ADP probe interrupt flag"]
    #[inline(always)]
    pub fn adpprbif(&self) -> AdpprbifR {
        AdpprbifR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - ADP sense interrupt flag"]
    #[inline(always)]
    pub fn adpsnsif(&self) -> AdpsnsifR {
        AdpsnsifR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - ADP timeout interrupt flag"]
    #[inline(always)]
    pub fn adptoif(&self) -> AdptoifR {
        AdptoifR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - ADP probe interrupt mask"]
    #[inline(always)]
    pub fn adpprbim(&self) -> AdpprbimR {
        AdpprbimR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - ADP sense interrupt mask"]
    #[inline(always)]
    pub fn adpsnsim(&self) -> AdpsnsimR {
        AdpsnsimR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - ADP timeout interrupt mask"]
    #[inline(always)]
    pub fn adptoim(&self) -> AdptoimR {
        AdptoimR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bits 27:28 - Access request"]
    #[inline(always)]
    pub fn ar(&self) -> ArR {
        ArR::new(((self.bits >> 27) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Probe discharge"]
    #[inline(always)]
    #[must_use]
    pub fn prbdschg(&mut self) -> PrbdschgW<OtgFsGadpctlSpec> {
        PrbdschgW::new(self, 0)
    }
    #[doc = "Bits 2:3 - Probe delta"]
    #[inline(always)]
    #[must_use]
    pub fn prbdelta(&mut self) -> PrbdeltaW<OtgFsGadpctlSpec> {
        PrbdeltaW::new(self, 2)
    }
    #[doc = "Bits 4:5 - Probe period"]
    #[inline(always)]
    #[must_use]
    pub fn prbper(&mut self) -> PrbperW<OtgFsGadpctlSpec> {
        PrbperW::new(self, 4)
    }
    #[doc = "Bits 6:16 - Ramp time"]
    #[inline(always)]
    #[must_use]
    pub fn rtim(&mut self) -> RtimW<OtgFsGadpctlSpec> {
        RtimW::new(self, 6)
    }
    #[doc = "Bit 17 - Enable probe"]
    #[inline(always)]
    #[must_use]
    pub fn enaprb(&mut self) -> EnaprbW<OtgFsGadpctlSpec> {
        EnaprbW::new(self, 17)
    }
    #[doc = "Bit 18 - Enable sense"]
    #[inline(always)]
    #[must_use]
    pub fn enasns(&mut self) -> EnasnsW<OtgFsGadpctlSpec> {
        EnasnsW::new(self, 18)
    }
    #[doc = "Bit 19 - ADP reset"]
    #[inline(always)]
    #[must_use]
    pub fn adprst(&mut self) -> AdprstW<OtgFsGadpctlSpec> {
        AdprstW::new(self, 19)
    }
    #[doc = "Bit 20 - ADP enable"]
    #[inline(always)]
    #[must_use]
    pub fn adpen(&mut self) -> AdpenW<OtgFsGadpctlSpec> {
        AdpenW::new(self, 20)
    }
    #[doc = "Bit 21 - ADP probe interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn adpprbif(&mut self) -> AdpprbifW<OtgFsGadpctlSpec> {
        AdpprbifW::new(self, 21)
    }
    #[doc = "Bit 22 - ADP sense interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn adpsnsif(&mut self) -> AdpsnsifW<OtgFsGadpctlSpec> {
        AdpsnsifW::new(self, 22)
    }
    #[doc = "Bit 23 - ADP timeout interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn adptoif(&mut self) -> AdptoifW<OtgFsGadpctlSpec> {
        AdptoifW::new(self, 23)
    }
    #[doc = "Bit 24 - ADP probe interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn adpprbim(&mut self) -> AdpprbimW<OtgFsGadpctlSpec> {
        AdpprbimW::new(self, 24)
    }
    #[doc = "Bit 25 - ADP sense interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn adpsnsim(&mut self) -> AdpsnsimW<OtgFsGadpctlSpec> {
        AdpsnsimW::new(self, 25)
    }
    #[doc = "Bit 26 - ADP timeout interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn adptoim(&mut self) -> AdptoimW<OtgFsGadpctlSpec> {
        AdptoimW::new(self, 26)
    }
    #[doc = "Bits 27:28 - Access request"]
    #[inline(always)]
    #[must_use]
    pub fn ar(&mut self) -> ArW<OtgFsGadpctlSpec> {
        ArW::new(self, 27)
    }
}
#[doc = "OTG ADP timer, control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gadpctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gadpctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGadpctlSpec;
impl crate::RegisterSpec for OtgFsGadpctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`otg_fs_gadpctl::R`](R) reader structure"]
impl crate::Readable for OtgFsGadpctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gadpctl::W`](W) writer structure"]
impl crate::Writable for OtgFsGadpctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GADPCTL to value 0x0200_0400"]
impl crate::Resettable for OtgFsGadpctlSpec {
    const RESET_VALUE: u32 = 0x0200_0400;
}
