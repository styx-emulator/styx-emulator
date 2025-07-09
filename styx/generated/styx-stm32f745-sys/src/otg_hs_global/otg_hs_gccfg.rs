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
#[doc = "Register `OTG_HS_GCCFG` reader"]
pub type R = crate::R<OtgHsGccfgSpec>;
#[doc = "Register `OTG_HS_GCCFG` writer"]
pub type W = crate::W<OtgHsGccfgSpec>;
#[doc = "Field `DCDET` reader - Data contact detection (DCD) status"]
pub type DcdetR = crate::BitReader;
#[doc = "Field `DCDET` writer - Data contact detection (DCD) status"]
pub type DcdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PDET` reader - Primary detection (PD) status"]
pub type PdetR = crate::BitReader;
#[doc = "Field `PDET` writer - Primary detection (PD) status"]
pub type PdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDET` reader - Secondary detection (SD) status"]
pub type SdetR = crate::BitReader;
#[doc = "Field `SDET` writer - Secondary detection (SD) status"]
pub type SdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PS2DET` reader - DM pull-up detection status"]
pub type Ps2detR = crate::BitReader;
#[doc = "Field `PS2DET` writer - DM pull-up detection status"]
pub type Ps2detW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PWRDWN` reader - Power down"]
pub type PwrdwnR = crate::BitReader;
#[doc = "Field `PWRDWN` writer - Power down"]
pub type PwrdwnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BCDEN` reader - Battery charging detector (BCD) enable"]
pub type BcdenR = crate::BitReader;
#[doc = "Field `BCDEN` writer - Battery charging detector (BCD) enable"]
pub type BcdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DCDEN` reader - Data contact detection (DCD) mode enable"]
pub type DcdenR = crate::BitReader;
#[doc = "Field `DCDEN` writer - Data contact detection (DCD) mode enable"]
pub type DcdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PDEN` reader - Primary detection (PD) mode enable"]
pub type PdenR = crate::BitReader;
#[doc = "Field `PDEN` writer - Primary detection (PD) mode enable"]
pub type PdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDEN` reader - Secondary detection (SD) mode enable"]
pub type SdenR = crate::BitReader;
#[doc = "Field `SDEN` writer - Secondary detection (SD) mode enable"]
pub type SdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBDEN` reader - USB VBUS detection enable"]
pub type VbdenR = crate::BitReader;
#[doc = "Field `VBDEN` writer - USB VBUS detection enable"]
pub type VbdenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Data contact detection (DCD) status"]
    #[inline(always)]
    pub fn dcdet(&self) -> DcdetR {
        DcdetR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Primary detection (PD) status"]
    #[inline(always)]
    pub fn pdet(&self) -> PdetR {
        PdetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Secondary detection (SD) status"]
    #[inline(always)]
    pub fn sdet(&self) -> SdetR {
        SdetR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - DM pull-up detection status"]
    #[inline(always)]
    pub fn ps2det(&self) -> Ps2detR {
        Ps2detR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 16 - Power down"]
    #[inline(always)]
    pub fn pwrdwn(&self) -> PwrdwnR {
        PwrdwnR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Battery charging detector (BCD) enable"]
    #[inline(always)]
    pub fn bcden(&self) -> BcdenR {
        BcdenR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Data contact detection (DCD) mode enable"]
    #[inline(always)]
    pub fn dcden(&self) -> DcdenR {
        DcdenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Primary detection (PD) mode enable"]
    #[inline(always)]
    pub fn pden(&self) -> PdenR {
        PdenR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Secondary detection (SD) mode enable"]
    #[inline(always)]
    pub fn sden(&self) -> SdenR {
        SdenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - USB VBUS detection enable"]
    #[inline(always)]
    pub fn vbden(&self) -> VbdenR {
        VbdenR::new(((self.bits >> 21) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Data contact detection (DCD) status"]
    #[inline(always)]
    #[must_use]
    pub fn dcdet(&mut self) -> DcdetW<OtgHsGccfgSpec> {
        DcdetW::new(self, 0)
    }
    #[doc = "Bit 1 - Primary detection (PD) status"]
    #[inline(always)]
    #[must_use]
    pub fn pdet(&mut self) -> PdetW<OtgHsGccfgSpec> {
        PdetW::new(self, 1)
    }
    #[doc = "Bit 2 - Secondary detection (SD) status"]
    #[inline(always)]
    #[must_use]
    pub fn sdet(&mut self) -> SdetW<OtgHsGccfgSpec> {
        SdetW::new(self, 2)
    }
    #[doc = "Bit 3 - DM pull-up detection status"]
    #[inline(always)]
    #[must_use]
    pub fn ps2det(&mut self) -> Ps2detW<OtgHsGccfgSpec> {
        Ps2detW::new(self, 3)
    }
    #[doc = "Bit 16 - Power down"]
    #[inline(always)]
    #[must_use]
    pub fn pwrdwn(&mut self) -> PwrdwnW<OtgHsGccfgSpec> {
        PwrdwnW::new(self, 16)
    }
    #[doc = "Bit 17 - Battery charging detector (BCD) enable"]
    #[inline(always)]
    #[must_use]
    pub fn bcden(&mut self) -> BcdenW<OtgHsGccfgSpec> {
        BcdenW::new(self, 17)
    }
    #[doc = "Bit 18 - Data contact detection (DCD) mode enable"]
    #[inline(always)]
    #[must_use]
    pub fn dcden(&mut self) -> DcdenW<OtgHsGccfgSpec> {
        DcdenW::new(self, 18)
    }
    #[doc = "Bit 19 - Primary detection (PD) mode enable"]
    #[inline(always)]
    #[must_use]
    pub fn pden(&mut self) -> PdenW<OtgHsGccfgSpec> {
        PdenW::new(self, 19)
    }
    #[doc = "Bit 20 - Secondary detection (SD) mode enable"]
    #[inline(always)]
    #[must_use]
    pub fn sden(&mut self) -> SdenW<OtgHsGccfgSpec> {
        SdenW::new(self, 20)
    }
    #[doc = "Bit 21 - USB VBUS detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn vbden(&mut self) -> VbdenW<OtgHsGccfgSpec> {
        VbdenW::new(self, 21)
    }
}
#[doc = "OTG_HS general core configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gccfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gccfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsGccfgSpec;
impl crate::RegisterSpec for OtgHsGccfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`otg_hs_gccfg::R`](R) reader structure"]
impl crate::Readable for OtgHsGccfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_gccfg::W`](W) writer structure"]
impl crate::Writable for OtgHsGccfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_GCCFG to value 0"]
impl crate::Resettable for OtgHsGccfgSpec {
    const RESET_VALUE: u32 = 0;
}
