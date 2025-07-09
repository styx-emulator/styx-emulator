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
#[doc = "Register `ctrlgrp_dramsts` reader"]
pub type R = crate::R<CtrlgrpDramstsSpec>;
#[doc = "Register `ctrlgrp_dramsts` writer"]
pub type W = crate::W<CtrlgrpDramstsSpec>;
#[doc = "Field `calsuccess` reader - This bit will be set to 1 if the PHY was able to successfully calibrate."]
pub type CalsuccessR = crate::BitReader;
#[doc = "Field `calsuccess` writer - This bit will be set to 1 if the PHY was able to successfully calibrate."]
pub type CalsuccessW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `calfail` reader - This bit will be set to 1 if the PHY was unable to calibrate."]
pub type CalfailR = crate::BitReader;
#[doc = "Field `calfail` writer - This bit will be set to 1 if the PHY was unable to calibrate."]
pub type CalfailW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sbeerr` reader - This bit will be set to 1 if there have been any ECC single bit errors detected."]
pub type SbeerrR = crate::BitReader;
#[doc = "Field `sbeerr` writer - This bit will be set to 1 if there have been any ECC single bit errors detected."]
pub type SbeerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbeerr` reader - This bit will be set to 1 if there have been any ECC double bit errors detected."]
pub type DbeerrR = crate::BitReader;
#[doc = "Field `dbeerr` writer - This bit will be set to 1 if there have been any ECC double bit errors detected."]
pub type DbeerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `corrdrop` reader - This bit will be set to 1 if there any auto-corrections have been dropped."]
pub type CorrdropR = crate::BitReader;
#[doc = "Field `corrdrop` writer - This bit will be set to 1 if there any auto-corrections have been dropped."]
pub type CorrdropW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit will be set to 1 if the PHY was able to successfully calibrate."]
    #[inline(always)]
    pub fn calsuccess(&self) -> CalsuccessR {
        CalsuccessR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit will be set to 1 if the PHY was unable to calibrate."]
    #[inline(always)]
    pub fn calfail(&self) -> CalfailR {
        CalfailR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit will be set to 1 if there have been any ECC single bit errors detected."]
    #[inline(always)]
    pub fn sbeerr(&self) -> SbeerrR {
        SbeerrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit will be set to 1 if there have been any ECC double bit errors detected."]
    #[inline(always)]
    pub fn dbeerr(&self) -> DbeerrR {
        DbeerrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit will be set to 1 if there any auto-corrections have been dropped."]
    #[inline(always)]
    pub fn corrdrop(&self) -> CorrdropR {
        CorrdropR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit will be set to 1 if the PHY was able to successfully calibrate."]
    #[inline(always)]
    #[must_use]
    pub fn calsuccess(&mut self) -> CalsuccessW<CtrlgrpDramstsSpec> {
        CalsuccessW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit will be set to 1 if the PHY was unable to calibrate."]
    #[inline(always)]
    #[must_use]
    pub fn calfail(&mut self) -> CalfailW<CtrlgrpDramstsSpec> {
        CalfailW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit will be set to 1 if there have been any ECC single bit errors detected."]
    #[inline(always)]
    #[must_use]
    pub fn sbeerr(&mut self) -> SbeerrW<CtrlgrpDramstsSpec> {
        SbeerrW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit will be set to 1 if there have been any ECC double bit errors detected."]
    #[inline(always)]
    #[must_use]
    pub fn dbeerr(&mut self) -> DbeerrW<CtrlgrpDramstsSpec> {
        DbeerrW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit will be set to 1 if there any auto-corrections have been dropped."]
    #[inline(always)]
    #[must_use]
    pub fn corrdrop(&mut self) -> CorrdropW<CtrlgrpDramstsSpec> {
        CorrdropW::new(self, 4)
    }
}
#[doc = "This register provides the status of the calibration and ECC logic.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramsts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramsts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramstsSpec;
impl crate::RegisterSpec for CtrlgrpDramstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 20536u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramsts::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramstsSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramsts::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramstsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramsts to value 0"]
impl crate::Resettable for CtrlgrpDramstsSpec {
    const RESET_VALUE: u32 = 0;
}
