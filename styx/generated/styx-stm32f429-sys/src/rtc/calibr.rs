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
#[doc = "Register `CALIBR` reader"]
pub type R = crate::R<CalibrSpec>;
#[doc = "Register `CALIBR` writer"]
pub type W = crate::W<CalibrSpec>;
#[doc = "Field `DC` reader - Digital calibration"]
pub type DcR = crate::FieldReader;
#[doc = "Field `DC` writer - Digital calibration"]
pub type DcW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `DCS` reader - Digital calibration sign"]
pub type DcsR = crate::BitReader;
#[doc = "Field `DCS` writer - Digital calibration sign"]
pub type DcsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - Digital calibration"]
    #[inline(always)]
    pub fn dc(&self) -> DcR {
        DcR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bit 7 - Digital calibration sign"]
    #[inline(always)]
    pub fn dcs(&self) -> DcsR {
        DcsR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - Digital calibration"]
    #[inline(always)]
    #[must_use]
    pub fn dc(&mut self) -> DcW<CalibrSpec> {
        DcW::new(self, 0)
    }
    #[doc = "Bit 7 - Digital calibration sign"]
    #[inline(always)]
    #[must_use]
    pub fn dcs(&mut self) -> DcsW<CalibrSpec> {
        DcsW::new(self, 7)
    }
}
#[doc = "calibration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`calibr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`calibr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CalibrSpec;
impl crate::RegisterSpec for CalibrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`calibr::R`](R) reader structure"]
impl crate::Readable for CalibrSpec {}
#[doc = "`write(|w| ..)` method takes [`calibr::W`](W) writer structure"]
impl crate::Writable for CalibrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CALIBR to value 0"]
impl crate::Resettable for CalibrSpec {
    const RESET_VALUE: u32 = 0;
}
