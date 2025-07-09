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
#[doc = "Register `MPU_RBAR` reader"]
pub type R = crate::R<MpuRbarSpec>;
#[doc = "Register `MPU_RBAR` writer"]
pub type W = crate::W<MpuRbarSpec>;
#[doc = "Field `REGION` reader - MPU region field"]
pub type RegionR = crate::FieldReader;
#[doc = "Field `REGION` writer - MPU region field"]
pub type RegionW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `VALID` reader - MPU region number valid"]
pub type ValidR = crate::BitReader;
#[doc = "Field `VALID` writer - MPU region number valid"]
pub type ValidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADDR` reader - Region base address field"]
pub type AddrR = crate::FieldReader<u32>;
#[doc = "Field `ADDR` writer - Region base address field"]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 27, u32>;
impl R {
    #[doc = "Bits 0:3 - MPU region field"]
    #[inline(always)]
    pub fn region(&self) -> RegionR {
        RegionR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 4 - MPU region number valid"]
    #[inline(always)]
    pub fn valid(&self) -> ValidR {
        ValidR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:31 - Region base address field"]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new((self.bits >> 5) & 0x07ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:3 - MPU region field"]
    #[inline(always)]
    #[must_use]
    pub fn region(&mut self) -> RegionW<MpuRbarSpec> {
        RegionW::new(self, 0)
    }
    #[doc = "Bit 4 - MPU region number valid"]
    #[inline(always)]
    #[must_use]
    pub fn valid(&mut self) -> ValidW<MpuRbarSpec> {
        ValidW::new(self, 4)
    }
    #[doc = "Bits 5:31 - Region base address field"]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<MpuRbarSpec> {
        AddrW::new(self, 5)
    }
}
#[doc = "MPU region base address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_rbar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpu_rbar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MpuRbarSpec;
impl crate::RegisterSpec for MpuRbarSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`mpu_rbar::R`](R) reader structure"]
impl crate::Readable for MpuRbarSpec {}
#[doc = "`write(|w| ..)` method takes [`mpu_rbar::W`](W) writer structure"]
impl crate::Writable for MpuRbarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MPU_RBAR to value 0"]
impl crate::Resettable for MpuRbarSpec {
    const RESET_VALUE: u32 = 0;
}
