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
#[doc = "Register `MPU_RASR` reader"]
pub type R = crate::R<MpuRasrSpec>;
#[doc = "Register `MPU_RASR` writer"]
pub type W = crate::W<MpuRasrSpec>;
#[doc = "Field `ENABLE` reader - Region enable bit."]
pub type EnableR = crate::BitReader;
#[doc = "Field `ENABLE` writer - Region enable bit."]
pub type EnableW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SIZE` reader - Size of the MPU protection region"]
pub type SizeR = crate::FieldReader;
#[doc = "Field `SIZE` writer - Size of the MPU protection region"]
pub type SizeW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SRD` reader - Subregion disable bits"]
pub type SrdR = crate::FieldReader;
#[doc = "Field `SRD` writer - Subregion disable bits"]
pub type SrdW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `B` reader - memory attribute"]
pub type BR = crate::BitReader;
#[doc = "Field `B` writer - memory attribute"]
pub type BW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `C` reader - memory attribute"]
pub type CR = crate::BitReader;
#[doc = "Field `C` writer - memory attribute"]
pub type CW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `S` reader - Shareable memory attribute"]
pub type SR = crate::BitReader;
#[doc = "Field `S` writer - Shareable memory attribute"]
pub type SW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEX` reader - memory attribute"]
pub type TexR = crate::FieldReader;
#[doc = "Field `TEX` writer - memory attribute"]
pub type TexW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `AP` reader - Access permission"]
pub type ApR = crate::FieldReader;
#[doc = "Field `AP` writer - Access permission"]
pub type ApW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `XN` reader - Instruction access disable bit"]
pub type XnR = crate::BitReader;
#[doc = "Field `XN` writer - Instruction access disable bit"]
pub type XnW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Region enable bit."]
    #[inline(always)]
    pub fn enable(&self) -> EnableR {
        EnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:5 - Size of the MPU protection region"]
    #[inline(always)]
    pub fn size(&self) -> SizeR {
        SizeR::new(((self.bits >> 1) & 0x1f) as u8)
    }
    #[doc = "Bits 8:15 - Subregion disable bits"]
    #[inline(always)]
    pub fn srd(&self) -> SrdR {
        SrdR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bit 16 - memory attribute"]
    #[inline(always)]
    pub fn b(&self) -> BR {
        BR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - memory attribute"]
    #[inline(always)]
    pub fn c(&self) -> CR {
        CR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Shareable memory attribute"]
    #[inline(always)]
    pub fn s(&self) -> SR {
        SR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bits 19:21 - memory attribute"]
    #[inline(always)]
    pub fn tex(&self) -> TexR {
        TexR::new(((self.bits >> 19) & 7) as u8)
    }
    #[doc = "Bits 24:26 - Access permission"]
    #[inline(always)]
    pub fn ap(&self) -> ApR {
        ApR::new(((self.bits >> 24) & 7) as u8)
    }
    #[doc = "Bit 28 - Instruction access disable bit"]
    #[inline(always)]
    pub fn xn(&self) -> XnR {
        XnR::new(((self.bits >> 28) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Region enable bit."]
    #[inline(always)]
    #[must_use]
    pub fn enable(&mut self) -> EnableW<MpuRasrSpec> {
        EnableW::new(self, 0)
    }
    #[doc = "Bits 1:5 - Size of the MPU protection region"]
    #[inline(always)]
    #[must_use]
    pub fn size(&mut self) -> SizeW<MpuRasrSpec> {
        SizeW::new(self, 1)
    }
    #[doc = "Bits 8:15 - Subregion disable bits"]
    #[inline(always)]
    #[must_use]
    pub fn srd(&mut self) -> SrdW<MpuRasrSpec> {
        SrdW::new(self, 8)
    }
    #[doc = "Bit 16 - memory attribute"]
    #[inline(always)]
    #[must_use]
    pub fn b(&mut self) -> BW<MpuRasrSpec> {
        BW::new(self, 16)
    }
    #[doc = "Bit 17 - memory attribute"]
    #[inline(always)]
    #[must_use]
    pub fn c(&mut self) -> CW<MpuRasrSpec> {
        CW::new(self, 17)
    }
    #[doc = "Bit 18 - Shareable memory attribute"]
    #[inline(always)]
    #[must_use]
    pub fn s(&mut self) -> SW<MpuRasrSpec> {
        SW::new(self, 18)
    }
    #[doc = "Bits 19:21 - memory attribute"]
    #[inline(always)]
    #[must_use]
    pub fn tex(&mut self) -> TexW<MpuRasrSpec> {
        TexW::new(self, 19)
    }
    #[doc = "Bits 24:26 - Access permission"]
    #[inline(always)]
    #[must_use]
    pub fn ap(&mut self) -> ApW<MpuRasrSpec> {
        ApW::new(self, 24)
    }
    #[doc = "Bit 28 - Instruction access disable bit"]
    #[inline(always)]
    #[must_use]
    pub fn xn(&mut self) -> XnW<MpuRasrSpec> {
        XnW::new(self, 28)
    }
}
#[doc = "MPU region attribute and size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_rasr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpu_rasr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MpuRasrSpec;
impl crate::RegisterSpec for MpuRasrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`mpu_rasr::R`](R) reader structure"]
impl crate::Readable for MpuRasrSpec {}
#[doc = "`write(|w| ..)` method takes [`mpu_rasr::W`](W) writer structure"]
impl crate::Writable for MpuRasrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MPU_RASR to value 0"]
impl crate::Resettable for MpuRasrSpec {
    const RESET_VALUE: u32 = 0;
}
