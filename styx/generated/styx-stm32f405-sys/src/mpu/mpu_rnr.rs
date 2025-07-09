// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MPU_RNR` reader"]
pub type R = crate::R<MpuRnrSpec>;
#[doc = "Register `MPU_RNR` writer"]
pub type W = crate::W<MpuRnrSpec>;
#[doc = "Field `REGION` reader - MPU region"]
pub type RegionR = crate::FieldReader;
#[doc = "Field `REGION` writer - MPU region"]
pub type RegionW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - MPU region"]
    #[inline(always)]
    pub fn region(&self) -> RegionR {
        RegionR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - MPU region"]
    #[inline(always)]
    #[must_use]
    pub fn region(&mut self) -> RegionW<MpuRnrSpec> {
        RegionW::new(self, 0)
    }
}
#[doc = "MPU region number register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_rnr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpu_rnr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MpuRnrSpec;
impl crate::RegisterSpec for MpuRnrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`mpu_rnr::R`](R) reader structure"]
impl crate::Readable for MpuRnrSpec {}
#[doc = "`write(|w| ..)` method takes [`mpu_rnr::W`](W) writer structure"]
impl crate::Writable for MpuRnrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MPU_RNR to value 0"]
impl crate::Resettable for MpuRnrSpec {
    const RESET_VALUE: u32 = 0;
}
