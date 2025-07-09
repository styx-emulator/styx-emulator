// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MPU_TYPER` reader"]
pub type R = crate::R<MpuTyperSpec>;
#[doc = "Register `MPU_TYPER` writer"]
pub type W = crate::W<MpuTyperSpec>;
#[doc = "Field `SEPARATE` reader - Separate flag"]
pub type SeparateR = crate::BitReader;
#[doc = "Field `SEPARATE` writer - Separate flag"]
pub type SeparateW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DREGION` reader - Number of MPU data regions"]
pub type DregionR = crate::FieldReader;
#[doc = "Field `DREGION` writer - Number of MPU data regions"]
pub type DregionW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IREGION` reader - Number of MPU instruction regions"]
pub type IregionR = crate::FieldReader;
#[doc = "Field `IREGION` writer - Number of MPU instruction regions"]
pub type IregionW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bit 0 - Separate flag"]
    #[inline(always)]
    pub fn separate(&self) -> SeparateR {
        SeparateR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 8:15 - Number of MPU data regions"]
    #[inline(always)]
    pub fn dregion(&self) -> DregionR {
        DregionR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Number of MPU instruction regions"]
    #[inline(always)]
    pub fn iregion(&self) -> IregionR {
        IregionR::new(((self.bits >> 16) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Separate flag"]
    #[inline(always)]
    #[must_use]
    pub fn separate(&mut self) -> SeparateW<MpuTyperSpec> {
        SeparateW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Number of MPU data regions"]
    #[inline(always)]
    #[must_use]
    pub fn dregion(&mut self) -> DregionW<MpuTyperSpec> {
        DregionW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Number of MPU instruction regions"]
    #[inline(always)]
    #[must_use]
    pub fn iregion(&mut self) -> IregionW<MpuTyperSpec> {
        IregionW::new(self, 16)
    }
}
#[doc = "MPU type register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_typer::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MpuTyperSpec;
impl crate::RegisterSpec for MpuTyperSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`mpu_typer::R`](R) reader structure"]
impl crate::Readable for MpuTyperSpec {}
#[doc = "`reset()` method sets MPU_TYPER to value 0x0800"]
impl crate::Resettable for MpuTyperSpec {
    const RESET_VALUE: u32 = 0x0800;
}
