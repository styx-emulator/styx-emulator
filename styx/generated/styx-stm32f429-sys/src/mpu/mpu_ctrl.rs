// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MPU_CTRL` reader"]
pub type R = crate::R<MpuCtrlSpec>;
#[doc = "Register `MPU_CTRL` writer"]
pub type W = crate::W<MpuCtrlSpec>;
#[doc = "Field `ENABLE` reader - Enables the MPU"]
pub type EnableR = crate::BitReader;
#[doc = "Field `ENABLE` writer - Enables the MPU"]
pub type EnableW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HFNMIENA` reader - Enables the operation of MPU during hard fault"]
pub type HfnmienaR = crate::BitReader;
#[doc = "Field `HFNMIENA` writer - Enables the operation of MPU during hard fault"]
pub type HfnmienaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRIVDEFENA` reader - Enable priviliged software access to default memory map"]
pub type PrivdefenaR = crate::BitReader;
#[doc = "Field `PRIVDEFENA` writer - Enable priviliged software access to default memory map"]
pub type PrivdefenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enables the MPU"]
    #[inline(always)]
    pub fn enable(&self) -> EnableR {
        EnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Enables the operation of MPU during hard fault"]
    #[inline(always)]
    pub fn hfnmiena(&self) -> HfnmienaR {
        HfnmienaR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Enable priviliged software access to default memory map"]
    #[inline(always)]
    pub fn privdefena(&self) -> PrivdefenaR {
        PrivdefenaR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables the MPU"]
    #[inline(always)]
    #[must_use]
    pub fn enable(&mut self) -> EnableW<MpuCtrlSpec> {
        EnableW::new(self, 0)
    }
    #[doc = "Bit 1 - Enables the operation of MPU during hard fault"]
    #[inline(always)]
    #[must_use]
    pub fn hfnmiena(&mut self) -> HfnmienaW<MpuCtrlSpec> {
        HfnmienaW::new(self, 1)
    }
    #[doc = "Bit 2 - Enable priviliged software access to default memory map"]
    #[inline(always)]
    #[must_use]
    pub fn privdefena(&mut self) -> PrivdefenaW<MpuCtrlSpec> {
        PrivdefenaW::new(self, 2)
    }
}
#[doc = "MPU control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_ctrl::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MpuCtrlSpec;
impl crate::RegisterSpec for MpuCtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`mpu_ctrl::R`](R) reader structure"]
impl crate::Readable for MpuCtrlSpec {}
#[doc = "`reset()` method sets MPU_CTRL to value 0"]
impl crate::Resettable for MpuCtrlSpec {
    const RESET_VALUE: u32 = 0;
}
