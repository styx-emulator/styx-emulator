// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_id_code` reader"]
pub type R = crate::R<GpioIdCodeSpec>;
#[doc = "Register `gpio_id_code` writer"]
pub type W = crate::W<GpioIdCodeSpec>;
#[doc = "Field `gpio_id_code` reader - Chip identification"]
pub type GpioIdCodeR = crate::FieldReader<u32>;
#[doc = "Field `gpio_id_code` writer - Chip identification"]
pub type GpioIdCodeW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Chip identification"]
    #[inline(always)]
    pub fn gpio_id_code(&self) -> GpioIdCodeR {
        GpioIdCodeR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Chip identification"]
    #[inline(always)]
    #[must_use]
    pub fn gpio_id_code(&mut self) -> GpioIdCodeW<GpioIdCodeSpec> {
        GpioIdCodeW::new(self, 0)
    }
}
#[doc = "GPIO ID code.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_id_code::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioIdCodeSpec;
impl crate::RegisterSpec for GpioIdCodeSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`gpio_id_code::R`](R) reader structure"]
impl crate::Readable for GpioIdCodeSpec {}
#[doc = "`reset()` method sets gpio_id_code to value 0"]
impl crate::Resettable for GpioIdCodeSpec {
    const RESET_VALUE: u32 = 0;
}
