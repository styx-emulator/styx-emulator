// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DOR1` reader"]
pub type R = crate::R<Dor1Spec>;
#[doc = "Register `DOR1` writer"]
pub type W = crate::W<Dor1Spec>;
#[doc = "Field `DACC1DOR` reader - DAC channel1 data output"]
pub type Dacc1dorR = crate::FieldReader<u16>;
#[doc = "Field `DACC1DOR` writer - DAC channel1 data output"]
pub type Dacc1dorW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - DAC channel1 data output"]
    #[inline(always)]
    pub fn dacc1dor(&self) -> Dacc1dorR {
        Dacc1dorR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - DAC channel1 data output"]
    #[inline(always)]
    #[must_use]
    pub fn dacc1dor(&mut self) -> Dacc1dorW<Dor1Spec> {
        Dacc1dorW::new(self, 0)
    }
}
#[doc = "channel1 data output register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dor1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dor1Spec;
impl crate::RegisterSpec for Dor1Spec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`dor1::R`](R) reader structure"]
impl crate::Readable for Dor1Spec {}
#[doc = "`reset()` method sets DOR1 to value 0"]
impl crate::Resettable for Dor1Spec {
    const RESET_VALUE: u32 = 0;
}
