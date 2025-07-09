// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DOR2` reader"]
pub type R = crate::R<Dor2Spec>;
#[doc = "Register `DOR2` writer"]
pub type W = crate::W<Dor2Spec>;
#[doc = "Field `DACC2DOR` reader - DAC channel2 data output"]
pub type Dacc2dorR = crate::FieldReader<u16>;
#[doc = "Field `DACC2DOR` writer - DAC channel2 data output"]
pub type Dacc2dorW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - DAC channel2 data output"]
    #[inline(always)]
    pub fn dacc2dor(&self) -> Dacc2dorR {
        Dacc2dorR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - DAC channel2 data output"]
    #[inline(always)]
    #[must_use]
    pub fn dacc2dor(&mut self) -> Dacc2dorW<Dor2Spec> {
        Dacc2dorW::new(self, 0)
    }
}
#[doc = "channel2 data output register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dor2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dor2Spec;
impl crate::RegisterSpec for Dor2Spec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`dor2::R`](R) reader structure"]
impl crate::Readable for Dor2Spec {}
#[doc = "`reset()` method sets DOR2 to value 0"]
impl crate::Resettable for Dor2Spec {
    const RESET_VALUE: u32 = 0;
}
