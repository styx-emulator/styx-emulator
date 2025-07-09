// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DHR8RD` reader"]
pub type R = crate::R<Dhr8rdSpec>;
#[doc = "Register `DHR8RD` writer"]
pub type W = crate::W<Dhr8rdSpec>;
#[doc = "Field `DACC1DHR` reader - DAC channel1 8-bit right-aligned data"]
pub type Dacc1dhrR = crate::FieldReader;
#[doc = "Field `DACC1DHR` writer - DAC channel1 8-bit right-aligned data"]
pub type Dacc1dhrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DACC2DHR` reader - DAC channel2 8-bit right-aligned data"]
pub type Dacc2dhrR = crate::FieldReader;
#[doc = "Field `DACC2DHR` writer - DAC channel2 8-bit right-aligned data"]
pub type Dacc2dhrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - DAC channel1 8-bit right-aligned data"]
    #[inline(always)]
    pub fn dacc1dhr(&self) -> Dacc1dhrR {
        Dacc1dhrR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - DAC channel2 8-bit right-aligned data"]
    #[inline(always)]
    pub fn dacc2dhr(&self) -> Dacc2dhrR {
        Dacc2dhrR::new(((self.bits >> 8) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - DAC channel1 8-bit right-aligned data"]
    #[inline(always)]
    #[must_use]
    pub fn dacc1dhr(&mut self) -> Dacc1dhrW<Dhr8rdSpec> {
        Dacc1dhrW::new(self, 0)
    }
    #[doc = "Bits 8:15 - DAC channel2 8-bit right-aligned data"]
    #[inline(always)]
    #[must_use]
    pub fn dacc2dhr(&mut self) -> Dacc2dhrW<Dhr8rdSpec> {
        Dacc2dhrW::new(self, 8)
    }
}
#[doc = "DUAL DAC 8-bit right aligned data holding register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dhr8rd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dhr8rd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dhr8rdSpec;
impl crate::RegisterSpec for Dhr8rdSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`dhr8rd::R`](R) reader structure"]
impl crate::Readable for Dhr8rdSpec {}
#[doc = "`write(|w| ..)` method takes [`dhr8rd::W`](W) writer structure"]
impl crate::Writable for Dhr8rdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DHR8RD to value 0"]
impl crate::Resettable for Dhr8rdSpec {
    const RESET_VALUE: u32 = 0;
}
