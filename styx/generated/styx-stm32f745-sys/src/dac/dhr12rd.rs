// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DHR12RD` reader"]
pub type R = crate::R<Dhr12rdSpec>;
#[doc = "Register `DHR12RD` writer"]
pub type W = crate::W<Dhr12rdSpec>;
#[doc = "Field `DACC1DHR` reader - DAC channel1 12-bit right-aligned data"]
pub type Dacc1dhrR = crate::FieldReader<u16>;
#[doc = "Field `DACC1DHR` writer - DAC channel1 12-bit right-aligned data"]
pub type Dacc1dhrW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `DACC2DHR` reader - DAC channel2 12-bit right-aligned data"]
pub type Dacc2dhrR = crate::FieldReader<u16>;
#[doc = "Field `DACC2DHR` writer - DAC channel2 12-bit right-aligned data"]
pub type Dacc2dhrW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - DAC channel1 12-bit right-aligned data"]
    #[inline(always)]
    pub fn dacc1dhr(&self) -> Dacc1dhrR {
        Dacc1dhrR::new((self.bits & 0x0fff) as u16)
    }
    #[doc = "Bits 16:27 - DAC channel2 12-bit right-aligned data"]
    #[inline(always)]
    pub fn dacc2dhr(&self) -> Dacc2dhrR {
        Dacc2dhrR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - DAC channel1 12-bit right-aligned data"]
    #[inline(always)]
    #[must_use]
    pub fn dacc1dhr(&mut self) -> Dacc1dhrW<Dhr12rdSpec> {
        Dacc1dhrW::new(self, 0)
    }
    #[doc = "Bits 16:27 - DAC channel2 12-bit right-aligned data"]
    #[inline(always)]
    #[must_use]
    pub fn dacc2dhr(&mut self) -> Dacc2dhrW<Dhr12rdSpec> {
        Dacc2dhrW::new(self, 16)
    }
}
#[doc = "Dual DAC 12-bit right-aligned data holding register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dhr12rd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dhr12rd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dhr12rdSpec;
impl crate::RegisterSpec for Dhr12rdSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`dhr12rd::R`](R) reader structure"]
impl crate::Readable for Dhr12rdSpec {}
#[doc = "`write(|w| ..)` method takes [`dhr12rd::W`](W) writer structure"]
impl crate::Writable for Dhr12rdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DHR12RD to value 0"]
impl crate::Resettable for Dhr12rdSpec {
    const RESET_VALUE: u32 = 0;
}
