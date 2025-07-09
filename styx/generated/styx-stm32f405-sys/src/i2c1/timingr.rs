// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TIMINGR` reader"]
pub type R = crate::R<TimingrSpec>;
#[doc = "Register `TIMINGR` writer"]
pub type W = crate::W<TimingrSpec>;
#[doc = "Field `SCLL` reader - SCL low period (master mode)"]
pub type ScllR = crate::FieldReader;
#[doc = "Field `SCLL` writer - SCL low period (master mode)"]
pub type ScllW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `SCLH` reader - SCL high period (master mode)"]
pub type SclhR = crate::FieldReader;
#[doc = "Field `SCLH` writer - SCL high period (master mode)"]
pub type SclhW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `SDADEL` reader - Data hold time"]
pub type SdadelR = crate::FieldReader;
#[doc = "Field `SDADEL` writer - Data hold time"]
pub type SdadelW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `SCLDEL` reader - Data setup time"]
pub type ScldelR = crate::FieldReader;
#[doc = "Field `SCLDEL` writer - Data setup time"]
pub type ScldelW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PRESC` reader - Timing prescaler"]
pub type PrescR = crate::FieldReader;
#[doc = "Field `PRESC` writer - Timing prescaler"]
pub type PrescW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:7 - SCL low period (master mode)"]
    #[inline(always)]
    pub fn scll(&self) -> ScllR {
        ScllR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - SCL high period (master mode)"]
    #[inline(always)]
    pub fn sclh(&self) -> SclhR {
        SclhR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:19 - Data hold time"]
    #[inline(always)]
    pub fn sdadel(&self) -> SdadelR {
        SdadelR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - Data setup time"]
    #[inline(always)]
    pub fn scldel(&self) -> ScldelR {
        ScldelR::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bits 28:31 - Timing prescaler"]
    #[inline(always)]
    pub fn presc(&self) -> PrescR {
        PrescR::new(((self.bits >> 28) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - SCL low period (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn scll(&mut self) -> ScllW<TimingrSpec> {
        ScllW::new(self, 0)
    }
    #[doc = "Bits 8:15 - SCL high period (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn sclh(&mut self) -> SclhW<TimingrSpec> {
        SclhW::new(self, 8)
    }
    #[doc = "Bits 16:19 - Data hold time"]
    #[inline(always)]
    #[must_use]
    pub fn sdadel(&mut self) -> SdadelW<TimingrSpec> {
        SdadelW::new(self, 16)
    }
    #[doc = "Bits 20:23 - Data setup time"]
    #[inline(always)]
    #[must_use]
    pub fn scldel(&mut self) -> ScldelW<TimingrSpec> {
        ScldelW::new(self, 20)
    }
    #[doc = "Bits 28:31 - Timing prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn presc(&mut self) -> PrescW<TimingrSpec> {
        PrescW::new(self, 28)
    }
}
#[doc = "Timing register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timingr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`timingr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimingrSpec;
impl crate::RegisterSpec for TimingrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`timingr::R`](R) reader structure"]
impl crate::Readable for TimingrSpec {}
#[doc = "`write(|w| ..)` method takes [`timingr::W`](W) writer structure"]
impl crate::Writable for TimingrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TIMINGR to value 0"]
impl crate::Resettable for TimingrSpec {
    const RESET_VALUE: u32 = 0;
}
