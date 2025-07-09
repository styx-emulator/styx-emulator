// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CDR` reader"]
pub type R = crate::R<CdrSpec>;
#[doc = "Register `CDR` writer"]
pub type W = crate::W<CdrSpec>;
#[doc = "Field `DATA1` reader - 1st data item of a pair of regular conversions"]
pub type Data1R = crate::FieldReader<u16>;
#[doc = "Field `DATA1` writer - 1st data item of a pair of regular conversions"]
pub type Data1W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `DATA2` reader - 2nd data item of a pair of regular conversions"]
pub type Data2R = crate::FieldReader<u16>;
#[doc = "Field `DATA2` writer - 2nd data item of a pair of regular conversions"]
pub type Data2W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - 1st data item of a pair of regular conversions"]
    #[inline(always)]
    pub fn data1(&self) -> Data1R {
        Data1R::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - 2nd data item of a pair of regular conversions"]
    #[inline(always)]
    pub fn data2(&self) -> Data2R {
        Data2R::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - 1st data item of a pair of regular conversions"]
    #[inline(always)]
    #[must_use]
    pub fn data1(&mut self) -> Data1W<CdrSpec> {
        Data1W::new(self, 0)
    }
    #[doc = "Bits 16:31 - 2nd data item of a pair of regular conversions"]
    #[inline(always)]
    #[must_use]
    pub fn data2(&mut self) -> Data2W<CdrSpec> {
        Data2W::new(self, 16)
    }
}
#[doc = "ADC common regular data register for dual and triple modes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CdrSpec;
impl crate::RegisterSpec for CdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`cdr::R`](R) reader structure"]
impl crate::Readable for CdrSpec {}
#[doc = "`reset()` method sets CDR to value 0"]
impl crate::Resettable for CdrSpec {
    const RESET_VALUE: u32 = 0;
}
