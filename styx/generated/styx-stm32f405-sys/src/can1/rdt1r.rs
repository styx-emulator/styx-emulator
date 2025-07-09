// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RDT1R` reader"]
pub type R = crate::R<Rdt1rSpec>;
#[doc = "Register `RDT1R` writer"]
pub type W = crate::W<Rdt1rSpec>;
#[doc = "Field `DLC` reader - DLC"]
pub type DlcR = crate::FieldReader;
#[doc = "Field `DLC` writer - DLC"]
pub type DlcW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `FMI` reader - FMI"]
pub type FmiR = crate::FieldReader;
#[doc = "Field `FMI` writer - FMI"]
pub type FmiW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `TIME` reader - TIME"]
pub type TimeR = crate::FieldReader<u16>;
#[doc = "Field `TIME` writer - TIME"]
pub type TimeW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:3 - DLC"]
    #[inline(always)]
    pub fn dlc(&self) -> DlcR {
        DlcR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 8:15 - FMI"]
    #[inline(always)]
    pub fn fmi(&self) -> FmiR {
        FmiR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:31 - TIME"]
    #[inline(always)]
    pub fn time(&self) -> TimeR {
        TimeR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:3 - DLC"]
    #[inline(always)]
    #[must_use]
    pub fn dlc(&mut self) -> DlcW<Rdt1rSpec> {
        DlcW::new(self, 0)
    }
    #[doc = "Bits 8:15 - FMI"]
    #[inline(always)]
    #[must_use]
    pub fn fmi(&mut self) -> FmiW<Rdt1rSpec> {
        FmiW::new(self, 8)
    }
    #[doc = "Bits 16:31 - TIME"]
    #[inline(always)]
    #[must_use]
    pub fn time(&mut self) -> TimeW<Rdt1rSpec> {
        TimeW::new(self, 16)
    }
}
#[doc = "mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdt1r::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Rdt1rSpec;
impl crate::RegisterSpec for Rdt1rSpec {
    type Ux = u32;
    const OFFSET: u64 = 452u64;
}
#[doc = "`read()` method returns [`rdt1r::R`](R) reader structure"]
impl crate::Readable for Rdt1rSpec {}
#[doc = "`reset()` method sets RDT1R to value 0"]
impl crate::Resettable for Rdt1rSpec {
    const RESET_VALUE: u32 = 0;
}
