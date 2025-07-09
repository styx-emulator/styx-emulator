// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RDR` reader"]
pub type R = crate::R<RdrSpec>;
#[doc = "Register `RDR` writer"]
pub type W = crate::W<RdrSpec>;
#[doc = "Field `RDR` reader - Receive data value"]
pub type RdrR = crate::FieldReader<u16>;
#[doc = "Field `RDR` writer - Receive data value"]
pub type RdrW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:8 - Receive data value"]
    #[inline(always)]
    pub fn rdr(&self) -> RdrR {
        RdrR::new((self.bits & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Receive data value"]
    #[inline(always)]
    #[must_use]
    pub fn rdr(&mut self) -> RdrW<RdrSpec> {
        RdrW::new(self, 0)
    }
}
#[doc = "Receive data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RdrSpec;
impl crate::RegisterSpec for RdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`rdr::R`](R) reader structure"]
impl crate::Readable for RdrSpec {}
#[doc = "`reset()` method sets RDR to value 0"]
impl crate::Resettable for RdrSpec {
    const RESET_VALUE: u32 = 0;
}
