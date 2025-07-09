// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rxflr` reader"]
pub type R = crate::R<RxflrSpec>;
#[doc = "Register `rxflr` writer"]
pub type W = crate::W<RxflrSpec>;
#[doc = "Field `rxtfl` reader - Contains the number of valid data entries in the receive FIFO."]
pub type RxtflR = crate::FieldReader<u16>;
#[doc = "Field `rxtfl` writer - Contains the number of valid data entries in the receive FIFO."]
pub type RxtflW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:8 - Contains the number of valid data entries in the receive FIFO."]
    #[inline(always)]
    pub fn rxtfl(&self) -> RxtflR {
        RxtflR::new((self.bits & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Contains the number of valid data entries in the receive FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rxtfl(&mut self) -> RxtflW<RxflrSpec> {
        RxtflW::new(self, 0)
    }
}
#[doc = "This register contains the number of valid data entriesin the receive FIFO memory. This register can be read at any time. Ranges from 0 to 256.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxflr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxflrSpec;
impl crate::RegisterSpec for RxflrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`rxflr::R`](R) reader structure"]
impl crate::Readable for RxflrSpec {}
#[doc = "`reset()` method sets rxflr to value 0"]
impl crate::Resettable for RxflrSpec {
    const RESET_VALUE: u32 = 0;
}
