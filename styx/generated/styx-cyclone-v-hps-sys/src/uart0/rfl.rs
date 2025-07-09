// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rfl` reader"]
pub type R = crate::R<RflSpec>;
#[doc = "Register `rfl` writer"]
pub type W = crate::W<RflSpec>;
#[doc = "Field `rfl` reader - This indicates the number of data entries in the receive FIFO."]
pub type RflR = crate::FieldReader;
#[doc = "Field `rfl` writer - This indicates the number of data entries in the receive FIFO."]
pub type RflW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - This indicates the number of data entries in the receive FIFO."]
    #[inline(always)]
    pub fn rfl(&self) -> RflR {
        RflR::new((self.bits & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - This indicates the number of data entries in the receive FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rfl(&mut self) -> RflW<RflSpec> {
        RflW::new(self, 0)
    }
}
#[doc = "This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rfl::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RflSpec;
impl crate::RegisterSpec for RflSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`rfl::R`](R) reader structure"]
impl crate::Readable for RflSpec {}
#[doc = "`reset()` method sets rfl to value 0"]
impl crate::Resettable for RflSpec {
    const RESET_VALUE: u32 = 0;
}
