// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `tfl` reader"]
pub type R = crate::R<TflSpec>;
#[doc = "Register `tfl` writer"]
pub type W = crate::W<TflSpec>;
#[doc = "Field `tfl` reader - This indicates the number of data entries in the transmit FIFO."]
pub type TflR = crate::FieldReader;
#[doc = "Field `tfl` writer - This indicates the number of data entries in the transmit FIFO."]
pub type TflW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - This indicates the number of data entries in the transmit FIFO."]
    #[inline(always)]
    pub fn tfl(&self) -> TflR {
        TflR::new((self.bits & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - This indicates the number of data entries in the transmit FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn tfl(&mut self) -> TflW<TflSpec> {
        TflW::new(self, 0)
    }
}
#[doc = "This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tfl::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TflSpec;
impl crate::RegisterSpec for TflSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`tfl::R`](R) reader structure"]
impl crate::Readable for TflSpec {}
#[doc = "`reset()` method sets tfl to value 0"]
impl crate::Resettable for TflSpec {
    const RESET_VALUE: u32 = 0;
}
