// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `txflr` reader"]
pub type R = crate::R<TxflrSpec>;
#[doc = "Register `txflr` writer"]
pub type W = crate::W<TxflrSpec>;
#[doc = "Field `txtfl` reader - Contains the number of valid data entries in the transmit FIFO."]
pub type TxtflR = crate::FieldReader<u16>;
#[doc = "Field `txtfl` writer - Contains the number of valid data entries in the transmit FIFO."]
pub type TxtflW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:8 - Contains the number of valid data entries in the transmit FIFO."]
    #[inline(always)]
    pub fn txtfl(&self) -> TxtflR {
        TxtflR::new((self.bits & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Contains the number of valid data entries in the transmit FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn txtfl(&mut self) -> TxtflW<TxflrSpec> {
        TxtflW::new(self, 0)
    }
}
#[doc = "This register contains the number of valid data entries in the transmit FIFO memory. Ranges from 0 to 256.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txflr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxflrSpec;
impl crate::RegisterSpec for TxflrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`txflr::R`](R) reader structure"]
impl crate::Readable for TxflrSpec {}
#[doc = "`reset()` method sets txflr to value 0"]
impl crate::Resettable for TxflrSpec {
    const RESET_VALUE: u32 = 0;
}
