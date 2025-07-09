// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `tcbcnt` reader"]
pub type R = crate::R<TcbcntSpec>;
#[doc = "Register `tcbcnt` writer"]
pub type W = crate::W<TcbcntSpec>;
#[doc = "Field `trans_card_byte_count` reader - Number of bytes transferred by CIU unit to card."]
pub type TransCardByteCountR = crate::FieldReader<u32>;
#[doc = "Field `trans_card_byte_count` writer - Number of bytes transferred by CIU unit to card."]
pub type TransCardByteCountW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes transferred by CIU unit to card."]
    #[inline(always)]
    pub fn trans_card_byte_count(&self) -> TransCardByteCountR {
        TransCardByteCountR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes transferred by CIU unit to card."]
    #[inline(always)]
    #[must_use]
    pub fn trans_card_byte_count(&mut self) -> TransCardByteCountW<TcbcntSpec> {
        TransCardByteCountW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tcbcnt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TcbcntSpec;
impl crate::RegisterSpec for TcbcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`tcbcnt::R`](R) reader structure"]
impl crate::Readable for TcbcntSpec {}
#[doc = "`reset()` method sets tcbcnt to value 0"]
impl crate::Resettable for TcbcntSpec {
    const RESET_VALUE: u32 = 0;
}
