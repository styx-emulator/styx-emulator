// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `status_err_block_addr1` reader"]
pub type R = crate::R<StatusErrBlockAddr1Spec>;
#[doc = "Register `status_err_block_addr1` writer"]
pub type W = crate::W<StatusErrBlockAddr1Spec>;
#[doc = "Field `value` reader - Holds the block address that resulted in a failure on program or erase operation."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Holds the block address that resulted in a failure on program or erase operation."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Holds the block address that resulted in a failure on program or erase operation."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Holds the block address that resulted in a failure on program or erase operation."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<StatusErrBlockAddr1Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Erred block address bank 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_block_addr1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusErrBlockAddr1Spec;
impl crate::RegisterSpec for StatusErrBlockAddr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 1184u64;
}
#[doc = "`read()` method returns [`status_err_block_addr1::R`](R) reader structure"]
impl crate::Readable for StatusErrBlockAddr1Spec {}
#[doc = "`reset()` method sets status_err_block_addr1 to value 0"]
impl crate::Resettable for StatusErrBlockAddr1Spec {
    const RESET_VALUE: u32 = 0;
}
