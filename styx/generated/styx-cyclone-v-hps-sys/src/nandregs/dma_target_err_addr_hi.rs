// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_target_err_addr_hi` reader"]
pub type R = crate::R<DmaTargetErrAddrHiSpec>;
#[doc = "Register `dma_target_err_addr_hi` writer"]
pub type W = crate::W<DmaTargetErrAddrHiSpec>;
#[doc = "Field `value` reader - Most significant 16 bits"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Most significant 16 bits"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Most significant 16 bits"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Most significant 16 bits"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DmaTargetErrAddrHiSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Transaction address for which controller initiator interface received an ERROR target response.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_target_err_addr_hi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaTargetErrAddrHiSpec;
impl crate::RegisterSpec for DmaTargetErrAddrHiSpec {
    type Ux = u32;
    const OFFSET: u64 = 1872u64;
}
#[doc = "`read()` method returns [`dma_target_err_addr_hi::R`](R) reader structure"]
impl crate::Readable for DmaTargetErrAddrHiSpec {}
#[doc = "`reset()` method sets dma_target_err_addr_hi to value 0"]
impl crate::Resettable for DmaTargetErrAddrHiSpec {
    const RESET_VALUE: u32 = 0;
}
