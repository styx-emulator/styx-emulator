// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_target_err_addr_lo` reader"]
pub type R = crate::R<DmaTargetErrAddrLoSpec>;
#[doc = "Register `dma_target_err_addr_lo` writer"]
pub type W = crate::W<DmaTargetErrAddrLoSpec>;
#[doc = "Field `value` reader - Least significant 16 bits"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Least significant 16 bits"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Least significant 16 bits"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Least significant 16 bits"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DmaTargetErrAddrLoSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Transaction address for which controller initiator interface received an ERROR target response.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_target_err_addr_lo::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaTargetErrAddrLoSpec;
impl crate::RegisterSpec for DmaTargetErrAddrLoSpec {
    type Ux = u32;
    const OFFSET: u64 = 1856u64;
}
#[doc = "`read()` method returns [`dma_target_err_addr_lo::R`](R) reader structure"]
impl crate::Readable for DmaTargetErrAddrLoSpec {}
#[doc = "`reset()` method sets dma_target_err_addr_lo to value 0"]
impl crate::Resettable for DmaTargetErrAddrLoSpec {
    const RESET_VALUE: u32 = 0;
}
