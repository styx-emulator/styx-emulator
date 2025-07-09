// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TXDR` reader"]
pub type R = crate::R<TxdrSpec>;
#[doc = "Register `TXDR` writer"]
pub type W = crate::W<TxdrSpec>;
#[doc = "Field `TXD` reader - Tx Data register"]
pub type TxdR = crate::FieldReader;
#[doc = "Field `TXD` writer - Tx Data register"]
pub type TxdW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Tx Data register"]
    #[inline(always)]
    pub fn txd(&self) -> TxdR {
        TxdR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Tx Data register"]
    #[inline(always)]
    #[must_use]
    pub fn txd(&mut self) -> TxdW<TxdrSpec> {
        TxdW::new(self, 0)
    }
}
#[doc = "Tx data register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txdr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxdrSpec;
impl crate::RegisterSpec for TxdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`write(|w| ..)` method takes [`txdr::W`](W) writer structure"]
impl crate::Writable for TxdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TXDR to value 0"]
impl crate::Resettable for TxdrSpec {
    const RESET_VALUE: u32 = 0;
}
