// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TXDR` reader"]
pub type R = crate::R<TxdrSpec>;
#[doc = "Register `TXDR` writer"]
pub type W = crate::W<TxdrSpec>;
#[doc = "Field `TXDATA` reader - 8-bit transmit data"]
pub type TxdataR = crate::FieldReader;
#[doc = "Field `TXDATA` writer - 8-bit transmit data"]
pub type TxdataW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - 8-bit transmit data"]
    #[inline(always)]
    pub fn txdata(&self) -> TxdataR {
        TxdataR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - 8-bit transmit data"]
    #[inline(always)]
    #[must_use]
    pub fn txdata(&mut self) -> TxdataW<TxdrSpec> {
        TxdataW::new(self, 0)
    }
}
#[doc = "Transmit data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txdr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txdr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxdrSpec;
impl crate::RegisterSpec for TxdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`txdr::R`](R) reader structure"]
impl crate::Readable for TxdrSpec {}
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
