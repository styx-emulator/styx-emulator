// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RXCRCR` reader"]
pub type R = crate::R<RxcrcrSpec>;
#[doc = "Register `RXCRCR` writer"]
pub type W = crate::W<RxcrcrSpec>;
#[doc = "Field `RxCRC` reader - Rx CRC register"]
pub type RxCrcR = crate::FieldReader<u16>;
#[doc = "Field `RxCRC` writer - Rx CRC register"]
pub type RxCrcW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Rx CRC register"]
    #[inline(always)]
    pub fn rx_crc(&self) -> RxCrcR {
        RxCrcR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Rx CRC register"]
    #[inline(always)]
    #[must_use]
    pub fn rx_crc(&mut self) -> RxCrcW<RxcrcrSpec> {
        RxCrcW::new(self, 0)
    }
}
#[doc = "RX CRC register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxcrcr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxcrcrSpec;
impl crate::RegisterSpec for RxcrcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`rxcrcr::R`](R) reader structure"]
impl crate::Readable for RxcrcrSpec {}
#[doc = "`reset()` method sets RXCRCR to value 0"]
impl crate::Resettable for RxcrcrSpec {
    const RESET_VALUE: u32 = 0;
}
