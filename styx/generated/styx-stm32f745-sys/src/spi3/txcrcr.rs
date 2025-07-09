// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TXCRCR` reader"]
pub type R = crate::R<TxcrcrSpec>;
#[doc = "Register `TXCRCR` writer"]
pub type W = crate::W<TxcrcrSpec>;
#[doc = "Field `TxCRC` reader - Tx CRC register"]
pub type TxCrcR = crate::FieldReader<u16>;
#[doc = "Field `TxCRC` writer - Tx CRC register"]
pub type TxCrcW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Tx CRC register"]
    #[inline(always)]
    pub fn tx_crc(&self) -> TxCrcR {
        TxCrcR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Tx CRC register"]
    #[inline(always)]
    #[must_use]
    pub fn tx_crc(&mut self) -> TxCrcW<TxcrcrSpec> {
        TxCrcW::new(self, 0)
    }
}
#[doc = "TX CRC register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txcrcr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxcrcrSpec;
impl crate::RegisterSpec for TxcrcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`txcrcr::R`](R) reader structure"]
impl crate::Readable for TxcrcrSpec {}
#[doc = "`reset()` method sets TXCRCR to value 0"]
impl crate::Resettable for TxcrcrSpec {
    const RESET_VALUE: u32 = 0;
}
