// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_txflr` reader"]
pub type R = crate::R<IcTxflrSpec>;
#[doc = "Register `ic_txflr` writer"]
pub type W = crate::W<IcTxflrSpec>;
#[doc = "Field `txflr` reader - Transmit FIFO Level.Contains the number of valid data entries in the transmit FIFO."]
pub type TxflrR = crate::FieldReader;
#[doc = "Field `txflr` writer - Transmit FIFO Level.Contains the number of valid data entries in the transmit FIFO."]
pub type TxflrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:6 - Transmit FIFO Level.Contains the number of valid data entries in the transmit FIFO."]
    #[inline(always)]
    pub fn txflr(&self) -> TxflrR {
        TxflrR::new((self.bits & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:6 - Transmit FIFO Level.Contains the number of valid data entries in the transmit FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn txflr(&mut self) -> TxflrW<IcTxflrSpec> {
        TxflrW::new(self, 0)
    }
}
#[doc = "This register contains the number of valid data entries in the transmit FIFO buffer. It is cleared whenever: - The I2C is disabled - There is a transmit abort that is, TX_ABRT bit is set in the ic_raw_intr_stat register. The slave bulk transmit mode is aborted The register increments whenever data is placed into the transmit FIFO and decrements when data is taken from the transmit FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_txflr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcTxflrSpec;
impl crate::RegisterSpec for IcTxflrSpec {
    type Ux = u32;
    const OFFSET: u64 = 116u64;
}
#[doc = "`read()` method returns [`ic_txflr::R`](R) reader structure"]
impl crate::Readable for IcTxflrSpec {}
#[doc = "`reset()` method sets ic_txflr to value 0"]
impl crate::Resettable for IcTxflrSpec {
    const RESET_VALUE: u32 = 0;
}
