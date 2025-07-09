// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_tx_abrt` reader"]
pub type R = crate::R<IcClrTxAbrtSpec>;
#[doc = "Register `ic_clr_tx_abrt` writer"]
pub type W = crate::W<IcClrTxAbrtSpec>;
#[doc = "Field `clr_tx_abort` reader - Read this register to clear the TX_ABRT interrupt (bit 6) of the ic_raw_intr_stat register, and the ic_tx_abrt_source register. This also releases the TX FIFO from the flushed/reset state, allowing more writes to the TX FIFO. Refer to Bit 9 of the ic_tx_abrt_source register for an exception to clearing ic_tx_abrt_source."]
pub type ClrTxAbortR = crate::BitReader;
#[doc = "Field `clr_tx_abort` writer - Read this register to clear the TX_ABRT interrupt (bit 6) of the ic_raw_intr_stat register, and the ic_tx_abrt_source register. This also releases the TX FIFO from the flushed/reset state, allowing more writes to the TX FIFO. Refer to Bit 9 of the ic_tx_abrt_source register for an exception to clearing ic_tx_abrt_source."]
pub type ClrTxAbortW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the TX_ABRT interrupt (bit 6) of the ic_raw_intr_stat register, and the ic_tx_abrt_source register. This also releases the TX FIFO from the flushed/reset state, allowing more writes to the TX FIFO. Refer to Bit 9 of the ic_tx_abrt_source register for an exception to clearing ic_tx_abrt_source."]
    #[inline(always)]
    pub fn clr_tx_abort(&self) -> ClrTxAbortR {
        ClrTxAbortR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the TX_ABRT interrupt (bit 6) of the ic_raw_intr_stat register, and the ic_tx_abrt_source register. This also releases the TX FIFO from the flushed/reset state, allowing more writes to the TX FIFO. Refer to Bit 9 of the ic_tx_abrt_source register for an exception to clearing ic_tx_abrt_source."]
    #[inline(always)]
    #[must_use]
    pub fn clr_tx_abort(&mut self) -> ClrTxAbortW<IcClrTxAbrtSpec> {
        ClrTxAbortW::new(self, 0)
    }
}
#[doc = "Clear TX_ABRT Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_tx_abrt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrTxAbrtSpec;
impl crate::RegisterSpec for IcClrTxAbrtSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`ic_clr_tx_abrt::R`](R) reader structure"]
impl crate::Readable for IcClrTxAbrtSpec {}
#[doc = "`reset()` method sets ic_clr_tx_abrt to value 0"]
impl crate::Resettable for IcClrTxAbrtSpec {
    const RESET_VALUE: u32 = 0;
}
