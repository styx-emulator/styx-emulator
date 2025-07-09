// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `txftlr` reader"]
pub type R = crate::R<TxftlrSpec>;
#[doc = "Register `txftlr` writer"]
pub type W = crate::W<TxftlrSpec>;
#[doc = "Field `tft` reader - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
pub type TftR = crate::FieldReader;
#[doc = "Field `tft` writer - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
pub type TftW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
    #[inline(always)]
    pub fn tft(&self) -> TftR {
        TftR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
    #[inline(always)]
    #[must_use]
    pub fn tft(&mut self) -> TftW<TxftlrSpec> {
        TftW::new(self, 0)
    }
}
#[doc = "This register controls the threshold value for the transmit FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txftlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txftlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxftlrSpec;
impl crate::RegisterSpec for TxftlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`txftlr::R`](R) reader structure"]
impl crate::Readable for TxftlrSpec {}
#[doc = "`write(|w| ..)` method takes [`txftlr::W`](W) writer structure"]
impl crate::Writable for TxftlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets txftlr to value 0"]
impl crate::Resettable for TxftlrSpec {
    const RESET_VALUE: u32 = 0;
}
