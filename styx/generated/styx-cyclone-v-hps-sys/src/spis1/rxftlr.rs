// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rxftlr` reader"]
pub type R = crate::R<RxftlrSpec>;
#[doc = "Register `rxftlr` writer"]
pub type W = crate::W<RxftlrSpec>;
#[doc = "Field `rft` reader - Controls the level of entries (or above) at which the receive FIFO controller triggers an interrupt. When the number of receive FIFO entries is greater than or equal to this value + 1, the receive FIFO full interrupt is triggered."]
pub type RftR = crate::FieldReader;
#[doc = "Field `rft` writer - Controls the level of entries (or above) at which the receive FIFO controller triggers an interrupt. When the number of receive FIFO entries is greater than or equal to this value + 1, the receive FIFO full interrupt is triggered."]
pub type RftW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Controls the level of entries (or above) at which the receive FIFO controller triggers an interrupt. When the number of receive FIFO entries is greater than or equal to this value + 1, the receive FIFO full interrupt is triggered."]
    #[inline(always)]
    pub fn rft(&self) -> RftR {
        RftR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Controls the level of entries (or above) at which the receive FIFO controller triggers an interrupt. When the number of receive FIFO entries is greater than or equal to this value + 1, the receive FIFO full interrupt is triggered."]
    #[inline(always)]
    #[must_use]
    pub fn rft(&mut self) -> RftW<RxftlrSpec> {
        RftW::new(self, 0)
    }
}
#[doc = "This register controls the threshold value for the receive FIFO memory. It is impossible to write to this register when the SPI Slave is enabled. The SPI Slave is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxftlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rxftlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxftlrSpec;
impl crate::RegisterSpec for RxftlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`rxftlr::R`](R) reader structure"]
impl crate::Readable for RxftlrSpec {}
#[doc = "`write(|w| ..)` method takes [`rxftlr::W`](W) writer structure"]
impl crate::Writable for RxftlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets rxftlr to value 0"]
impl crate::Resettable for RxftlrSpec {
    const RESET_VALUE: u32 = 0;
}
