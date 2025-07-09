// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rxuicr` reader"]
pub type R = crate::R<RxuicrSpec>;
#[doc = "Register `rxuicr` writer"]
pub type W = crate::W<RxuicrSpec>;
#[doc = "Field `rxuicr` reader - This register reflects the status of the interrupt. A read from this register clears the spi_rxu_intr interrupt; writing has no effect."]
pub type RxuicrR = crate::BitReader;
#[doc = "Field `rxuicr` writer - This register reflects the status of the interrupt. A read from this register clears the spi_rxu_intr interrupt; writing has no effect."]
pub type RxuicrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the spi_rxu_intr interrupt; writing has no effect."]
    #[inline(always)]
    pub fn rxuicr(&self) -> RxuicrR {
        RxuicrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the spi_rxu_intr interrupt; writing has no effect."]
    #[inline(always)]
    #[must_use]
    pub fn rxuicr(&mut self) -> RxuicrW<RxuicrSpec> {
        RxuicrW::new(self, 0)
    }
}
#[doc = "Receive FIFO Underflow Interrupt Clear Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxuicr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxuicrSpec;
impl crate::RegisterSpec for RxuicrSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`rxuicr::R`](R) reader structure"]
impl crate::Readable for RxuicrSpec {}
#[doc = "`reset()` method sets rxuicr to value 0"]
impl crate::Resettable for RxuicrSpec {
    const RESET_VALUE: u32 = 0;
}
