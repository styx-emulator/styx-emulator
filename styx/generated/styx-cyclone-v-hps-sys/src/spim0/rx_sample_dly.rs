// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rx_sample_dly` reader"]
pub type R = crate::R<RxSampleDlySpec>;
#[doc = "Register `rx_sample_dly` writer"]
pub type W = crate::W<RxSampleDlySpec>;
#[doc = "Field `rsd` reader - This register is used to delay the sample of the rxd input port. Each value represents a single spi_m_clk delay on the sample of rxd. Note; If this register is programmed with a value that exceeds 64, a 0 delay will be applied to the receive sample. The maximum delay is 64 spi_m_clk cycles."]
pub type RsdR = crate::FieldReader;
#[doc = "Field `rsd` writer - This register is used to delay the sample of the rxd input port. Each value represents a single spi_m_clk delay on the sample of rxd. Note; If this register is programmed with a value that exceeds 64, a 0 delay will be applied to the receive sample. The maximum delay is 64 spi_m_clk cycles."]
pub type RsdW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:6 - This register is used to delay the sample of the rxd input port. Each value represents a single spi_m_clk delay on the sample of rxd. Note; If this register is programmed with a value that exceeds 64, a 0 delay will be applied to the receive sample. The maximum delay is 64 spi_m_clk cycles."]
    #[inline(always)]
    pub fn rsd(&self) -> RsdR {
        RsdR::new((self.bits & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:6 - This register is used to delay the sample of the rxd input port. Each value represents a single spi_m_clk delay on the sample of rxd. Note; If this register is programmed with a value that exceeds 64, a 0 delay will be applied to the receive sample. The maximum delay is 64 spi_m_clk cycles."]
    #[inline(always)]
    #[must_use]
    pub fn rsd(&mut self) -> RsdW<RxSampleDlySpec> {
        RsdW::new(self, 0)
    }
}
#[doc = "This register controls the number of spi_m_clk cycles that are delayed (from the default sample time) before the actual sample of the rxd input occurs. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rx_sample_dly::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rx_sample_dly::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxSampleDlySpec;
impl crate::RegisterSpec for RxSampleDlySpec {
    type Ux = u32;
    const OFFSET: u64 = 252u64;
}
#[doc = "`read()` method returns [`rx_sample_dly::R`](R) reader structure"]
impl crate::Readable for RxSampleDlySpec {}
#[doc = "`write(|w| ..)` method takes [`rx_sample_dly::W`](W) writer structure"]
impl crate::Writable for RxSampleDlySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets rx_sample_dly to value 0"]
impl crate::Resettable for RxSampleDlySpec {
    const RESET_VALUE: u32 = 0;
}
