// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `tmout` reader"]
pub type R = crate::R<TmoutSpec>;
#[doc = "Register `tmout` writer"]
pub type W = crate::W<TmoutSpec>;
#[doc = "Field `response_timeout` reader - Response timeout value. Value is in number of card output clocks sdmmc_cclk_out."]
pub type ResponseTimeoutR = crate::FieldReader;
#[doc = "Field `response_timeout` writer - Response timeout value. Value is in number of card output clocks sdmmc_cclk_out."]
pub type ResponseTimeoutW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `data_timeout` reader - Value for card Data Read Timeout; same value also used for Data Starvation by Host timeout. Value is in number of card output clocks sdmmc_cclk_out of selected card."]
pub type DataTimeoutR = crate::FieldReader<u32>;
#[doc = "Field `data_timeout` writer - Value for card Data Read Timeout; same value also used for Data Starvation by Host timeout. Value is in number of card output clocks sdmmc_cclk_out of selected card."]
pub type DataTimeoutW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:7 - Response timeout value. Value is in number of card output clocks sdmmc_cclk_out."]
    #[inline(always)]
    pub fn response_timeout(&self) -> ResponseTimeoutR {
        ResponseTimeoutR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:31 - Value for card Data Read Timeout; same value also used for Data Starvation by Host timeout. Value is in number of card output clocks sdmmc_cclk_out of selected card."]
    #[inline(always)]
    pub fn data_timeout(&self) -> DataTimeoutR {
        DataTimeoutR::new((self.bits >> 8) & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:7 - Response timeout value. Value is in number of card output clocks sdmmc_cclk_out."]
    #[inline(always)]
    #[must_use]
    pub fn response_timeout(&mut self) -> ResponseTimeoutW<TmoutSpec> {
        ResponseTimeoutW::new(self, 0)
    }
    #[doc = "Bits 8:31 - Value for card Data Read Timeout; same value also used for Data Starvation by Host timeout. Value is in number of card output clocks sdmmc_cclk_out of selected card."]
    #[inline(always)]
    #[must_use]
    pub fn data_timeout(&mut self) -> DataTimeoutW<TmoutSpec> {
        DataTimeoutW::new(self, 8)
    }
}
#[doc = "Sets timeout values\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tmout::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tmout::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TmoutSpec;
impl crate::RegisterSpec for TmoutSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`tmout::R`](R) reader structure"]
impl crate::Readable for TmoutSpec {}
#[doc = "`write(|w| ..)` method takes [`tmout::W`](W) writer structure"]
impl crate::Writable for TmoutSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets tmout to value 0xffff_ff40"]
impl crate::Resettable for TmoutSpec {
    const RESET_VALUE: u32 = 0xffff_ff40;
}
