// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_prefetch_mode` reader"]
pub type R = crate::R<ConfigPrefetchModeSpec>;
#[doc = "Register `config_prefetch_mode` writer"]
pub type W = crate::W<ConfigPrefetchModeSpec>;
#[doc = "Field `prefetch_en` reader - Enable prefetch of Data"]
pub type PrefetchEnR = crate::BitReader;
#[doc = "Field `prefetch_en` writer - Enable prefetch of Data"]
pub type PrefetchEnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `prefetch_burst_length` reader - If prefetch_en is set and prefetch_burst_length is set to ZERO, the controller will start prefetching data only after the receiving the first Map01 read command for the page. If prefetch_en is set and prefetch_burst_length is set to a non-ZERO, valid value, the controller will start prefetching data corresponding to this value even before the first Map01 for the current page has been received. The value written here should be in bytes."]
pub type PrefetchBurstLengthR = crate::FieldReader<u16>;
#[doc = "Field `prefetch_burst_length` writer - If prefetch_en is set and prefetch_burst_length is set to ZERO, the controller will start prefetching data only after the receiving the first Map01 read command for the page. If prefetch_en is set and prefetch_burst_length is set to a non-ZERO, valid value, the controller will start prefetching data corresponding to this value even before the first Map01 for the current page has been received. The value written here should be in bytes."]
pub type PrefetchBurstLengthW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bit 0 - Enable prefetch of Data"]
    #[inline(always)]
    pub fn prefetch_en(&self) -> PrefetchEnR {
        PrefetchEnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 4:15 - If prefetch_en is set and prefetch_burst_length is set to ZERO, the controller will start prefetching data only after the receiving the first Map01 read command for the page. If prefetch_en is set and prefetch_burst_length is set to a non-ZERO, valid value, the controller will start prefetching data corresponding to this value even before the first Map01 for the current page has been received. The value written here should be in bytes."]
    #[inline(always)]
    pub fn prefetch_burst_length(&self) -> PrefetchBurstLengthR {
        PrefetchBurstLengthR::new(((self.bits >> 4) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - Enable prefetch of Data"]
    #[inline(always)]
    #[must_use]
    pub fn prefetch_en(&mut self) -> PrefetchEnW<ConfigPrefetchModeSpec> {
        PrefetchEnW::new(self, 0)
    }
    #[doc = "Bits 4:15 - If prefetch_en is set and prefetch_burst_length is set to ZERO, the controller will start prefetching data only after the receiving the first Map01 read command for the page. If prefetch_en is set and prefetch_burst_length is set to a non-ZERO, valid value, the controller will start prefetching data corresponding to this value even before the first Map01 for the current page has been received. The value written here should be in bytes."]
    #[inline(always)]
    #[must_use]
    pub fn prefetch_burst_length(&mut self) -> PrefetchBurstLengthW<ConfigPrefetchModeSpec> {
        PrefetchBurstLengthW::new(self, 4)
    }
}
#[doc = "Enables read data prefetching to faster performance\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_prefetch_mode::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_prefetch_mode::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigPrefetchModeSpec;
impl crate::RegisterSpec for ConfigPrefetchModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 192u64;
}
#[doc = "`read()` method returns [`config_prefetch_mode::R`](R) reader structure"]
impl crate::Readable for ConfigPrefetchModeSpec {}
#[doc = "`write(|w| ..)` method takes [`config_prefetch_mode::W`](W) writer structure"]
impl crate::Writable for ConfigPrefetchModeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_prefetch_mode to value 0x01"]
impl crate::Resettable for ConfigPrefetchModeSpec {
    const RESET_VALUE: u32 = 0x01;
}
