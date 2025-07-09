// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_cache_read_enable` reader"]
pub type R = crate::R<ConfigCacheReadEnableSpec>;
#[doc = "Register `config_cache_read_enable` writer"]
pub type W = crate::W<ConfigCacheReadEnableSpec>;
#[doc = "Field `flag` reader - list\\]\\[*\\]1 - Cache read supported \\[*\\]0 - Cache read not supported\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - list\\]\\[*\\]1 - Cache read supported \\[*\\]0 - Cache read not supported\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Cache read supported \\[*\\]0 - Cache read not supported\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Cache read supported \\[*\\]0 - Cache read not supported\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigCacheReadEnableSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Device supports cache read command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_cache_read_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_cache_read_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigCacheReadEnableSpec;
impl crate::RegisterSpec for ConfigCacheReadEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 176u64;
}
#[doc = "`read()` method returns [`config_cache_read_enable::R`](R) reader structure"]
impl crate::Readable for ConfigCacheReadEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`config_cache_read_enable::W`](W) writer structure"]
impl crate::Writable for ConfigCacheReadEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_cache_read_enable to value 0"]
impl crate::Resettable for ConfigCacheReadEnableSpec {
    const RESET_VALUE: u32 = 0;
}
