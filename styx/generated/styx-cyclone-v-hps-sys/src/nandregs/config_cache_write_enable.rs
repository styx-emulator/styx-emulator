// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_cache_write_enable` reader"]
pub type R = crate::R<ConfigCacheWriteEnableSpec>;
#[doc = "Register `config_cache_write_enable` writer"]
pub type W = crate::W<ConfigCacheWriteEnableSpec>;
#[doc = "Field `flag` reader - list\\]\\[*\\]1 - Cache write supported \\[*\\]0 - Cache write not supported\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - list\\]\\[*\\]1 - Cache write supported \\[*\\]0 - Cache write not supported\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Cache write supported \\[*\\]0 - Cache write not supported\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Cache write supported \\[*\\]0 - Cache write not supported\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigCacheWriteEnableSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Device supports cache write command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_cache_write_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_cache_write_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigCacheWriteEnableSpec;
impl crate::RegisterSpec for ConfigCacheWriteEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 160u64;
}
#[doc = "`read()` method returns [`config_cache_write_enable::R`](R) reader structure"]
impl crate::Readable for ConfigCacheWriteEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`config_cache_write_enable::W`](W) writer structure"]
impl crate::Writable for ConfigCacheWriteEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_cache_write_enable to value 0"]
impl crate::Resettable for ConfigCacheWriteEnableSpec {
    const RESET_VALUE: u32 = 0;
}
