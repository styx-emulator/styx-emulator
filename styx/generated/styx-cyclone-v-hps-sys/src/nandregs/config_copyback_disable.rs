// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_copyback_disable` reader"]
pub type R = crate::R<ConfigCopybackDisableSpec>;
#[doc = "Register `config_copyback_disable` writer"]
pub type W = crate::W<ConfigCopybackDisableSpec>;
#[doc = "Field `flag` reader - list\\]\\[*\\]1 - Copyback disabled \\[*\\]0 - Copyback enabled\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - list\\]\\[*\\]1 - Copyback disabled \\[*\\]0 - Copyback enabled\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Copyback disabled \\[*\\]0 - Copyback enabled\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Copyback disabled \\[*\\]0 - Copyback enabled\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigCopybackDisableSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Device does not support copyback command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_copyback_disable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_copyback_disable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigCopybackDisableSpec;
impl crate::RegisterSpec for ConfigCopybackDisableSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`config_copyback_disable::R`](R) reader structure"]
impl crate::Readable for ConfigCopybackDisableSpec {}
#[doc = "`write(|w| ..)` method takes [`config_copyback_disable::W`](W) writer structure"]
impl crate::Writable for ConfigCopybackDisableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_copyback_disable to value 0"]
impl crate::Resettable for ConfigCopybackDisableSpec {
    const RESET_VALUE: u32 = 0;
}
