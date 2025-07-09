// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_chip_enable_dont_care` reader"]
pub type R = crate::R<ConfigChipEnableDontCareSpec>;
#[doc = "Register `config_chip_enable_dont_care` writer"]
pub type W = crate::W<ConfigChipEnableDontCareSpec>;
#[doc = "Field `flag` reader - Controller can interleave commands between banks when this feature is enabled. \\[list\\]\\[*\\]1 - Device in dont care mode \\[*\\]0 - Device cares for chip enable\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - Controller can interleave commands between banks when this feature is enabled. \\[list\\]\\[*\\]1 - Device in dont care mode \\[*\\]0 - Device cares for chip enable\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Controller can interleave commands between banks when this feature is enabled. \\[list\\]\\[*\\]1 - Device in dont care mode \\[*\\]0 - Device cares for chip enable\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controller can interleave commands between banks when this feature is enabled. \\[list\\]\\[*\\]1 - Device in dont care mode \\[*\\]0 - Device cares for chip enable\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigChipEnableDontCareSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Device can work in the chip enable dont care mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_chip_enable_dont_care::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_chip_enable_dont_care::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigChipEnableDontCareSpec;
impl crate::RegisterSpec for ConfigChipEnableDontCareSpec {
    type Ux = u32;
    const OFFSET: u64 = 208u64;
}
#[doc = "`read()` method returns [`config_chip_enable_dont_care::R`](R) reader structure"]
impl crate::Readable for ConfigChipEnableDontCareSpec {}
#[doc = "`write(|w| ..)` method takes [`config_chip_enable_dont_care::W`](W) writer structure"]
impl crate::Writable for ConfigChipEnableDontCareSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_chip_enable_dont_care to value 0"]
impl crate::Resettable for ConfigChipEnableDontCareSpec {
    const RESET_VALUE: u32 = 0;
}
