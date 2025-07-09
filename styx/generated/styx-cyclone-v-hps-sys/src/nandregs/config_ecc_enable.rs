// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_ecc_enable` reader"]
pub type R = crate::R<ConfigEccEnableSpec>;
#[doc = "Register `config_ecc_enable` writer"]
pub type W = crate::W<ConfigEccEnableSpec>;
#[doc = "Field `flag` reader - Enables or disables controller ECC capabilities. When enabled, controller calculates ECC check-bits and writes them onto device on program operation. On page reads, check-bits are recomputed and errors reported, if any, after comparing with stored check-bits. When disabled, controller does not compute check-bits. \\[list\\]\\[*\\]1 - ECC Enabled \\[*\\]0 - ECC disabled\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - Enables or disables controller ECC capabilities. When enabled, controller calculates ECC check-bits and writes them onto device on program operation. On page reads, check-bits are recomputed and errors reported, if any, after comparing with stored check-bits. When disabled, controller does not compute check-bits. \\[list\\]\\[*\\]1 - ECC Enabled \\[*\\]0 - ECC disabled\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enables or disables controller ECC capabilities. When enabled, controller calculates ECC check-bits and writes them onto device on program operation. On page reads, check-bits are recomputed and errors reported, if any, after comparing with stored check-bits. When disabled, controller does not compute check-bits. \\[list\\]\\[*\\]1 - ECC Enabled \\[*\\]0 - ECC disabled\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables or disables controller ECC capabilities. When enabled, controller calculates ECC check-bits and writes them onto device on program operation. On page reads, check-bits are recomputed and errors reported, if any, after comparing with stored check-bits. When disabled, controller does not compute check-bits. \\[list\\]\\[*\\]1 - ECC Enabled \\[*\\]0 - ECC disabled\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigEccEnableSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Enable controller ECC check bit generation and correction\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_ecc_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_ecc_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigEccEnableSpec;
impl crate::RegisterSpec for ConfigEccEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 224u64;
}
#[doc = "`read()` method returns [`config_ecc_enable::R`](R) reader structure"]
impl crate::Readable for ConfigEccEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`config_ecc_enable::W`](W) writer structure"]
impl crate::Writable for ConfigEccEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_ecc_enable to value 0x01"]
impl crate::Resettable for ConfigEccEnableSpec {
    const RESET_VALUE: u32 = 0x01;
}
