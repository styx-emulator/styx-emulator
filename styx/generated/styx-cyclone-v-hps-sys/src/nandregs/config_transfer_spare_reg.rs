// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_transfer_spare_reg` reader"]
pub type R = crate::R<ConfigTransferSpareRegSpec>;
#[doc = "Register `config_transfer_spare_reg` writer"]
pub type W = crate::W<ConfigTransferSpareRegSpec>;
#[doc = "Field `flag` reader - On all read or write commands through Map 01, if this bit is set, data in spare area of memory will be transfered to host along with main area of data. The main area will be transfered followed by spare area.\\[list\\]\\[*\\]1 - MAIN+SPARE \\[*\\]0 - MAIN\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - On all read or write commands through Map 01, if this bit is set, data in spare area of memory will be transfered to host along with main area of data. The main area will be transfered followed by spare area.\\[list\\]\\[*\\]1 - MAIN+SPARE \\[*\\]0 - MAIN\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - On all read or write commands through Map 01, if this bit is set, data in spare area of memory will be transfered to host along with main area of data. The main area will be transfered followed by spare area.\\[list\\]\\[*\\]1 - MAIN+SPARE \\[*\\]0 - MAIN\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - On all read or write commands through Map 01, if this bit is set, data in spare area of memory will be transfered to host along with main area of data. The main area will be transfered followed by spare area.\\[list\\]\\[*\\]1 - MAIN+SPARE \\[*\\]0 - MAIN\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigTransferSpareRegSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Default data transfer mode. (Ignored during Spare only mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_transfer_spare_reg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_transfer_spare_reg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigTransferSpareRegSpec;
impl crate::RegisterSpec for ConfigTransferSpareRegSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`config_transfer_spare_reg::R`](R) reader structure"]
impl crate::Readable for ConfigTransferSpareRegSpec {}
#[doc = "`write(|w| ..)` method takes [`config_transfer_spare_reg::W`](W) writer structure"]
impl crate::Writable for ConfigTransferSpareRegSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_transfer_spare_reg to value 0"]
impl crate::Resettable for ConfigTransferSpareRegSpec {
    const RESET_VALUE: u32 = 0;
}
