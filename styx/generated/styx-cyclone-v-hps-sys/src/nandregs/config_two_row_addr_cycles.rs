// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_two_row_addr_cycles` reader"]
pub type R = crate::R<ConfigTwoRowAddrCyclesSpec>;
#[doc = "Register `config_two_row_addr_cycles` writer"]
pub type W = crate::W<ConfigTwoRowAddrCyclesSpec>;
#[doc = "Field `flag` reader - This flag must be set for devices which allow for 2 ROW address cycles instead of the usual 3. Alternatively, the TWOROWADDR field of the System Manager NANDGRP_BOOTSTRAP register when asserted will set this flag."]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - This flag must be set for devices which allow for 2 ROW address cycles instead of the usual 3. Alternatively, the TWOROWADDR field of the System Manager NANDGRP_BOOTSTRAP register when asserted will set this flag."]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This flag must be set for devices which allow for 2 ROW address cycles instead of the usual 3. Alternatively, the TWOROWADDR field of the System Manager NANDGRP_BOOTSTRAP register when asserted will set this flag."]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This flag must be set for devices which allow for 2 ROW address cycles instead of the usual 3. Alternatively, the TWOROWADDR field of the System Manager NANDGRP_BOOTSTRAP register when asserted will set this flag."]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigTwoRowAddrCyclesSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Attached device has only 2 ROW address cycles\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_two_row_addr_cycles::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_two_row_addr_cycles::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigTwoRowAddrCyclesSpec;
impl crate::RegisterSpec for ConfigTwoRowAddrCyclesSpec {
    type Ux = u32;
    const OFFSET: u64 = 400u64;
}
#[doc = "`read()` method returns [`config_two_row_addr_cycles::R`](R) reader structure"]
impl crate::Readable for ConfigTwoRowAddrCyclesSpec {}
#[doc = "`write(|w| ..)` method takes [`config_two_row_addr_cycles::W`](W) writer structure"]
impl crate::Writable for ConfigTwoRowAddrCyclesSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_two_row_addr_cycles to value 0"]
impl crate::Resettable for ConfigTwoRowAddrCyclesSpec {
    const RESET_VALUE: u32 = 0;
}
