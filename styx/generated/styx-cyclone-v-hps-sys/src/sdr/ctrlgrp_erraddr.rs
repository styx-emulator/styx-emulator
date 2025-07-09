// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_erraddr` reader"]
pub type R = crate::R<CtrlgrpErraddrSpec>;
#[doc = "Register `ctrlgrp_erraddr` writer"]
pub type W = crate::W<CtrlgrpErraddrSpec>;
#[doc = "Field `addr` reader - The address of the most recent ECC error."]
pub type AddrR = crate::FieldReader<u32>;
#[doc = "Field `addr` writer - The address of the most recent ECC error."]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The address of the most recent ECC error."]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The address of the most recent ECC error."]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<CtrlgrpErraddrSpec> {
        AddrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_erraddr::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_erraddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpErraddrSpec;
impl crate::RegisterSpec for CtrlgrpErraddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20552u64;
}
#[doc = "`read()` method returns [`ctrlgrp_erraddr::R`](R) reader structure"]
impl crate::Readable for CtrlgrpErraddrSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_erraddr::W`](W) writer structure"]
impl crate::Writable for CtrlgrpErraddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
