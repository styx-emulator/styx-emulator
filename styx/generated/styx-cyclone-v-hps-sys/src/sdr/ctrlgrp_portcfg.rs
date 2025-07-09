// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_portcfg` reader"]
pub type R = crate::R<CtrlgrpPortcfgSpec>;
#[doc = "Register `ctrlgrp_portcfg` writer"]
pub type W = crate::W<CtrlgrpPortcfgSpec>;
#[doc = "Field `autopchen` reader - One bit per control port. Set bit N to a 1 to have the controller request an automatic precharge following bus command completion (close the row automatically). Set to a zero to request that the controller attempt to keep a row open. For random dominated operations this register should be set to a 1 for all active ports."]
pub type AutopchenR = crate::FieldReader<u16>;
#[doc = "Field `autopchen` writer - One bit per control port. Set bit N to a 1 to have the controller request an automatic precharge following bus command completion (close the row automatically). Set to a zero to request that the controller attempt to keep a row open. For random dominated operations this register should be set to a 1 for all active ports."]
pub type AutopchenW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
impl R {
    #[doc = "Bits 10:19 - One bit per control port. Set bit N to a 1 to have the controller request an automatic precharge following bus command completion (close the row automatically). Set to a zero to request that the controller attempt to keep a row open. For random dominated operations this register should be set to a 1 for all active ports."]
    #[inline(always)]
    pub fn autopchen(&self) -> AutopchenR {
        AutopchenR::new(((self.bits >> 10) & 0x03ff) as u16)
    }
}
impl W {
    #[doc = "Bits 10:19 - One bit per control port. Set bit N to a 1 to have the controller request an automatic precharge following bus command completion (close the row automatically). Set to a zero to request that the controller attempt to keep a row open. For random dominated operations this register should be set to a 1 for all active ports."]
    #[inline(always)]
    #[must_use]
    pub fn autopchen(&mut self) -> AutopchenW<CtrlgrpPortcfgSpec> {
        AutopchenW::new(self, 10)
    }
}
#[doc = "This register should be set to a zero in any bit which corresponds to a port which does mostly sequential memory accesses. For ports with highly random accesses, the bit should be set to a one.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_portcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_portcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpPortcfgSpec;
impl crate::RegisterSpec for CtrlgrpPortcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 20604u64;
}
#[doc = "`read()` method returns [`ctrlgrp_portcfg::R`](R) reader structure"]
impl crate::Readable for CtrlgrpPortcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_portcfg::W`](W) writer structure"]
impl crate::Writable for CtrlgrpPortcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_portcfg to value 0"]
impl crate::Resettable for CtrlgrpPortcfgSpec {
    const RESET_VALUE: u32 = 0;
}
