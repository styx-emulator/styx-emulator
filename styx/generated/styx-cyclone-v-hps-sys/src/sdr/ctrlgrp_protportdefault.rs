// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_protportdefault` reader"]
pub type R = crate::R<CtrlgrpProtportdefaultSpec>;
#[doc = "Register `ctrlgrp_protportdefault` writer"]
pub type W = crate::W<CtrlgrpProtportdefaultSpec>;
#[doc = "Field `portdefault` reader - Determines the default action for a transactions from a port. Set a bit to a zero to indicate that all accesses from the port should pass by default, set a bit to a one if the default protection is to fail the access."]
pub type PortdefaultR = crate::FieldReader<u16>;
#[doc = "Field `portdefault` writer - Determines the default action for a transactions from a port. Set a bit to a zero to indicate that all accesses from the port should pass by default, set a bit to a one if the default protection is to fail the access."]
pub type PortdefaultW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
impl R {
    #[doc = "Bits 0:9 - Determines the default action for a transactions from a port. Set a bit to a zero to indicate that all accesses from the port should pass by default, set a bit to a one if the default protection is to fail the access."]
    #[inline(always)]
    pub fn portdefault(&self) -> PortdefaultR {
        PortdefaultR::new((self.bits & 0x03ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:9 - Determines the default action for a transactions from a port. Set a bit to a zero to indicate that all accesses from the port should pass by default, set a bit to a one if the default protection is to fail the access."]
    #[inline(always)]
    #[must_use]
    pub fn portdefault(&mut self) -> PortdefaultW<CtrlgrpProtportdefaultSpec> {
        PortdefaultW::new(self, 0)
    }
}
#[doc = "This register controls the default protection assignment for a port. Ports which have explicit rules which define regions which are illegal to access should set the bits to pass by default. Ports which have explicit rules which define legal areas should set the bit to force all transactions to fail. Leaving this register to all zeros should be used for systems which do not desire any protection from the memory controller.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protportdefault::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protportdefault::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpProtportdefaultSpec;
impl crate::RegisterSpec for CtrlgrpProtportdefaultSpec {
    type Ux = u32;
    const OFFSET: u64 = 20620u64;
}
#[doc = "`read()` method returns [`ctrlgrp_protportdefault::R`](R) reader structure"]
impl crate::Readable for CtrlgrpProtportdefaultSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_protportdefault::W`](W) writer structure"]
impl crate::Writable for CtrlgrpProtportdefaultSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_protportdefault to value 0"]
impl crate::Resettable for CtrlgrpProtportdefaultSpec {
    const RESET_VALUE: u32 = 0;
}
