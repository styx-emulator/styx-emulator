// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramtiming1` reader"]
pub type R = crate::R<CtrlgrpDramtiming1Spec>;
#[doc = "Register `ctrlgrp_dramtiming1` writer"]
pub type W = crate::W<CtrlgrpDramtiming1Spec>;
#[doc = "Field `tcwl` reader - Memory write latency."]
pub type TcwlR = crate::FieldReader;
#[doc = "Field `tcwl` writer - Memory write latency."]
pub type TcwlW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `tal` reader - Memory additive latency."]
pub type TalR = crate::FieldReader;
#[doc = "Field `tal` writer - Memory additive latency."]
pub type TalW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `tcl` reader - Memory read latency."]
pub type TclR = crate::FieldReader;
#[doc = "Field `tcl` writer - Memory read latency."]
pub type TclW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `trrd` reader - The activate to activate, different banks timing parameter."]
pub type TrrdR = crate::FieldReader;
#[doc = "Field `trrd` writer - The activate to activate, different banks timing parameter."]
pub type TrrdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `tfaw` reader - The four-activate window timing parameter."]
pub type TfawR = crate::FieldReader;
#[doc = "Field `tfaw` writer - The four-activate window timing parameter."]
pub type TfawW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `trfc` reader - The refresh cycle timing parameter."]
pub type TrfcR = crate::FieldReader;
#[doc = "Field `trfc` writer - The refresh cycle timing parameter."]
pub type TrfcW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:3 - Memory write latency."]
    #[inline(always)]
    pub fn tcwl(&self) -> TcwlR {
        TcwlR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:8 - Memory additive latency."]
    #[inline(always)]
    pub fn tal(&self) -> TalR {
        TalR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 9:13 - Memory read latency."]
    #[inline(always)]
    pub fn tcl(&self) -> TclR {
        TclR::new(((self.bits >> 9) & 0x1f) as u8)
    }
    #[doc = "Bits 14:17 - The activate to activate, different banks timing parameter."]
    #[inline(always)]
    pub fn trrd(&self) -> TrrdR {
        TrrdR::new(((self.bits >> 14) & 0x0f) as u8)
    }
    #[doc = "Bits 18:23 - The four-activate window timing parameter."]
    #[inline(always)]
    pub fn tfaw(&self) -> TfawR {
        TfawR::new(((self.bits >> 18) & 0x3f) as u8)
    }
    #[doc = "Bits 24:31 - The refresh cycle timing parameter."]
    #[inline(always)]
    pub fn trfc(&self) -> TrfcR {
        TrfcR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Memory write latency."]
    #[inline(always)]
    #[must_use]
    pub fn tcwl(&mut self) -> TcwlW<CtrlgrpDramtiming1Spec> {
        TcwlW::new(self, 0)
    }
    #[doc = "Bits 4:8 - Memory additive latency."]
    #[inline(always)]
    #[must_use]
    pub fn tal(&mut self) -> TalW<CtrlgrpDramtiming1Spec> {
        TalW::new(self, 4)
    }
    #[doc = "Bits 9:13 - Memory read latency."]
    #[inline(always)]
    #[must_use]
    pub fn tcl(&mut self) -> TclW<CtrlgrpDramtiming1Spec> {
        TclW::new(self, 9)
    }
    #[doc = "Bits 14:17 - The activate to activate, different banks timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trrd(&mut self) -> TrrdW<CtrlgrpDramtiming1Spec> {
        TrrdW::new(self, 14)
    }
    #[doc = "Bits 18:23 - The four-activate window timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn tfaw(&mut self) -> TfawW<CtrlgrpDramtiming1Spec> {
        TfawW::new(self, 18)
    }
    #[doc = "Bits 24:31 - The refresh cycle timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trfc(&mut self) -> TrfcW<CtrlgrpDramtiming1Spec> {
        TrfcW::new(self, 24)
    }
}
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming1::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramtiming1Spec;
impl crate::RegisterSpec for CtrlgrpDramtiming1Spec {
    type Ux = u32;
    const OFFSET: u64 = 20484u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramtiming1::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramtiming1Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramtiming1::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramtiming1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
