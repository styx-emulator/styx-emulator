// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramtiming3` reader"]
pub type R = crate::R<CtrlgrpDramtiming3Spec>;
#[doc = "Register `ctrlgrp_dramtiming3` writer"]
pub type W = crate::W<CtrlgrpDramtiming3Spec>;
#[doc = "Field `trtp` reader - The read to precharge timing parameter."]
pub type TrtpR = crate::FieldReader;
#[doc = "Field `trtp` writer - The read to precharge timing parameter."]
pub type TrtpW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `tras` reader - The activate to precharge timing parameter."]
pub type TrasR = crate::FieldReader;
#[doc = "Field `tras` writer - The activate to precharge timing parameter."]
pub type TrasW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `trc` reader - The activate to activate timing parameter."]
pub type TrcR = crate::FieldReader;
#[doc = "Field `trc` writer - The activate to activate timing parameter."]
pub type TrcW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `tmrd` reader - Mode register timing parameter."]
pub type TmrdR = crate::FieldReader;
#[doc = "Field `tmrd` writer - Mode register timing parameter."]
pub type TmrdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `tccd` reader - The CAS to CAS delay time."]
pub type TccdR = crate::FieldReader;
#[doc = "Field `tccd` writer - The CAS to CAS delay time."]
pub type TccdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - The read to precharge timing parameter."]
    #[inline(always)]
    pub fn trtp(&self) -> TrtpR {
        TrtpR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:8 - The activate to precharge timing parameter."]
    #[inline(always)]
    pub fn tras(&self) -> TrasR {
        TrasR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 9:14 - The activate to activate timing parameter."]
    #[inline(always)]
    pub fn trc(&self) -> TrcR {
        TrcR::new(((self.bits >> 9) & 0x3f) as u8)
    }
    #[doc = "Bits 15:18 - Mode register timing parameter."]
    #[inline(always)]
    pub fn tmrd(&self) -> TmrdR {
        TmrdR::new(((self.bits >> 15) & 0x0f) as u8)
    }
    #[doc = "Bits 19:22 - The CAS to CAS delay time."]
    #[inline(always)]
    pub fn tccd(&self) -> TccdR {
        TccdR::new(((self.bits >> 19) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - The read to precharge timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trtp(&mut self) -> TrtpW<CtrlgrpDramtiming3Spec> {
        TrtpW::new(self, 0)
    }
    #[doc = "Bits 4:8 - The activate to precharge timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn tras(&mut self) -> TrasW<CtrlgrpDramtiming3Spec> {
        TrasW::new(self, 4)
    }
    #[doc = "Bits 9:14 - The activate to activate timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trc(&mut self) -> TrcW<CtrlgrpDramtiming3Spec> {
        TrcW::new(self, 9)
    }
    #[doc = "Bits 15:18 - Mode register timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn tmrd(&mut self) -> TmrdW<CtrlgrpDramtiming3Spec> {
        TmrdW::new(self, 15)
    }
    #[doc = "Bits 19:22 - The CAS to CAS delay time."]
    #[inline(always)]
    #[must_use]
    pub fn tccd(&mut self) -> TccdW<CtrlgrpDramtiming3Spec> {
        TccdW::new(self, 19)
    }
}
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramtiming3Spec;
impl crate::RegisterSpec for CtrlgrpDramtiming3Spec {
    type Ux = u32;
    const OFFSET: u64 = 20492u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramtiming3::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramtiming3Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramtiming3::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramtiming3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramtiming3 to value 0"]
impl crate::Resettable for CtrlgrpDramtiming3Spec {
    const RESET_VALUE: u32 = 0;
}
