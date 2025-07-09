// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramtiming2` reader"]
pub type R = crate::R<CtrlgrpDramtiming2Spec>;
#[doc = "Register `ctrlgrp_dramtiming2` writer"]
pub type W = crate::W<CtrlgrpDramtiming2Spec>;
#[doc = "Field `trefi` reader - The refresh interval timing parameter."]
pub type TrefiR = crate::FieldReader<u16>;
#[doc = "Field `trefi` writer - The refresh interval timing parameter."]
pub type TrefiW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
#[doc = "Field `trcd` reader - The activate to read/write timing parameter."]
pub type TrcdR = crate::FieldReader;
#[doc = "Field `trcd` writer - The activate to read/write timing parameter."]
pub type TrcdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `trp` reader - The precharge to activate timing parameter."]
pub type TrpR = crate::FieldReader;
#[doc = "Field `trp` writer - The precharge to activate timing parameter."]
pub type TrpW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `twr` reader - The write recovery timing."]
pub type TwrR = crate::FieldReader;
#[doc = "Field `twr` writer - The write recovery timing."]
pub type TwrW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `twtr` reader - The write to read timing parameter."]
pub type TwtrR = crate::FieldReader;
#[doc = "Field `twtr` writer - The write to read timing parameter."]
pub type TwtrW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:12 - The refresh interval timing parameter."]
    #[inline(always)]
    pub fn trefi(&self) -> TrefiR {
        TrefiR::new((self.bits & 0x1fff) as u16)
    }
    #[doc = "Bits 13:16 - The activate to read/write timing parameter."]
    #[inline(always)]
    pub fn trcd(&self) -> TrcdR {
        TrcdR::new(((self.bits >> 13) & 0x0f) as u8)
    }
    #[doc = "Bits 17:20 - The precharge to activate timing parameter."]
    #[inline(always)]
    pub fn trp(&self) -> TrpR {
        TrpR::new(((self.bits >> 17) & 0x0f) as u8)
    }
    #[doc = "Bits 21:24 - The write recovery timing."]
    #[inline(always)]
    pub fn twr(&self) -> TwrR {
        TwrR::new(((self.bits >> 21) & 0x0f) as u8)
    }
    #[doc = "Bits 25:28 - The write to read timing parameter."]
    #[inline(always)]
    pub fn twtr(&self) -> TwtrR {
        TwtrR::new(((self.bits >> 25) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:12 - The refresh interval timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trefi(&mut self) -> TrefiW<CtrlgrpDramtiming2Spec> {
        TrefiW::new(self, 0)
    }
    #[doc = "Bits 13:16 - The activate to read/write timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trcd(&mut self) -> TrcdW<CtrlgrpDramtiming2Spec> {
        TrcdW::new(self, 13)
    }
    #[doc = "Bits 17:20 - The precharge to activate timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn trp(&mut self) -> TrpW<CtrlgrpDramtiming2Spec> {
        TrpW::new(self, 17)
    }
    #[doc = "Bits 21:24 - The write recovery timing."]
    #[inline(always)]
    #[must_use]
    pub fn twr(&mut self) -> TwrW<CtrlgrpDramtiming2Spec> {
        TwrW::new(self, 21)
    }
    #[doc = "Bits 25:28 - The write to read timing parameter."]
    #[inline(always)]
    #[must_use]
    pub fn twtr(&mut self) -> TwtrW<CtrlgrpDramtiming2Spec> {
        TwtrW::new(self, 25)
    }
}
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramtiming2Spec;
impl crate::RegisterSpec for CtrlgrpDramtiming2Spec {
    type Ux = u32;
    const OFFSET: u64 = 20488u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramtiming2::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramtiming2Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramtiming2::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramtiming2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramtiming2 to value 0"]
impl crate::Resettable for CtrlgrpDramtiming2Spec {
    const RESET_VALUE: u32 = 0;
}
