// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramintr` reader"]
pub type R = crate::R<CtrlgrpDramintrSpec>;
#[doc = "Register `ctrlgrp_dramintr` writer"]
pub type W = crate::W<CtrlgrpDramintrSpec>;
#[doc = "Field `intren` reader - Enable the interrupt output."]
pub type IntrenR = crate::BitReader;
#[doc = "Field `intren` writer - Enable the interrupt output."]
pub type IntrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sbemask` reader - Mask the single bit error interrupt."]
pub type SbemaskR = crate::BitReader;
#[doc = "Field `sbemask` writer - Mask the single bit error interrupt."]
pub type SbemaskW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbemask` reader - Mask the double bit error interrupt."]
pub type DbemaskR = crate::BitReader;
#[doc = "Field `dbemask` writer - Mask the double bit error interrupt."]
pub type DbemaskW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `corrdropmask` reader - Set this bit to a one to mask interrupts for an ECC correction write back needing to be dropped. This indicates a burst of memory errors in a short period of time."]
pub type CorrdropmaskR = crate::BitReader;
#[doc = "Field `corrdropmask` writer - Set this bit to a one to mask interrupts for an ECC correction write back needing to be dropped. This indicates a burst of memory errors in a short period of time."]
pub type CorrdropmaskW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `intrclr` reader - Writing to this self-clearing bit clears the interrupt signal. Writing to this bit also clears the error count and error address registers."]
pub type IntrclrR = crate::BitReader;
#[doc = "Field `intrclr` writer - Writing to this self-clearing bit clears the interrupt signal. Writing to this bit also clears the error count and error address registers."]
pub type IntrclrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enable the interrupt output."]
    #[inline(always)]
    pub fn intren(&self) -> IntrenR {
        IntrenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mask the single bit error interrupt."]
    #[inline(always)]
    pub fn sbemask(&self) -> SbemaskR {
        SbemaskR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Mask the double bit error interrupt."]
    #[inline(always)]
    pub fn dbemask(&self) -> DbemaskR {
        DbemaskR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Set this bit to a one to mask interrupts for an ECC correction write back needing to be dropped. This indicates a burst of memory errors in a short period of time."]
    #[inline(always)]
    pub fn corrdropmask(&self) -> CorrdropmaskR {
        CorrdropmaskR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Writing to this self-clearing bit clears the interrupt signal. Writing to this bit also clears the error count and error address registers."]
    #[inline(always)]
    pub fn intrclr(&self) -> IntrclrR {
        IntrclrR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enable the interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn intren(&mut self) -> IntrenW<CtrlgrpDramintrSpec> {
        IntrenW::new(self, 0)
    }
    #[doc = "Bit 1 - Mask the single bit error interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn sbemask(&mut self) -> SbemaskW<CtrlgrpDramintrSpec> {
        SbemaskW::new(self, 1)
    }
    #[doc = "Bit 2 - Mask the double bit error interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn dbemask(&mut self) -> DbemaskW<CtrlgrpDramintrSpec> {
        DbemaskW::new(self, 2)
    }
    #[doc = "Bit 3 - Set this bit to a one to mask interrupts for an ECC correction write back needing to be dropped. This indicates a burst of memory errors in a short period of time."]
    #[inline(always)]
    #[must_use]
    pub fn corrdropmask(&mut self) -> CorrdropmaskW<CtrlgrpDramintrSpec> {
        CorrdropmaskW::new(self, 3)
    }
    #[doc = "Bit 4 - Writing to this self-clearing bit clears the interrupt signal. Writing to this bit also clears the error count and error address registers."]
    #[inline(always)]
    #[must_use]
    pub fn intrclr(&mut self) -> IntrclrW<CtrlgrpDramintrSpec> {
        IntrclrW::new(self, 4)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramintr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramintr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramintrSpec;
impl crate::RegisterSpec for CtrlgrpDramintrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20540u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramintr::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramintrSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramintr::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramintrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramintr to value 0"]
impl crate::Resettable for CtrlgrpDramintrSpec {
    const RESET_VALUE: u32 = 0;
}
