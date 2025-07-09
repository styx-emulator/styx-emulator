// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mastergrp_usb1_ahb_cntl` reader"]
pub type R = crate::R<MastergrpUsb1AhbCntlSpec>;
#[doc = "Register `mastergrp_usb1_ahb_cntl` writer"]
pub type W = crate::W<MastergrpUsb1AhbCntlSpec>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecerrEn {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<DecerrEn> for bool {
    #[inline(always)]
    fn from(variant: DecerrEn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `decerr_en` reader - "]
pub type DecerrEnR = crate::BitReader<DecerrEn>;
impl DecerrEnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DecerrEn {
        match self.bits {
            false => DecerrEn::Disable,
            true => DecerrEn::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == DecerrEn::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == DecerrEn::Enable
    }
}
#[doc = "Field `decerr_en` writer - "]
pub type DecerrEnW<'a, REG> = crate::BitWriter<'a, REG, DecerrEn>;
impl<'a, REG> DecerrEnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(DecerrEn::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(DecerrEn::Enable)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForceIncr {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<ForceIncr> for bool {
    #[inline(always)]
    fn from(variant: ForceIncr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `force_incr` reader - "]
pub type ForceIncrR = crate::BitReader<ForceIncr>;
impl ForceIncrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ForceIncr {
        match self.bits {
            false => ForceIncr::Disable,
            true => ForceIncr::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == ForceIncr::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == ForceIncr::Enable
    }
}
#[doc = "Field `force_incr` writer - "]
pub type ForceIncrW<'a, REG> = crate::BitWriter<'a, REG, ForceIncr>;
impl<'a, REG> ForceIncrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(ForceIncr::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(ForceIncr::Enable)
    }
}
impl R {
    #[doc = "Bit 0"]
    #[inline(always)]
    pub fn decerr_en(&self) -> DecerrEnR {
        DecerrEnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    pub fn force_incr(&self) -> ForceIncrR {
        ForceIncrR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0"]
    #[inline(always)]
    #[must_use]
    pub fn decerr_en(&mut self) -> DecerrEnW<MastergrpUsb1AhbCntlSpec> {
        DecerrEnW::new(self, 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn force_incr(&mut self) -> ForceIncrW<MastergrpUsb1AhbCntlSpec> {
        ForceIncrW::new(self, 1)
    }
}
#[doc = "Sets the block issuing capability to one outstanding transaction.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_usb1_ahb_cntl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_usb1_ahb_cntl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MastergrpUsb1AhbCntlSpec;
impl crate::RegisterSpec for MastergrpUsb1AhbCntlSpec {
    type Ux = u32;
    const OFFSET: u64 = 41028u64;
}
#[doc = "`read()` method returns [`mastergrp_usb1_ahb_cntl::R`](R) reader structure"]
impl crate::Readable for MastergrpUsb1AhbCntlSpec {}
#[doc = "`write(|w| ..)` method takes [`mastergrp_usb1_ahb_cntl::W`](W) writer structure"]
impl crate::Writable for MastergrpUsb1AhbCntlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mastergrp_usb1_ahb_cntl to value 0"]
impl crate::Resettable for MastergrpUsb1AhbCntlSpec {
    const RESET_VALUE: u32 = 0;
}
