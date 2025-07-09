// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `romhwgrp_ctrl` reader"]
pub type R = crate::R<RomhwgrpCtrlSpec>;
#[doc = "Register `romhwgrp_ctrl` writer"]
pub type W = crate::W<RomhwgrpCtrlSpec>;
#[doc = "Controls the number of wait states applied to the Boot ROM's read operation. This field is cleared on a cold reset and optionally updated by hardware upon deassertion of warm reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waitstate {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Waitstate> for bool {
    #[inline(always)]
    fn from(variant: Waitstate) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `waitstate` reader - Controls the number of wait states applied to the Boot ROM's read operation. This field is cleared on a cold reset and optionally updated by hardware upon deassertion of warm reset."]
pub type WaitstateR = crate::BitReader<Waitstate>;
impl WaitstateR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Waitstate {
        match self.bits {
            false => Waitstate::Disable,
            true => Waitstate::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Waitstate::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Waitstate::Enable
    }
}
#[doc = "Field `waitstate` writer - Controls the number of wait states applied to the Boot ROM's read operation. This field is cleared on a cold reset and optionally updated by hardware upon deassertion of warm reset."]
pub type WaitstateW<'a, REG> = crate::BitWriter<'a, REG, Waitstate>;
impl<'a, REG> WaitstateW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Waitstate::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Waitstate::Enable)
    }
}
#[doc = "Controls whether the wait state bit is updated upon deassertion of warm reset. This field is set on a cold reset.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ensfmdwru {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ensfmdwru> for bool {
    #[inline(always)]
    fn from(variant: Ensfmdwru) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ensfmdwru` reader - Controls whether the wait state bit is updated upon deassertion of warm reset. This field is set on a cold reset."]
pub type EnsfmdwruR = crate::BitReader<Ensfmdwru>;
impl EnsfmdwruR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ensfmdwru {
        match self.bits {
            false => Ensfmdwru::Disable,
            true => Ensfmdwru::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ensfmdwru::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ensfmdwru::Enable
    }
}
#[doc = "Field `ensfmdwru` writer - Controls whether the wait state bit is updated upon deassertion of warm reset. This field is set on a cold reset."]
pub type EnsfmdwruW<'a, REG> = crate::BitWriter<'a, REG, Ensfmdwru>;
impl<'a, REG> EnsfmdwruW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ensfmdwru::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ensfmdwru::Enable)
    }
}
impl R {
    #[doc = "Bit 0 - Controls the number of wait states applied to the Boot ROM's read operation. This field is cleared on a cold reset and optionally updated by hardware upon deassertion of warm reset."]
    #[inline(always)]
    pub fn waitstate(&self) -> WaitstateR {
        WaitstateR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether the wait state bit is updated upon deassertion of warm reset. This field is set on a cold reset."]
    #[inline(always)]
    pub fn ensfmdwru(&self) -> EnsfmdwruR {
        EnsfmdwruR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls the number of wait states applied to the Boot ROM's read operation. This field is cleared on a cold reset and optionally updated by hardware upon deassertion of warm reset."]
    #[inline(always)]
    #[must_use]
    pub fn waitstate(&mut self) -> WaitstateW<RomhwgrpCtrlSpec> {
        WaitstateW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether the wait state bit is updated upon deassertion of warm reset. This field is set on a cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn ensfmdwru(&mut self) -> EnsfmdwruW<RomhwgrpCtrlSpec> {
        EnsfmdwruW::new(self, 1)
    }
}
#[doc = "Controls behavior of Boot ROM hardware. All fields are only reset by a cold reset (ignore warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romhwgrp_ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romhwgrp_ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomhwgrpCtrlSpec;
impl crate::RegisterSpec for RomhwgrpCtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 256u64;
}
#[doc = "`read()` method returns [`romhwgrp_ctrl::R`](R) reader structure"]
impl crate::Readable for RomhwgrpCtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`romhwgrp_ctrl::W`](W) writer structure"]
impl crate::Writable for RomhwgrpCtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romhwgrp_ctrl to value 0x02"]
impl crate::Resettable for RomhwgrpCtrlSpec {
    const RESET_VALUE: u32 = 0x02;
}
