// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `back_end_power_r` reader"]
pub type R = crate::R<BackEndPowerRSpec>;
#[doc = "Register `back_end_power_r` writer"]
pub type W = crate::W<BackEndPowerRSpec>;
#[doc = "Back end power operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum BackEndPower {
    #[doc = "1: `1`"]
    Backend1 = 1,
    #[doc = "0: `0`"]
    Backend0 = 0,
}
impl From<BackEndPower> for u16 {
    #[inline(always)]
    fn from(variant: BackEndPower) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for BackEndPower {
    type Ux = u16;
}
#[doc = "Field `back_end_power` reader - Back end power operation."]
pub type BackEndPowerR = crate::FieldReader<BackEndPower>;
impl BackEndPowerR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<BackEndPower> {
        match self.bits {
            1 => Some(BackEndPower::Backend1),
            0 => Some(BackEndPower::Backend0),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_backend1(&self) -> bool {
        *self == BackEndPower::Backend1
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_backend0(&self) -> bool {
        *self == BackEndPower::Backend0
    }
}
#[doc = "Field `back_end_power` writer - Back end power operation."]
pub type BackEndPowerW<'a, REG> = crate::FieldWriter<'a, REG, 16, BackEndPower>;
impl<'a, REG> BackEndPowerW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u16>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn backend1(self) -> &'a mut crate::W<REG> {
        self.variant(BackEndPower::Backend1)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn backend0(self) -> &'a mut crate::W<REG> {
        self.variant(BackEndPower::Backend0)
    }
}
impl R {
    #[doc = "Bits 0:15 - Back end power operation."]
    #[inline(always)]
    pub fn back_end_power(&self) -> BackEndPowerR {
        BackEndPowerR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Back end power operation."]
    #[inline(always)]
    #[must_use]
    pub fn back_end_power(&mut self) -> BackEndPowerW<BackEndPowerRSpec> {
        BackEndPowerW::new(self, 0)
    }
}
#[doc = "See Field Description\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`back_end_power_r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`back_end_power_r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BackEndPowerRSpec;
impl crate::RegisterSpec for BackEndPowerRSpec {
    type Ux = u32;
    const OFFSET: u64 = 260u64;
}
#[doc = "`read()` method returns [`back_end_power_r::R`](R) reader structure"]
impl crate::Readable for BackEndPowerRSpec {}
#[doc = "`write(|w| ..)` method takes [`back_end_power_r::W`](W) writer structure"]
impl crate::Writable for BackEndPowerRSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets back_end_power_r to value 0"]
impl crate::Resettable for BackEndPowerRSpec {
    const RESET_VALUE: u32 = 0;
}
