// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_inttype_level` reader"]
pub type R = crate::R<GpioInttypeLevelSpec>;
#[doc = "Register `gpio_inttype_level` writer"]
pub type W = crate::W<GpioInttypeLevelSpec>;
#[doc = "This field controls the type of interrupt that can occur on the Port A Data Register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioInttypeLevel {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<GpioInttypeLevel> for u32 {
    #[inline(always)]
    fn from(variant: GpioInttypeLevel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioInttypeLevel {
    type Ux = u32;
}
#[doc = "Field `gpio_inttype_level` reader - This field controls the type of interrupt that can occur on the Port A Data Register."]
pub type GpioInttypeLevelR = crate::FieldReader<GpioInttypeLevel>;
impl GpioInttypeLevelR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioInttypeLevel> {
        match self.bits {
            0 => Some(GpioInttypeLevel::Level),
            1 => Some(GpioInttypeLevel::Edge),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == GpioInttypeLevel::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == GpioInttypeLevel::Edge
    }
}
#[doc = "Field `gpio_inttype_level` writer - This field controls the type of interrupt that can occur on the Port A Data Register."]
pub type GpioInttypeLevelW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioInttypeLevel>;
impl<'a, REG> GpioInttypeLevelW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(GpioInttypeLevel::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(GpioInttypeLevel::Edge)
    }
}
impl R {
    #[doc = "Bits 0:28 - This field controls the type of interrupt that can occur on the Port A Data Register."]
    #[inline(always)]
    pub fn gpio_inttype_level(&self) -> GpioInttypeLevelR {
        GpioInttypeLevelR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - This field controls the type of interrupt that can occur on the Port A Data Register."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_inttype_level(&mut self) -> GpioInttypeLevelW<GpioInttypeLevelSpec> {
        GpioInttypeLevelW::new(self, 0)
    }
}
#[doc = "The interrupt level register defines the type of interrupt (edge or level).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_inttype_level::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_inttype_level::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioInttypeLevelSpec;
impl crate::RegisterSpec for GpioInttypeLevelSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`gpio_inttype_level::R`](R) reader structure"]
impl crate::Readable for GpioInttypeLevelSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_inttype_level::W`](W) writer structure"]
impl crate::Writable for GpioInttypeLevelSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_inttype_level to value 0"]
impl crate::Resettable for GpioInttypeLevelSpec {
    const RESET_VALUE: u32 = 0;
}
