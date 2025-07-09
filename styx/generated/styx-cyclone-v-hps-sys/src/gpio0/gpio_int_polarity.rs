// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_int_polarity` reader"]
pub type R = crate::R<GpioIntPolaritySpec>;
#[doc = "Register `gpio_int_polarity` writer"]
pub type W = crate::W<GpioIntPolaritySpec>;
#[doc = "Controls the polarity of edge or level sensitivity that can occur on input of Port A Data Register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioIntPolarity {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<GpioIntPolarity> for u32 {
    #[inline(always)]
    fn from(variant: GpioIntPolarity) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioIntPolarity {
    type Ux = u32;
}
#[doc = "Field `gpio_int_polarity` reader - Controls the polarity of edge or level sensitivity that can occur on input of Port A Data Register."]
pub type GpioIntPolarityR = crate::FieldReader<GpioIntPolarity>;
impl GpioIntPolarityR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioIntPolarity> {
        match self.bits {
            0 => Some(GpioIntPolarity::Actlow),
            1 => Some(GpioIntPolarity::Acthigh),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == GpioIntPolarity::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == GpioIntPolarity::Acthigh
    }
}
#[doc = "Field `gpio_int_polarity` writer - Controls the polarity of edge or level sensitivity that can occur on input of Port A Data Register."]
pub type GpioIntPolarityW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioIntPolarity>;
impl<'a, REG> GpioIntPolarityW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(GpioIntPolarity::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(GpioIntPolarity::Acthigh)
    }
}
impl R {
    #[doc = "Bits 0:28 - Controls the polarity of edge or level sensitivity that can occur on input of Port A Data Register."]
    #[inline(always)]
    pub fn gpio_int_polarity(&self) -> GpioIntPolarityR {
        GpioIntPolarityR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Controls the polarity of edge or level sensitivity that can occur on input of Port A Data Register."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_int_polarity(&mut self) -> GpioIntPolarityW<GpioIntPolaritySpec> {
        GpioIntPolarityW::new(self, 0)
    }
}
#[doc = "Controls the Polarity of Interrupts that can occur on inputs of Port A Data Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_int_polarity::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_int_polarity::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioIntPolaritySpec;
impl crate::RegisterSpec for GpioIntPolaritySpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`gpio_int_polarity::R`](R) reader structure"]
impl crate::Readable for GpioIntPolaritySpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_int_polarity::W`](W) writer structure"]
impl crate::Writable for GpioIntPolaritySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_int_polarity to value 0"]
impl crate::Resettable for GpioIntPolaritySpec {
    const RESET_VALUE: u32 = 0;
}
