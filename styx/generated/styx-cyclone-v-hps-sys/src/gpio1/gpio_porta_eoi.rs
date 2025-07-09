// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_porta_eoi` reader"]
pub type R = crate::R<GpioPortaEoiSpec>;
#[doc = "Register `gpio_porta_eoi` writer"]
pub type W = crate::W<GpioPortaEoiSpec>;
#[doc = "Field `gpio_porta_eoi` reader - Controls the clearing of edge type interrupts from the Port A Data Register."]
pub type GpioPortaEoiR = crate::FieldReader<u32>;
#[doc = "Controls the clearing of edge type interrupts from the Port A Data Register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioPortaEoi {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<GpioPortaEoi> for u32 {
    #[inline(always)]
    fn from(variant: GpioPortaEoi) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioPortaEoi {
    type Ux = u32;
}
#[doc = "Field `gpio_porta_eoi` writer - Controls the clearing of edge type interrupts from the Port A Data Register."]
pub type GpioPortaEoiW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioPortaEoi>;
impl<'a, REG> GpioPortaEoiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(GpioPortaEoi::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(GpioPortaEoi::Clr)
    }
}
impl R {
    #[doc = "Bits 0:28 - Controls the clearing of edge type interrupts from the Port A Data Register."]
    #[inline(always)]
    pub fn gpio_porta_eoi(&self) -> GpioPortaEoiR {
        GpioPortaEoiR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Controls the clearing of edge type interrupts from the Port A Data Register."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_porta_eoi(&mut self) -> GpioPortaEoiW<GpioPortaEoiSpec> {
        GpioPortaEoiW::new(self, 0)
    }
}
#[doc = "Port A Data Register interrupt handling.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_porta_eoi::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioPortaEoiSpec;
impl crate::RegisterSpec for GpioPortaEoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`write(|w| ..)` method takes [`gpio_porta_eoi::W`](W) writer structure"]
impl crate::Writable for GpioPortaEoiSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_porta_eoi to value 0"]
impl crate::Resettable for GpioPortaEoiSpec {
    const RESET_VALUE: u32 = 0;
}
