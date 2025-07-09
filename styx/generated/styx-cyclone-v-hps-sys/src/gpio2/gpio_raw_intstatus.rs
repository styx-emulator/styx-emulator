// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_raw_intstatus` reader"]
pub type R = crate::R<GpioRawIntstatusSpec>;
#[doc = "Register `gpio_raw_intstatus` writer"]
pub type W = crate::W<GpioRawIntstatusSpec>;
#[doc = "Raw interrupt of status of Port A Data Register (premasking bits)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioRawIntstatus {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<GpioRawIntstatus> for u32 {
    #[inline(always)]
    fn from(variant: GpioRawIntstatus) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioRawIntstatus {
    type Ux = u32;
}
#[doc = "Field `gpio_raw_intstatus` reader - Raw interrupt of status of Port A Data Register (premasking bits)"]
pub type GpioRawIntstatusR = crate::FieldReader<GpioRawIntstatus>;
impl GpioRawIntstatusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioRawIntstatus> {
        match self.bits {
            0 => Some(GpioRawIntstatus::Inactive),
            1 => Some(GpioRawIntstatus::Active),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == GpioRawIntstatus::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == GpioRawIntstatus::Active
    }
}
#[doc = "Field `gpio_raw_intstatus` writer - Raw interrupt of status of Port A Data Register (premasking bits)"]
pub type GpioRawIntstatusW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioRawIntstatus>;
impl<'a, REG> GpioRawIntstatusW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(GpioRawIntstatus::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(GpioRawIntstatus::Active)
    }
}
impl R {
    #[doc = "Bits 0:28 - Raw interrupt of status of Port A Data Register (premasking bits)"]
    #[inline(always)]
    pub fn gpio_raw_intstatus(&self) -> GpioRawIntstatusR {
        GpioRawIntstatusR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Raw interrupt of status of Port A Data Register (premasking bits)"]
    #[inline(always)]
    #[must_use]
    pub fn gpio_raw_intstatus(&mut self) -> GpioRawIntstatusW<GpioRawIntstatusSpec> {
        GpioRawIntstatusW::new(self, 0)
    }
}
#[doc = "This is the Raw Interrupt Status Register for Port A Data Register. It is used with the Interrupt Mask Register to allow interrupts from the Port A Data Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_raw_intstatus::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_raw_intstatus::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioRawIntstatusSpec;
impl crate::RegisterSpec for GpioRawIntstatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`gpio_raw_intstatus::R`](R) reader structure"]
impl crate::Readable for GpioRawIntstatusSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_raw_intstatus::W`](W) writer structure"]
impl crate::Writable for GpioRawIntstatusSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_raw_intstatus to value 0"]
impl crate::Resettable for GpioRawIntstatusSpec {
    const RESET_VALUE: u32 = 0;
}
