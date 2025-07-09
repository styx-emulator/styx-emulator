// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `gpio_swporta_ddr` reader"]
pub type R = crate::R<GpioSwportaDdrSpec>;
#[doc = "Register `gpio_swporta_ddr` writer"]
pub type W = crate::W<GpioSwportaDdrSpec>;
#[doc = "Values written to this register independently control the direction of the corresponding data bit in the Port A Data Register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioSwportaDdr {
    #[doc = "0: `0`"]
    In = 0,
    #[doc = "1: `1`"]
    Out = 1,
}
impl From<GpioSwportaDdr> for u32 {
    #[inline(always)]
    fn from(variant: GpioSwportaDdr) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioSwportaDdr {
    type Ux = u32;
}
#[doc = "Field `gpio_swporta_ddr` reader - Values written to this register independently control the direction of the corresponding data bit in the Port A Data Register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
pub type GpioSwportaDdrR = crate::FieldReader<GpioSwportaDdr>;
impl GpioSwportaDdrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioSwportaDdr> {
        match self.bits {
            0 => Some(GpioSwportaDdr::In),
            1 => Some(GpioSwportaDdr::Out),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_in(&self) -> bool {
        *self == GpioSwportaDdr::In
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_out(&self) -> bool {
        *self == GpioSwportaDdr::Out
    }
}
#[doc = "Field `gpio_swporta_ddr` writer - Values written to this register independently control the direction of the corresponding data bit in the Port A Data Register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
pub type GpioSwportaDdrW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioSwportaDdr>;
impl<'a, REG> GpioSwportaDdrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn in_(self) -> &'a mut crate::W<REG> {
        self.variant(GpioSwportaDdr::In)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn out(self) -> &'a mut crate::W<REG> {
        self.variant(GpioSwportaDdr::Out)
    }
}
impl R {
    #[doc = "Bits 0:28 - Values written to this register independently control the direction of the corresponding data bit in the Port A Data Register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
    #[inline(always)]
    pub fn gpio_swporta_ddr(&self) -> GpioSwportaDdrR {
        GpioSwportaDdrR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Values written to this register independently control the direction of the corresponding data bit in the Port A Data Register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_swporta_ddr(&mut self) -> GpioSwportaDdrW<GpioSwportaDdrSpec> {
        GpioSwportaDdrW::new(self, 0)
    }
}
#[doc = "This register establishes the direction of each corresponding GPIO Data Field Bit. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_swporta_ddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_swporta_ddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioSwportaDdrSpec;
impl crate::RegisterSpec for GpioSwportaDdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`gpio_swporta_ddr::R`](R) reader structure"]
impl crate::Readable for GpioSwportaDdrSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_swporta_ddr::W`](W) writer structure"]
impl crate::Writable for GpioSwportaDdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_swporta_ddr to value 0"]
impl crate::Resettable for GpioSwportaDdrSpec {
    const RESET_VALUE: u32 = 0;
}
