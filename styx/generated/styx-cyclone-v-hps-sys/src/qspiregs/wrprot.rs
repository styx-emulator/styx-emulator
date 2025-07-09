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
#[doc = "Register `wrprot` reader"]
pub type R = crate::R<WrprotSpec>;
#[doc = "Register `wrprot` writer"]
pub type W = crate::W<WrprotSpec>;
#[doc = "When enabled, the protection region defined in the lower and upper write protection registers is inverted meaning it is the region that the system is permitted to write to. When disabled, the protection region defined in the lower and upper write protection registers is the region that the system is not permitted to write to.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inv {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Disable = 0,
}
impl From<Inv> for bool {
    #[inline(always)]
    fn from(variant: Inv) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inv` reader - When enabled, the protection region defined in the lower and upper write protection registers is inverted meaning it is the region that the system is permitted to write to. When disabled, the protection region defined in the lower and upper write protection registers is the region that the system is not permitted to write to."]
pub type InvR = crate::BitReader<Inv>;
impl InvR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inv {
        match self.bits {
            true => Inv::Enable,
            false => Inv::Disable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Inv::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Inv::Disable
    }
}
#[doc = "Field `inv` writer - When enabled, the protection region defined in the lower and upper write protection registers is inverted meaning it is the region that the system is permitted to write to. When disabled, the protection region defined in the lower and upper write protection registers is the region that the system is not permitted to write to."]
pub type InvW<'a, REG> = crate::BitWriter<'a, REG, Inv>;
impl<'a, REG> InvW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Inv::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Inv::Disable)
    }
}
#[doc = "When enabled, any AHB write access with an address within the protection region defined in the lower and upper write protection registers is rejected. An AHB error response is generated and an interrupt source triggered. When disabled, the protection region is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum En {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Disable = 0,
}
impl From<En> for bool {
    #[inline(always)]
    fn from(variant: En) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `en` reader - When enabled, any AHB write access with an address within the protection region defined in the lower and upper write protection registers is rejected. An AHB error response is generated and an interrupt source triggered. When disabled, the protection region is disabled."]
pub type EnR = crate::BitReader<En>;
impl EnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> En {
        match self.bits {
            true => En::Enable,
            false => En::Disable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == En::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == En::Disable
    }
}
#[doc = "Field `en` writer - When enabled, any AHB write access with an address within the protection region defined in the lower and upper write protection registers is rejected. An AHB error response is generated and an interrupt source triggered. When disabled, the protection region is disabled."]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG, En>;
impl<'a, REG> EnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(En::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(En::Disable)
    }
}
impl R {
    #[doc = "Bit 0 - When enabled, the protection region defined in the lower and upper write protection registers is inverted meaning it is the region that the system is permitted to write to. When disabled, the protection region defined in the lower and upper write protection registers is the region that the system is not permitted to write to."]
    #[inline(always)]
    pub fn inv(&self) -> InvR {
        InvR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When enabled, any AHB write access with an address within the protection region defined in the lower and upper write protection registers is rejected. An AHB error response is generated and an interrupt source triggered. When disabled, the protection region is disabled."]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When enabled, the protection region defined in the lower and upper write protection registers is inverted meaning it is the region that the system is permitted to write to. When disabled, the protection region defined in the lower and upper write protection registers is the region that the system is not permitted to write to."]
    #[inline(always)]
    #[must_use]
    pub fn inv(&mut self) -> InvW<WrprotSpec> {
        InvW::new(self, 0)
    }
    #[doc = "Bit 1 - When enabled, any AHB write access with an address within the protection region defined in the lower and upper write protection registers is rejected. An AHB error response is generated and an interrupt source triggered. When disabled, the protection region is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<WrprotSpec> {
        EnW::new(self, 1)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wrprot::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wrprot::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WrprotSpec;
impl crate::RegisterSpec for WrprotSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`wrprot::R`](R) reader structure"]
impl crate::Readable for WrprotSpec {}
#[doc = "`write(|w| ..)` method takes [`wrprot::W`](W) writer structure"]
impl crate::Writable for WrprotSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets wrprot to value 0"]
impl crate::Resettable for WrprotSpec {
    const RESET_VALUE: u32 = 0;
}
