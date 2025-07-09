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
#[doc = "Register `fpgaintfgrp_module` reader"]
pub type R = crate::R<FpgaintfgrpModuleSpec>;
#[doc = "Register `fpgaintfgrp_module` writer"]
pub type W = crate::W<FpgaintfgrpModuleSpec>;
#[doc = "Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emac0 {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Emac0> for bool {
    #[inline(always)]
    fn from(variant: Emac0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `emac_0` reader - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
pub type Emac0R = crate::BitReader<Emac0>;
impl Emac0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Emac0 {
        match self.bits {
            false => Emac0::Disable,
            true => Emac0::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Emac0::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Emac0::Enable
    }
}
#[doc = "Field `emac_0` writer - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
pub type Emac0W<'a, REG> = crate::BitWriter<'a, REG, Emac0>;
impl<'a, REG> Emac0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Emac0::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Emac0::Enable)
    }
}
#[doc = "Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emac1 {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Emac1> for bool {
    #[inline(always)]
    fn from(variant: Emac1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `emac_1` reader - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
pub type Emac1R = crate::BitReader<Emac1>;
impl Emac1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Emac1 {
        match self.bits {
            false => Emac1::Disable,
            true => Emac1::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Emac1::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Emac1::Enable
    }
}
#[doc = "Field `emac_1` writer - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
pub type Emac1W<'a, REG> = crate::BitWriter<'a, REG, Emac1>;
impl<'a, REG> Emac1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Emac1::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Emac1::Enable)
    }
}
impl R {
    #[doc = "Bit 2 - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
    #[inline(always)]
    pub fn emac_0(&self) -> Emac0R {
        Emac0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
    #[inline(always)]
    pub fn emac_1(&self) -> Emac1R {
        Emac1R::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 2 - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
    #[inline(always)]
    #[must_use]
    pub fn emac_0(&mut self) -> Emac0W<FpgaintfgrpModuleSpec> {
        Emac0W::new(self, 2)
    }
    #[doc = "Bit 3 - Used to disable signals from the FPGA fabric to the EMAC modules that could potentially interfere with their normal operation. The array index corresponds to the EMAC module instance."]
    #[inline(always)]
    #[must_use]
    pub fn emac_1(&mut self) -> Emac1W<FpgaintfgrpModuleSpec> {
        Emac1W::new(self, 3)
    }
}
#[doc = "Used to disable signals from the FPGA fabric to individual HPS modules.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpgaintfgrp_module::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpgaintfgrp_module::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FpgaintfgrpModuleSpec;
impl crate::RegisterSpec for FpgaintfgrpModuleSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`fpgaintfgrp_module::R`](R) reader structure"]
impl crate::Readable for FpgaintfgrpModuleSpec {}
#[doc = "`write(|w| ..)` method takes [`fpgaintfgrp_module::W`](W) writer structure"]
impl crate::Writable for FpgaintfgrpModuleSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fpgaintfgrp_module to value 0"]
impl crate::Resettable for FpgaintfgrpModuleSpec {
    const RESET_VALUE: u32 = 0;
}
