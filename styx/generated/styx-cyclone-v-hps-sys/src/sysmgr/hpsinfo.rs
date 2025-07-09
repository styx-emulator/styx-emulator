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
#[doc = "Register `hpsinfo` reader"]
pub type R = crate::R<HpsinfoSpec>;
#[doc = "Register `hpsinfo` writer"]
pub type W = crate::W<HpsinfoSpec>;
#[doc = "Indicates if CPU1 is available in MPU or not.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dualcore {
    #[doc = "0: `0`"]
    SingleCore = 0,
    #[doc = "1: `1`"]
    DualCore = 1,
}
impl From<Dualcore> for bool {
    #[inline(always)]
    fn from(variant: Dualcore) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dualcore` reader - Indicates if CPU1 is available in MPU or not."]
pub type DualcoreR = crate::BitReader<Dualcore>;
impl DualcoreR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dualcore {
        match self.bits {
            false => Dualcore::SingleCore,
            true => Dualcore::DualCore,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single_core(&self) -> bool {
        *self == Dualcore::SingleCore
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dual_core(&self) -> bool {
        *self == Dualcore::DualCore
    }
}
#[doc = "Field `dualcore` writer - Indicates if CPU1 is available in MPU or not."]
pub type DualcoreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates if CAN0 and CAN1 controllers are available or not.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Can {
    #[doc = "0: `0`"]
    CanUnavailable = 0,
    #[doc = "1: `1`"]
    CanAvailable = 1,
}
impl From<Can> for bool {
    #[inline(always)]
    fn from(variant: Can) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `can` reader - Indicates if CAN0 and CAN1 controllers are available or not."]
pub type CanR = crate::BitReader<Can>;
impl CanR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Can {
        match self.bits {
            false => Can::CanUnavailable,
            true => Can::CanAvailable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_can_unavailable(&self) -> bool {
        *self == Can::CanUnavailable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_can_available(&self) -> bool {
        *self == Can::CanAvailable
    }
}
#[doc = "Field `can` writer - Indicates if CAN0 and CAN1 controllers are available or not."]
pub type CanW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Indicates if CPU1 is available in MPU or not."]
    #[inline(always)]
    pub fn dualcore(&self) -> DualcoreR {
        DualcoreR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Indicates if CAN0 and CAN1 controllers are available or not."]
    #[inline(always)]
    pub fn can(&self) -> CanR {
        CanR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Indicates if CPU1 is available in MPU or not."]
    #[inline(always)]
    #[must_use]
    pub fn dualcore(&mut self) -> DualcoreW<HpsinfoSpec> {
        DualcoreW::new(self, 0)
    }
    #[doc = "Bit 1 - Indicates if CAN0 and CAN1 controllers are available or not."]
    #[inline(always)]
    #[must_use]
    pub fn can(&mut self) -> CanW<HpsinfoSpec> {
        CanW::new(self, 1)
    }
}
#[doc = "Provides information about the HPS capabilities.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hpsinfo::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HpsinfoSpec;
impl crate::RegisterSpec for HpsinfoSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`hpsinfo::R`](R) reader structure"]
impl crate::Readable for HpsinfoSpec {}
#[doc = "`reset()` method sets hpsinfo to value 0"]
impl crate::Resettable for HpsinfoSpec {
    const RESET_VALUE: u32 = 0;
}
