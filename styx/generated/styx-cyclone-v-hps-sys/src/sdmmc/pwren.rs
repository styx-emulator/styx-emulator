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
#[doc = "Register `pwren` reader"]
pub type R = crate::R<PwrenSpec>;
#[doc = "Register `pwren` writer"]
pub type W = crate::W<PwrenSpec>;
#[doc = "Power on/off switch for one card; for example, bit\\[0\\]
controls the card. Once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerEnable {
    #[doc = "0: `0`"]
    Off = 0,
    #[doc = "1: `1`"]
    On = 1,
}
impl From<PowerEnable> for bool {
    #[inline(always)]
    fn from(variant: PowerEnable) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `power_enable` reader - Power on/off switch for one card; for example, bit\\[0\\]
controls the card. Once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card."]
pub type PowerEnableR = crate::BitReader<PowerEnable>;
impl PowerEnableR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> PowerEnable {
        match self.bits {
            false => PowerEnable::Off,
            true => PowerEnable::On,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_off(&self) -> bool {
        *self == PowerEnable::Off
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_on(&self) -> bool {
        *self == PowerEnable::On
    }
}
#[doc = "Field `power_enable` writer - Power on/off switch for one card; for example, bit\\[0\\]
controls the card. Once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card."]
pub type PowerEnableW<'a, REG> = crate::BitWriter<'a, REG, PowerEnable>;
impl<'a, REG> PowerEnableW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn off(self) -> &'a mut crate::W<REG> {
        self.variant(PowerEnable::Off)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn on(self) -> &'a mut crate::W<REG> {
        self.variant(PowerEnable::On)
    }
}
impl R {
    #[doc = "Bit 0 - Power on/off switch for one card; for example, bit\\[0\\]
controls the card. Once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card."]
    #[inline(always)]
    pub fn power_enable(&self) -> PowerEnableR {
        PowerEnableR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Power on/off switch for one card; for example, bit\\[0\\]
controls the card. Once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card."]
    #[inline(always)]
    #[must_use]
    pub fn power_enable(&mut self) -> PowerEnableW<PwrenSpec> {
        PowerEnableW::new(self, 0)
    }
}
#[doc = "Power on/off switch for card; once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pwren::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pwren::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PwrenSpec;
impl crate::RegisterSpec for PwrenSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`pwren::R`](R) reader structure"]
impl crate::Readable for PwrenSpec {}
#[doc = "`write(|w| ..)` method takes [`pwren::W`](W) writer structure"]
impl crate::Writable for PwrenSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pwren to value 0"]
impl crate::Resettable for PwrenSpec {
    const RESET_VALUE: u32 = 0;
}
