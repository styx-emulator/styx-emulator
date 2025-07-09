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
#[doc = "Register `config_rb_pin_enabled` reader"]
pub type R = crate::R<ConfigRbPinEnabledSpec>;
#[doc = "Register `config_rb_pin_enabled` writer"]
pub type W = crate::W<ConfigRbPinEnabledSpec>;
#[doc = "Field `bank0` reader - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 0. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 0. Polling mode.\\[/list\\]"]
pub type Bank0R = crate::BitReader;
#[doc = "Field `bank0` writer - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 0. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 0. Polling mode.\\[/list\\]"]
pub type Bank0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bank1` reader - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 1. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 1. Polling mode.\\[/list\\]"]
pub type Bank1R = crate::BitReader;
#[doc = "Field `bank1` writer - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 1. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 1. Polling mode.\\[/list\\]"]
pub type Bank1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bank2` reader - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 2. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 2. Polling mode.\\[/list\\]"]
pub type Bank2R = crate::BitReader;
#[doc = "Field `bank2` writer - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 2. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 2. Polling mode.\\[/list\\]"]
pub type Bank2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bank3` reader - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 3. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 3. Polling mode.\\[/list\\]"]
pub type Bank3R = crate::BitReader;
#[doc = "Field `bank3` writer - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 3. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 3. Polling mode.\\[/list\\]"]
pub type Bank3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 0. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 0. Polling mode.\\[/list\\]"]
    #[inline(always)]
    pub fn bank0(&self) -> Bank0R {
        Bank0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 1. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 1. Polling mode.\\[/list\\]"]
    #[inline(always)]
    pub fn bank1(&self) -> Bank1R {
        Bank1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 2. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 2. Polling mode.\\[/list\\]"]
    #[inline(always)]
    pub fn bank2(&self) -> Bank2R {
        Bank2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 3. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 3. Polling mode.\\[/list\\]"]
    #[inline(always)]
    pub fn bank3(&self) -> Bank3R {
        Bank3R::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 0. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 0. Polling mode.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn bank0(&mut self) -> Bank0W<ConfigRbPinEnabledSpec> {
        Bank0W::new(self, 0)
    }
    #[doc = "Bit 1 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 1. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 1. Polling mode.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn bank1(&mut self) -> Bank1W<ConfigRbPinEnabledSpec> {
        Bank1W::new(self, 1)
    }
    #[doc = "Bit 2 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 2. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 2. Polling mode.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn bank2(&mut self) -> Bank2W<ConfigRbPinEnabledSpec> {
        Bank2W::new(self, 2)
    }
    #[doc = "Bit 3 - Sets Denali Flash Controller in interrupt pin or polling mode \\[list\\]\\[*\\]1 - R/B pin enabled for bank 3. Interrupt pin mode. \\[*\\]0 - R/B pin disabled for bank 3. Polling mode.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn bank3(&mut self) -> Bank3W<ConfigRbPinEnabledSpec> {
        Bank3W::new(self, 3)
    }
}
#[doc = "Interrupt or polling mode. Ready/Busy pin is enabled from device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_rb_pin_enabled::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_rb_pin_enabled::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigRbPinEnabledSpec;
impl crate::RegisterSpec for ConfigRbPinEnabledSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`config_rb_pin_enabled::R`](R) reader structure"]
impl crate::Readable for ConfigRbPinEnabledSpec {}
#[doc = "`write(|w| ..)` method takes [`config_rb_pin_enabled::W`](W) writer structure"]
impl crate::Writable for ConfigRbPinEnabledSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_rb_pin_enabled to value 0x01"]
impl crate::Resettable for ConfigRbPinEnabledSpec {
    const RESET_VALUE: u32 = 0x01;
}
