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
#[doc = "Register `romcodegrp_warmramgrp_enable` reader"]
pub type R = crate::R<RomcodegrpWarmramgrpEnableSpec>;
#[doc = "Register `romcodegrp_warmramgrp_enable` writer"]
pub type W = crate::W<RomcodegrpWarmramgrpEnableSpec>;
#[doc = "Controls whether Boot ROM will attempt to boot from the contents of the On-chip RAM on a warm reset. When this feature is enabled, the Boot ROM code will not configure boot IOs, the pin mux, or clocks. Note that the enable value is a 32-bit magic value (provided by the enum).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Magic {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "2929655484: `10101110100111101111111010111100`"]
    Enabled = 2929655484,
}
impl From<Magic> for u32 {
    #[inline(always)]
    fn from(variant: Magic) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Magic {
    type Ux = u32;
}
#[doc = "Field `magic` reader - Controls whether Boot ROM will attempt to boot from the contents of the On-chip RAM on a warm reset. When this feature is enabled, the Boot ROM code will not configure boot IOs, the pin mux, or clocks. Note that the enable value is a 32-bit magic value (provided by the enum)."]
pub type MagicR = crate::FieldReader<Magic>;
impl MagicR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Magic> {
        match self.bits {
            0 => Some(Magic::Disabled),
            2929655484 => Some(Magic::Enabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Magic::Disabled
    }
    #[doc = "`10101110100111101111111010111100`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Magic::Enabled
    }
}
#[doc = "Field `magic` writer - Controls whether Boot ROM will attempt to boot from the contents of the On-chip RAM on a warm reset. When this feature is enabled, the Boot ROM code will not configure boot IOs, the pin mux, or clocks. Note that the enable value is a 32-bit magic value (provided by the enum)."]
pub type MagicW<'a, REG> = crate::FieldWriter<'a, REG, 32, Magic>;
impl<'a, REG> MagicW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Magic::Disabled)
    }
    #[doc = "`10101110100111101111111010111100`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Magic::Enabled)
    }
}
impl R {
    #[doc = "Bits 0:31 - Controls whether Boot ROM will attempt to boot from the contents of the On-chip RAM on a warm reset. When this feature is enabled, the Boot ROM code will not configure boot IOs, the pin mux, or clocks. Note that the enable value is a 32-bit magic value (provided by the enum)."]
    #[inline(always)]
    pub fn magic(&self) -> MagicR {
        MagicR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Controls whether Boot ROM will attempt to boot from the contents of the On-chip RAM on a warm reset. When this feature is enabled, the Boot ROM code will not configure boot IOs, the pin mux, or clocks. Note that the enable value is a 32-bit magic value (provided by the enum)."]
    #[inline(always)]
    #[must_use]
    pub fn magic(&mut self) -> MagicW<RomcodegrpWarmramgrpEnableSpec> {
        MagicW::new(self, 0)
    }
}
#[doc = "Enables or disables the warm reset from On-chip RAM feature.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpWarmramgrpEnableSpec;
impl crate::RegisterSpec for RomcodegrpWarmramgrpEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 224u64;
}
#[doc = "`read()` method returns [`romcodegrp_warmramgrp_enable::R`](R) reader structure"]
impl crate::Readable for RomcodegrpWarmramgrpEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_warmramgrp_enable::W`](W) writer structure"]
impl crate::Writable for RomcodegrpWarmramgrpEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_warmramgrp_enable to value 0"]
impl crate::Resettable for RomcodegrpWarmramgrpEnableSpec {
    const RESET_VALUE: u32 = 0;
}
