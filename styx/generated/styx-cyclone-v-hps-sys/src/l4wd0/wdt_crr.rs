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
#[doc = "Register `wdt_crr` reader"]
pub type R = crate::R<WdtCrrSpec>;
#[doc = "Register `wdt_crr` writer"]
pub type W = crate::W<WdtCrrSpec>;
#[doc = "Field `wdt_crr` reader - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
pub type WdtCrrR = crate::FieldReader;
#[doc = "This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WdtCrr {
    #[doc = "118: `1110110`"]
    Kick = 118,
}
impl From<WdtCrr> for u8 {
    #[inline(always)]
    fn from(variant: WdtCrr) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for WdtCrr {
    type Ux = u8;
}
#[doc = "Field `wdt_crr` writer - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
pub type WdtCrrW<'a, REG> = crate::FieldWriter<'a, REG, 8, WdtCrr>;
impl<'a, REG> WdtCrrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1110110`"]
    #[inline(always)]
    pub fn kick(self) -> &'a mut crate::W<REG> {
        self.variant(WdtCrr::Kick)
    }
}
impl R {
    #[doc = "Bits 0:7 - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
    #[inline(always)]
    pub fn wdt_crr(&self) -> WdtCrrR {
        WdtCrrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_crr(&mut self) -> WdtCrrW<WdtCrrSpec> {
        WdtCrrW::new(self, 0)
    }
}
#[doc = "Restarts the watchdog.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_crr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCrrSpec;
impl crate::RegisterSpec for WdtCrrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`write(|w| ..)` method takes [`wdt_crr::W`](W) writer structure"]
impl crate::Writable for WdtCrrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets wdt_crr to value 0"]
impl crate::Resettable for WdtCrrSpec {
    const RESET_VALUE: u32 = 0;
}
