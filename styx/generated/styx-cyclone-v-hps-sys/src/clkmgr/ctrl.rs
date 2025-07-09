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
#[doc = "Register `ctrl` reader"]
pub type R = crate::R<CtrlSpec>;
#[doc = "Register `ctrl` writer"]
pub type W = crate::W<CtrlSpec>;
#[doc = "Field `safemode` reader - When set the Clock Manager is in Safe Mode. In Safe Mode Clock Manager register settings defining clock behavior are ignored and clocks are set to a Safe Mode state.In Safe Mode all clocks with the optional exception of debug clocks, are directly generated from the EOSC1 clock input, all PLLs are bypassed, all programmable dividers are set to 1 and all clocks are enabled. This bit should only be cleared when clocks have been correctly configured This field is set on a cold reset and optionally on a warm reset and may not be set by SW."]
pub type SafemodeR = crate::BitReader;
#[doc = "Field `safemode` writer - When set the Clock Manager is in Safe Mode. In Safe Mode Clock Manager register settings defining clock behavior are ignored and clocks are set to a Safe Mode state.In Safe Mode all clocks with the optional exception of debug clocks, are directly generated from the EOSC1 clock input, all PLLs are bypassed, all programmable dividers are set to 1 and all clocks are enabled. This bit should only be cleared when clocks have been correctly configured This field is set on a cold reset and optionally on a warm reset and may not be set by SW."]
pub type SafemodeW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `ensfmdwr` reader - When set the Clock Manager will respond to a Safe Mode request from the Reset Manager on a warm reset by setting the Safe Mode bit. When clear the clock manager will not set the the Safe Mode bit on a warm reset This bit is cleared on a cold reset. Warm reset has no affect on this bit."]
pub type EnsfmdwrR = crate::BitReader;
#[doc = "Field `ensfmdwr` writer - When set the Clock Manager will respond to a Safe Mode request from the Reset Manager on a warm reset by setting the Safe Mode bit. When clear the clock manager will not set the the Safe Mode bit on a warm reset This bit is cleared on a cold reset. Warm reset has no affect on this bit."]
pub type EnsfmdwrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When set the Clock Manager is in Safe Mode. In Safe Mode Clock Manager register settings defining clock behavior are ignored and clocks are set to a Safe Mode state.In Safe Mode all clocks with the optional exception of debug clocks, are directly generated from the EOSC1 clock input, all PLLs are bypassed, all programmable dividers are set to 1 and all clocks are enabled. This bit should only be cleared when clocks have been correctly configured This field is set on a cold reset and optionally on a warm reset and may not be set by SW."]
    #[inline(always)]
    pub fn safemode(&self) -> SafemodeR {
        SafemodeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - When set the Clock Manager will respond to a Safe Mode request from the Reset Manager on a warm reset by setting the Safe Mode bit. When clear the clock manager will not set the the Safe Mode bit on a warm reset This bit is cleared on a cold reset. Warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn ensfmdwr(&self) -> EnsfmdwrR {
        EnsfmdwrR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set the Clock Manager is in Safe Mode. In Safe Mode Clock Manager register settings defining clock behavior are ignored and clocks are set to a Safe Mode state.In Safe Mode all clocks with the optional exception of debug clocks, are directly generated from the EOSC1 clock input, all PLLs are bypassed, all programmable dividers are set to 1 and all clocks are enabled. This bit should only be cleared when clocks have been correctly configured This field is set on a cold reset and optionally on a warm reset and may not be set by SW."]
    #[inline(always)]
    #[must_use]
    pub fn safemode(&mut self) -> SafemodeW<CtrlSpec> {
        SafemodeW::new(self, 0)
    }
    #[doc = "Bit 2 - When set the Clock Manager will respond to a Safe Mode request from the Reset Manager on a warm reset by setting the Safe Mode bit. When clear the clock manager will not set the the Safe Mode bit on a warm reset This bit is cleared on a cold reset. Warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn ensfmdwr(&mut self) -> EnsfmdwrW<CtrlSpec> {
        EnsfmdwrW::new(self, 2)
    }
}
#[doc = "Contains fields that control the entire Clock Manager.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlSpec;
impl crate::RegisterSpec for CtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`ctrl::R`](R) reader structure"]
impl crate::Readable for CtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrl::W`](W) writer structure"]
impl crate::Writable for CtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x01;
}
#[doc = "`reset()` method sets ctrl to value 0x05"]
impl crate::Resettable for CtrlSpec {
    const RESET_VALUE: u32 = 0x05;
}
