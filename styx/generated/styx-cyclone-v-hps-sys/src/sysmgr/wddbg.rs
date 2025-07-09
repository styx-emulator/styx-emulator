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
#[doc = "Register `wddbg` reader"]
pub type R = crate::R<WddbgSpec>;
#[doc = "Register `wddbg` writer"]
pub type W = crate::W<WddbgSpec>;
#[doc = "Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index.\n\nValue on reset: 3"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode0 {
    #[doc = "0: `0`"]
    Continue = 0,
    #[doc = "1: `1`"]
    PauseCpu0 = 1,
    #[doc = "2: `10`"]
    PauseCpu1 = 2,
    #[doc = "3: `11`"]
    PauseEither = 3,
}
impl From<Mode0> for u8 {
    #[inline(always)]
    fn from(variant: Mode0) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Mode0 {
    type Ux = u8;
}
#[doc = "Field `mode_0` reader - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
pub type Mode0R = crate::FieldReader<Mode0>;
impl Mode0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mode0 {
        match self.bits {
            0 => Mode0::Continue,
            1 => Mode0::PauseCpu0,
            2 => Mode0::PauseCpu1,
            3 => Mode0::PauseEither,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_continue(&self) -> bool {
        *self == Mode0::Continue
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pause_cpu0(&self) -> bool {
        *self == Mode0::PauseCpu0
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_pause_cpu1(&self) -> bool {
        *self == Mode0::PauseCpu1
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_pause_either(&self) -> bool {
        *self == Mode0::PauseEither
    }
}
#[doc = "Field `mode_0` writer - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
pub type Mode0W<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Mode0>;
impl<'a, REG> Mode0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn continue_(self) -> &'a mut crate::W<REG> {
        self.variant(Mode0::Continue)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pause_cpu0(self) -> &'a mut crate::W<REG> {
        self.variant(Mode0::PauseCpu0)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn pause_cpu1(self) -> &'a mut crate::W<REG> {
        self.variant(Mode0::PauseCpu1)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn pause_either(self) -> &'a mut crate::W<REG> {
        self.variant(Mode0::PauseEither)
    }
}
#[doc = "Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index.\n\nValue on reset: 3"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode1 {
    #[doc = "0: `0`"]
    Continue = 0,
    #[doc = "1: `1`"]
    PauseCpu0 = 1,
    #[doc = "2: `10`"]
    PauseCpu1 = 2,
    #[doc = "3: `11`"]
    PauseEither = 3,
}
impl From<Mode1> for u8 {
    #[inline(always)]
    fn from(variant: Mode1) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Mode1 {
    type Ux = u8;
}
#[doc = "Field `mode_1` reader - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
pub type Mode1R = crate::FieldReader<Mode1>;
impl Mode1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mode1 {
        match self.bits {
            0 => Mode1::Continue,
            1 => Mode1::PauseCpu0,
            2 => Mode1::PauseCpu1,
            3 => Mode1::PauseEither,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_continue(&self) -> bool {
        *self == Mode1::Continue
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pause_cpu0(&self) -> bool {
        *self == Mode1::PauseCpu0
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_pause_cpu1(&self) -> bool {
        *self == Mode1::PauseCpu1
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_pause_either(&self) -> bool {
        *self == Mode1::PauseEither
    }
}
#[doc = "Field `mode_1` writer - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
pub type Mode1W<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Mode1>;
impl<'a, REG> Mode1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn continue_(self) -> &'a mut crate::W<REG> {
        self.variant(Mode1::Continue)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pause_cpu0(self) -> &'a mut crate::W<REG> {
        self.variant(Mode1::PauseCpu0)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn pause_cpu1(self) -> &'a mut crate::W<REG> {
        self.variant(Mode1::PauseCpu1)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn pause_either(self) -> &'a mut crate::W<REG> {
        self.variant(Mode1::PauseEither)
    }
}
impl R {
    #[doc = "Bits 0:1 - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
    #[inline(always)]
    pub fn mode_0(&self) -> Mode0R {
        Mode0R::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
    #[inline(always)]
    pub fn mode_1(&self) -> Mode1R {
        Mode1R::new(((self.bits >> 2) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
    #[inline(always)]
    #[must_use]
    pub fn mode_0(&mut self) -> Mode0W<WddbgSpec> {
        Mode0W::new(self, 0)
    }
    #[doc = "Bits 2:3 - Controls behavior of L4 watchdog when CPUs in debug mode. Field array index matches L4 watchdog index."]
    #[inline(always)]
    #[must_use]
    pub fn mode_1(&mut self) -> Mode1W<WddbgSpec> {
        Mode1W::new(self, 2)
    }
}
#[doc = "Controls the behavior of the L4 watchdogs when the CPUs are in debug mode. These control registers are used to drive the pause input signal of the L4 watchdogs. Note that the watchdogs built into the MPU automatically are paused when their associated CPU enters debug mode. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wddbg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wddbg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WddbgSpec;
impl crate::RegisterSpec for WddbgSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`wddbg::R`](R) reader structure"]
impl crate::Readable for WddbgSpec {}
#[doc = "`write(|w| ..)` method takes [`wddbg::W`](W) writer structure"]
impl crate::Writable for WddbgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets wddbg to value 0x0f"]
impl crate::Resettable for WddbgSpec {
    const RESET_VALUE: u32 = 0x0f;
}
