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
#[doc = "Register `secgrp_l4osc1` reader"]
pub type R = crate::R<SecgrpL4osc1Spec>;
#[doc = "Register `secgrp_l4osc1` writer"]
pub type W = crate::W<SecgrpL4osc1Spec>;
#[doc = "Field `l4wd0` reader - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
pub type L4wd0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4wd0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<L4wd0> for bool {
    #[inline(always)]
    fn from(variant: L4wd0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `l4wd0` writer - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
pub type L4wd0W<'a, REG> = crate::BitWriter<'a, REG, L4wd0>;
impl<'a, REG> L4wd0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(L4wd0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(L4wd0::Nonsecure)
    }
}
#[doc = "Field `l4wd1` reader - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
pub type L4wd1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4wd1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<L4wd1> for bool {
    #[inline(always)]
    fn from(variant: L4wd1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `l4wd1` writer - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
pub type L4wd1W<'a, REG> = crate::BitWriter<'a, REG, L4wd1>;
impl<'a, REG> L4wd1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(L4wd1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(L4wd1::Nonsecure)
    }
}
#[doc = "Field `clkmgr` reader - Controls whether secure or non-secure masters can access the Clock Manager slave."]
pub type ClkmgrR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the Clock Manager slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clkmgr {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Clkmgr> for bool {
    #[inline(always)]
    fn from(variant: Clkmgr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `clkmgr` writer - Controls whether secure or non-secure masters can access the Clock Manager slave."]
pub type ClkmgrW<'a, REG> = crate::BitWriter<'a, REG, Clkmgr>;
impl<'a, REG> ClkmgrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Clkmgr::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Clkmgr::Nonsecure)
    }
}
#[doc = "Field `rstmgr` reader - Controls whether secure or non-secure masters can access the Reset Manager slave."]
pub type RstmgrR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the Reset Manager slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rstmgr {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Rstmgr> for bool {
    #[inline(always)]
    fn from(variant: Rstmgr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rstmgr` writer - Controls whether secure or non-secure masters can access the Reset Manager slave."]
pub type RstmgrW<'a, REG> = crate::BitWriter<'a, REG, Rstmgr>;
impl<'a, REG> RstmgrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Rstmgr::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Rstmgr::Nonsecure)
    }
}
#[doc = "Field `sysmgr` reader - Controls whether secure or non-secure masters can access the System Manager slave."]
pub type SysmgrR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the System Manager slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sysmgr {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Sysmgr> for bool {
    #[inline(always)]
    fn from(variant: Sysmgr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sysmgr` writer - Controls whether secure or non-secure masters can access the System Manager slave."]
pub type SysmgrW<'a, REG> = crate::BitWriter<'a, REG, Sysmgr>;
impl<'a, REG> SysmgrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Sysmgr::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Sysmgr::Nonsecure)
    }
}
#[doc = "Field `osc1timer0` reader - Controls whether secure or non-secure masters can access the OSC1 Timer 0 slave."]
pub type Osc1timer0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the OSC1 Timer 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Osc1timer0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Osc1timer0> for bool {
    #[inline(always)]
    fn from(variant: Osc1timer0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `osc1timer0` writer - Controls whether secure or non-secure masters can access the OSC1 Timer 0 slave."]
pub type Osc1timer0W<'a, REG> = crate::BitWriter<'a, REG, Osc1timer0>;
impl<'a, REG> Osc1timer0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Osc1timer0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Osc1timer0::Nonsecure)
    }
}
#[doc = "Field `osc1timer1` reader - Controls whether secure or non-secure masters can access the OSC1 Timer 1 slave."]
pub type Osc1timer1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the OSC1 Timer 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Osc1timer1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Osc1timer1> for bool {
    #[inline(always)]
    fn from(variant: Osc1timer1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `osc1timer1` writer - Controls whether secure or non-secure masters can access the OSC1 Timer 1 slave."]
pub type Osc1timer1W<'a, REG> = crate::BitWriter<'a, REG, Osc1timer1>;
impl<'a, REG> Osc1timer1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Osc1timer1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Osc1timer1::Nonsecure)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
    #[inline(always)]
    pub fn l4wd0(&self) -> L4wd0R {
        L4wd0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
    #[inline(always)]
    pub fn l4wd1(&self) -> L4wd1R {
        L4wd1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the Clock Manager slave."]
    #[inline(always)]
    pub fn clkmgr(&self) -> ClkmgrR {
        ClkmgrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the Reset Manager slave."]
    #[inline(always)]
    pub fn rstmgr(&self) -> RstmgrR {
        RstmgrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls whether secure or non-secure masters can access the System Manager slave."]
    #[inline(always)]
    pub fn sysmgr(&self) -> SysmgrR {
        SysmgrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Controls whether secure or non-secure masters can access the OSC1 Timer 0 slave."]
    #[inline(always)]
    pub fn osc1timer0(&self) -> Osc1timer0R {
        Osc1timer0R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Controls whether secure or non-secure masters can access the OSC1 Timer 1 slave."]
    #[inline(always)]
    pub fn osc1timer1(&self) -> Osc1timer1R {
        Osc1timer1R::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn l4wd0(&mut self) -> L4wd0W<SecgrpL4osc1Spec> {
        L4wd0W::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the L4 Watchdog Timer 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn l4wd1(&mut self) -> L4wd1W<SecgrpL4osc1Spec> {
        L4wd1W::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the Clock Manager slave."]
    #[inline(always)]
    #[must_use]
    pub fn clkmgr(&mut self) -> ClkmgrW<SecgrpL4osc1Spec> {
        ClkmgrW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the Reset Manager slave."]
    #[inline(always)]
    #[must_use]
    pub fn rstmgr(&mut self) -> RstmgrW<SecgrpL4osc1Spec> {
        RstmgrW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls whether secure or non-secure masters can access the System Manager slave."]
    #[inline(always)]
    #[must_use]
    pub fn sysmgr(&mut self) -> SysmgrW<SecgrpL4osc1Spec> {
        SysmgrW::new(self, 4)
    }
    #[doc = "Bit 5 - Controls whether secure or non-secure masters can access the OSC1 Timer 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn osc1timer0(&mut self) -> Osc1timer0W<SecgrpL4osc1Spec> {
        Osc1timer0W::new(self, 5)
    }
    #[doc = "Bit 6 - Controls whether secure or non-secure masters can access the OSC1 Timer 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn osc1timer1(&mut self) -> Osc1timer1W<SecgrpL4osc1Spec> {
        Osc1timer1W::new(self, 6)
    }
}
#[doc = "Controls security settings for L4 OSC1 peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4osc1::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SecgrpL4osc1Spec;
impl crate::RegisterSpec for SecgrpL4osc1Spec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`write(|w| ..)` method takes [`secgrp_l4osc1::W`](W) writer structure"]
impl crate::Writable for SecgrpL4osc1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets secgrp_l4osc1 to value 0"]
impl crate::Resettable for SecgrpL4osc1Spec {
    const RESET_VALUE: u32 = 0;
}
