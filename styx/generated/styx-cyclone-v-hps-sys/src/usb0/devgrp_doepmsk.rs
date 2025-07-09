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
#[doc = "Register `devgrp_doepmsk` reader"]
pub type R = crate::R<DevgrpDoepmskSpec>;
#[doc = "Register `devgrp_doepmsk` writer"]
pub type W = crate::W<DevgrpDoepmskSpec>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xfercomplmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Xfercomplmsk> for bool {
    #[inline(always)]
    fn from(variant: Xfercomplmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xfercomplmsk` reader - "]
pub type XfercomplmskR = crate::BitReader<Xfercomplmsk>;
impl XfercomplmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xfercomplmsk {
        match self.bits {
            false => Xfercomplmsk::Mask,
            true => Xfercomplmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Xfercomplmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Xfercomplmsk::Nomask
    }
}
#[doc = "Field `xfercomplmsk` writer - "]
pub type XfercomplmskW<'a, REG> = crate::BitWriter<'a, REG, Xfercomplmsk>;
impl<'a, REG> XfercomplmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Xfercomplmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Xfercomplmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epdisbldmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Epdisbldmsk> for bool {
    #[inline(always)]
    fn from(variant: Epdisbldmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epdisbldmsk` reader - "]
pub type EpdisbldmskR = crate::BitReader<Epdisbldmsk>;
impl EpdisbldmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epdisbldmsk {
        match self.bits {
            false => Epdisbldmsk::Mask,
            true => Epdisbldmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Epdisbldmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Epdisbldmsk::Nomask
    }
}
#[doc = "Field `epdisbldmsk` writer - "]
pub type EpdisbldmskW<'a, REG> = crate::BitWriter<'a, REG, Epdisbldmsk>;
impl<'a, REG> EpdisbldmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Epdisbldmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Epdisbldmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ahberrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ahberrmsk> for bool {
    #[inline(always)]
    fn from(variant: Ahberrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ahberrmsk` reader - "]
pub type AhberrmskR = crate::BitReader<Ahberrmsk>;
impl AhberrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ahberrmsk {
        match self.bits {
            false => Ahberrmsk::Mask,
            true => Ahberrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ahberrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ahberrmsk::Nomask
    }
}
#[doc = "Field `ahberrmsk` writer - "]
pub type AhberrmskW<'a, REG> = crate::BitWriter<'a, REG, Ahberrmsk>;
impl<'a, REG> AhberrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ahberrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ahberrmsk::Nomask)
    }
}
#[doc = "Applies to control endpoints only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setupmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Setupmsk> for bool {
    #[inline(always)]
    fn from(variant: Setupmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `setupmsk` reader - Applies to control endpoints only."]
pub type SetupmskR = crate::BitReader<Setupmsk>;
impl SetupmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Setupmsk {
        match self.bits {
            false => Setupmsk::Mask,
            true => Setupmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Setupmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Setupmsk::Nomask
    }
}
#[doc = "Field `setupmsk` writer - Applies to control endpoints only."]
pub type SetupmskW<'a, REG> = crate::BitWriter<'a, REG, Setupmsk>;
impl<'a, REG> SetupmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Setupmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Setupmsk::Nomask)
    }
}
#[doc = "Applies to control OUT endpoints only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outtknepdismsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Outtknepdismsk> for bool {
    #[inline(always)]
    fn from(variant: Outtknepdismsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outtknepdismsk` reader - Applies to control OUT endpoints only."]
pub type OuttknepdismskR = crate::BitReader<Outtknepdismsk>;
impl OuttknepdismskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outtknepdismsk {
        match self.bits {
            false => Outtknepdismsk::Mask,
            true => Outtknepdismsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outtknepdismsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outtknepdismsk::Nomask
    }
}
#[doc = "Field `outtknepdismsk` writer - Applies to control OUT endpoints only."]
pub type OuttknepdismskW<'a, REG> = crate::BitWriter<'a, REG, Outtknepdismsk>;
impl<'a, REG> OuttknepdismskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outtknepdismsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outtknepdismsk::Nomask)
    }
}
#[doc = "Applies to control OUT endpoints only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Back2backsetup {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Back2backsetup> for bool {
    #[inline(always)]
    fn from(variant: Back2backsetup) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `back2backsetup` reader - Applies to control OUT endpoints only."]
pub type Back2backsetupR = crate::BitReader<Back2backsetup>;
impl Back2backsetupR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Back2backsetup {
        match self.bits {
            false => Back2backsetup::Mask,
            true => Back2backsetup::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Back2backsetup::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Back2backsetup::Nomask
    }
}
#[doc = "Field `back2backsetup` writer - Applies to control OUT endpoints only."]
pub type Back2backsetupW<'a, REG> = crate::BitWriter<'a, REG, Back2backsetup>;
impl<'a, REG> Back2backsetupW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Back2backsetup::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Back2backsetup::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outpkterrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Outpkterrmsk> for bool {
    #[inline(always)]
    fn from(variant: Outpkterrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outpkterrmsk` reader - "]
pub type OutpkterrmskR = crate::BitReader<Outpkterrmsk>;
impl OutpkterrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outpkterrmsk {
        match self.bits {
            false => Outpkterrmsk::Mask,
            true => Outpkterrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outpkterrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outpkterrmsk::Nomask
    }
}
#[doc = "Field `outpkterrmsk` writer - "]
pub type OutpkterrmskW<'a, REG> = crate::BitWriter<'a, REG, Outpkterrmsk>;
impl<'a, REG> OutpkterrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outpkterrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outpkterrmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bnaoutintrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Bnaoutintrmsk> for bool {
    #[inline(always)]
    fn from(variant: Bnaoutintrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bnaoutintrmsk` reader - "]
pub type BnaoutintrmskR = crate::BitReader<Bnaoutintrmsk>;
impl BnaoutintrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bnaoutintrmsk {
        match self.bits {
            false => Bnaoutintrmsk::Mask,
            true => Bnaoutintrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Bnaoutintrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Bnaoutintrmsk::Nomask
    }
}
#[doc = "Field `bnaoutintrmsk` writer - "]
pub type BnaoutintrmskW<'a, REG> = crate::BitWriter<'a, REG, Bnaoutintrmsk>;
impl<'a, REG> BnaoutintrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Bnaoutintrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Bnaoutintrmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bbleerrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Bbleerrmsk> for bool {
    #[inline(always)]
    fn from(variant: Bbleerrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bbleerrmsk` reader - "]
pub type BbleerrmskR = crate::BitReader<Bbleerrmsk>;
impl BbleerrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bbleerrmsk {
        match self.bits {
            false => Bbleerrmsk::Mask,
            true => Bbleerrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Bbleerrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Bbleerrmsk::Nomask
    }
}
#[doc = "Field `bbleerrmsk` writer - "]
pub type BbleerrmskW<'a, REG> = crate::BitWriter<'a, REG, Bbleerrmsk>;
impl<'a, REG> BbleerrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Bbleerrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Bbleerrmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nakmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Nakmsk> for bool {
    #[inline(always)]
    fn from(variant: Nakmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nakmsk` reader - "]
pub type NakmskR = crate::BitReader<Nakmsk>;
impl NakmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nakmsk {
        match self.bits {
            false => Nakmsk::Mask,
            true => Nakmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Nakmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Nakmsk::Nomask
    }
}
#[doc = "Field `nakmsk` writer - "]
pub type NakmskW<'a, REG> = crate::BitWriter<'a, REG, Nakmsk>;
impl<'a, REG> NakmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Nakmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Nakmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nyetmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Nyetmsk> for bool {
    #[inline(always)]
    fn from(variant: Nyetmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nyetmsk` reader - "]
pub type NyetmskR = crate::BitReader<Nyetmsk>;
impl NyetmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nyetmsk {
        match self.bits {
            false => Nyetmsk::Mask,
            true => Nyetmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Nyetmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Nyetmsk::Nomask
    }
}
#[doc = "Field `nyetmsk` writer - "]
pub type NyetmskW<'a, REG> = crate::BitWriter<'a, REG, Nyetmsk>;
impl<'a, REG> NyetmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Nyetmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Nyetmsk::Nomask)
    }
}
impl R {
    #[doc = "Bit 0"]
    #[inline(always)]
    pub fn xfercomplmsk(&self) -> XfercomplmskR {
        XfercomplmskR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    pub fn epdisbldmsk(&self) -> EpdisbldmskR {
        EpdisbldmskR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    pub fn ahberrmsk(&self) -> AhberrmskR {
        AhberrmskR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Applies to control endpoints only."]
    #[inline(always)]
    pub fn setupmsk(&self) -> SetupmskR {
        SetupmskR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Applies to control OUT endpoints only."]
    #[inline(always)]
    pub fn outtknepdismsk(&self) -> OuttknepdismskR {
        OuttknepdismskR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Applies to control OUT endpoints only."]
    #[inline(always)]
    pub fn back2backsetup(&self) -> Back2backsetupR {
        Back2backsetupR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    pub fn outpkterrmsk(&self) -> OutpkterrmskR {
        OutpkterrmskR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    pub fn bnaoutintrmsk(&self) -> BnaoutintrmskR {
        BnaoutintrmskR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    pub fn bbleerrmsk(&self) -> BbleerrmskR {
        BbleerrmskR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    pub fn nakmsk(&self) -> NakmskR {
        NakmskR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14"]
    #[inline(always)]
    pub fn nyetmsk(&self) -> NyetmskR {
        NyetmskR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0"]
    #[inline(always)]
    #[must_use]
    pub fn xfercomplmsk(&mut self) -> XfercomplmskW<DevgrpDoepmskSpec> {
        XfercomplmskW::new(self, 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn epdisbldmsk(&mut self) -> EpdisbldmskW<DevgrpDoepmskSpec> {
        EpdisbldmskW::new(self, 1)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    #[must_use]
    pub fn ahberrmsk(&mut self) -> AhberrmskW<DevgrpDoepmskSpec> {
        AhberrmskW::new(self, 2)
    }
    #[doc = "Bit 3 - Applies to control endpoints only."]
    #[inline(always)]
    #[must_use]
    pub fn setupmsk(&mut self) -> SetupmskW<DevgrpDoepmskSpec> {
        SetupmskW::new(self, 3)
    }
    #[doc = "Bit 4 - Applies to control OUT endpoints only."]
    #[inline(always)]
    #[must_use]
    pub fn outtknepdismsk(&mut self) -> OuttknepdismskW<DevgrpDoepmskSpec> {
        OuttknepdismskW::new(self, 4)
    }
    #[doc = "Bit 6 - Applies to control OUT endpoints only."]
    #[inline(always)]
    #[must_use]
    pub fn back2backsetup(&mut self) -> Back2backsetupW<DevgrpDoepmskSpec> {
        Back2backsetupW::new(self, 6)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    #[must_use]
    pub fn outpkterrmsk(&mut self) -> OutpkterrmskW<DevgrpDoepmskSpec> {
        OutpkterrmskW::new(self, 8)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    #[must_use]
    pub fn bnaoutintrmsk(&mut self) -> BnaoutintrmskW<DevgrpDoepmskSpec> {
        BnaoutintrmskW::new(self, 9)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    #[must_use]
    pub fn bbleerrmsk(&mut self) -> BbleerrmskW<DevgrpDoepmskSpec> {
        BbleerrmskW::new(self, 12)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    #[must_use]
    pub fn nakmsk(&mut self) -> NakmskW<DevgrpDoepmskSpec> {
        NakmskW::new(self, 13)
    }
    #[doc = "Bit 14"]
    #[inline(always)]
    #[must_use]
    pub fn nyetmsk(&mut self) -> NyetmskW<DevgrpDoepmskSpec> {
        NyetmskW::new(self, 14)
    }
}
#[doc = "This register works with each of the Device OUT Endpoint Interrupt (DOEPINTn) registers for all endpoints to generate an interrupt per OUT endpoint. The OUT endpoint interrupt for a specific status in the DOEPINTn register can be masked by writing into the corresponding bit in this register. Status bits are masked by default\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepmskSpec;
impl crate::RegisterSpec for DevgrpDoepmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 2068u64;
}
#[doc = "`read()` method returns [`devgrp_doepmsk::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepmskSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_doepmsk::W`](W) writer structure"]
impl crate::Writable for DevgrpDoepmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_doepmsk to value 0"]
impl crate::Resettable for DevgrpDoepmskSpec {
    const RESET_VALUE: u32 = 0;
}
