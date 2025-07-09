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
#[doc = "Register `devgrp_diepmsk` reader"]
pub type R = crate::R<DevgrpDiepmskSpec>;
#[doc = "Register `devgrp_diepmsk` writer"]
pub type W = crate::W<DevgrpDiepmskSpec>;
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
#[doc = "Non-isochronous endpoints\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timeoutmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Timeoutmsk> for bool {
    #[inline(always)]
    fn from(variant: Timeoutmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timeoutmsk` reader - Non-isochronous endpoints"]
pub type TimeoutmskR = crate::BitReader<Timeoutmsk>;
impl TimeoutmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timeoutmsk {
        match self.bits {
            false => Timeoutmsk::Mask,
            true => Timeoutmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Timeoutmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Timeoutmsk::Nomask
    }
}
#[doc = "Field `timeoutmsk` writer - Non-isochronous endpoints"]
pub type TimeoutmskW<'a, REG> = crate::BitWriter<'a, REG, Timeoutmsk>;
impl<'a, REG> TimeoutmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Timeoutmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Timeoutmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intkntxfempmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Intkntxfempmsk> for bool {
    #[inline(always)]
    fn from(variant: Intkntxfempmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `intkntxfempmsk` reader - "]
pub type IntkntxfempmskR = crate::BitReader<Intkntxfempmsk>;
impl IntkntxfempmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Intkntxfempmsk {
        match self.bits {
            false => Intkntxfempmsk::Mask,
            true => Intkntxfempmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Intkntxfempmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Intkntxfempmsk::Nomask
    }
}
#[doc = "Field `intkntxfempmsk` writer - "]
pub type IntkntxfempmskW<'a, REG> = crate::BitWriter<'a, REG, Intkntxfempmsk>;
impl<'a, REG> IntkntxfempmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Intkntxfempmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Intkntxfempmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intknepmismsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Intknepmismsk> for bool {
    #[inline(always)]
    fn from(variant: Intknepmismsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `intknepmismsk` reader - "]
pub type IntknepmismskR = crate::BitReader<Intknepmismsk>;
impl IntknepmismskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Intknepmismsk {
        match self.bits {
            false => Intknepmismsk::Mask,
            true => Intknepmismsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Intknepmismsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Intknepmismsk::Nomask
    }
}
#[doc = "Field `intknepmismsk` writer - "]
pub type IntknepmismskW<'a, REG> = crate::BitWriter<'a, REG, Intknepmismsk>;
impl<'a, REG> IntknepmismskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Intknepmismsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Intknepmismsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepnakeffmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Inepnakeffmsk> for bool {
    #[inline(always)]
    fn from(variant: Inepnakeffmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepnakeffmsk` reader - "]
pub type InepnakeffmskR = crate::BitReader<Inepnakeffmsk>;
impl InepnakeffmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepnakeffmsk {
        match self.bits {
            false => Inepnakeffmsk::Mask,
            true => Inepnakeffmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepnakeffmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepnakeffmsk::Nomask
    }
}
#[doc = "Field `inepnakeffmsk` writer - "]
pub type InepnakeffmskW<'a, REG> = crate::BitWriter<'a, REG, Inepnakeffmsk>;
impl<'a, REG> InepnakeffmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepnakeffmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepnakeffmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfifoundrnmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Txfifoundrnmsk> for bool {
    #[inline(always)]
    fn from(variant: Txfifoundrnmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfifoundrnmsk` reader - "]
pub type TxfifoundrnmskR = crate::BitReader<Txfifoundrnmsk>;
impl TxfifoundrnmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfifoundrnmsk {
        match self.bits {
            false => Txfifoundrnmsk::Mask,
            true => Txfifoundrnmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Txfifoundrnmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Txfifoundrnmsk::Nomask
    }
}
#[doc = "Field `txfifoundrnmsk` writer - "]
pub type TxfifoundrnmskW<'a, REG> = crate::BitWriter<'a, REG, Txfifoundrnmsk>;
impl<'a, REG> TxfifoundrnmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Txfifoundrnmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Txfifoundrnmsk::Nomask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bnainintrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Bnainintrmsk> for bool {
    #[inline(always)]
    fn from(variant: Bnainintrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bnainintrmsk` reader - "]
pub type BnainintrmskR = crate::BitReader<Bnainintrmsk>;
impl BnainintrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bnainintrmsk {
        match self.bits {
            false => Bnainintrmsk::Mask,
            true => Bnainintrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Bnainintrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Bnainintrmsk::Nomask
    }
}
#[doc = "Field `bnainintrmsk` writer - "]
pub type BnainintrmskW<'a, REG> = crate::BitWriter<'a, REG, Bnainintrmsk>;
impl<'a, REG> BnainintrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Bnainintrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Bnainintrmsk::Nomask)
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
    #[doc = "Bit 3 - Non-isochronous endpoints"]
    #[inline(always)]
    pub fn timeoutmsk(&self) -> TimeoutmskR {
        TimeoutmskR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    pub fn intkntxfempmsk(&self) -> IntkntxfempmskR {
        IntkntxfempmskR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    pub fn intknepmismsk(&self) -> IntknepmismskR {
        IntknepmismskR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    pub fn inepnakeffmsk(&self) -> InepnakeffmskR {
        InepnakeffmskR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    pub fn txfifoundrnmsk(&self) -> TxfifoundrnmskR {
        TxfifoundrnmskR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    pub fn bnainintrmsk(&self) -> BnainintrmskR {
        BnainintrmskR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    pub fn nakmsk(&self) -> NakmskR {
        NakmskR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0"]
    #[inline(always)]
    #[must_use]
    pub fn xfercomplmsk(&mut self) -> XfercomplmskW<DevgrpDiepmskSpec> {
        XfercomplmskW::new(self, 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn epdisbldmsk(&mut self) -> EpdisbldmskW<DevgrpDiepmskSpec> {
        EpdisbldmskW::new(self, 1)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    #[must_use]
    pub fn ahberrmsk(&mut self) -> AhberrmskW<DevgrpDiepmskSpec> {
        AhberrmskW::new(self, 2)
    }
    #[doc = "Bit 3 - Non-isochronous endpoints"]
    #[inline(always)]
    #[must_use]
    pub fn timeoutmsk(&mut self) -> TimeoutmskW<DevgrpDiepmskSpec> {
        TimeoutmskW::new(self, 3)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    #[must_use]
    pub fn intkntxfempmsk(&mut self) -> IntkntxfempmskW<DevgrpDiepmskSpec> {
        IntkntxfempmskW::new(self, 4)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    #[must_use]
    pub fn intknepmismsk(&mut self) -> IntknepmismskW<DevgrpDiepmskSpec> {
        IntknepmismskW::new(self, 5)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    #[must_use]
    pub fn inepnakeffmsk(&mut self) -> InepnakeffmskW<DevgrpDiepmskSpec> {
        InepnakeffmskW::new(self, 6)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    #[must_use]
    pub fn txfifoundrnmsk(&mut self) -> TxfifoundrnmskW<DevgrpDiepmskSpec> {
        TxfifoundrnmskW::new(self, 8)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    #[must_use]
    pub fn bnainintrmsk(&mut self) -> BnainintrmskW<DevgrpDiepmskSpec> {
        BnainintrmskW::new(self, 9)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    #[must_use]
    pub fn nakmsk(&mut self) -> NakmskW<DevgrpDiepmskSpec> {
        NakmskW::new(self, 13)
    }
}
#[doc = "This register works with each of the Device IN Endpoint Interrupt (DIEPINTn) registers for all endpoints to generate an interrupt per IN endpoint. The IN endpoint interrupt for a specific status in the DIEPINTn register can be masked by writing to the corresponding bit in this register. Status bits are masked by default.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepmskSpec;
impl crate::RegisterSpec for DevgrpDiepmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 2064u64;
}
#[doc = "`read()` method returns [`devgrp_diepmsk::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepmskSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_diepmsk::W`](W) writer structure"]
impl crate::Writable for DevgrpDiepmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_diepmsk to value 0"]
impl crate::Resettable for DevgrpDiepmskSpec {
    const RESET_VALUE: u32 = 0;
}
