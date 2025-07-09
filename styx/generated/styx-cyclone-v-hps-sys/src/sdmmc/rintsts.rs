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
#[doc = "Register `rintsts` reader"]
pub type R = crate::R<RintstsSpec>;
#[doc = "Register `rintsts` writer"]
pub type W = crate::W<RintstsSpec>;
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Inactive,
            true => Cd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Cd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Cd::Active
    }
}
#[doc = "Field `cd` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type CdW<'a, REG> = crate::BitWriter1C<'a, REG, Cd>;
impl<'a, REG> CdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Re {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Re> for bool {
    #[inline(always)]
    fn from(variant: Re) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `re` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type ReR = crate::BitReader<Re>;
impl ReR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Re {
        match self.bits {
            false => Re::Inactive,
            true => Re::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Re::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Re::Active
    }
}
#[doc = "Field `re` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type ReW<'a, REG> = crate::BitWriter1C<'a, REG, Re>;
impl<'a, REG> ReW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Re::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Re::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Cmd> for bool {
    #[inline(always)]
    fn from(variant: Cmd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cmd` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type CmdR = crate::BitReader<Cmd>;
impl CmdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cmd {
        match self.bits {
            false => Cmd::Inactive,
            true => Cmd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Cmd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Cmd::Active
    }
}
#[doc = "Field `cmd` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type CmdW<'a, REG> = crate::BitWriter1C<'a, REG, Cmd>;
impl<'a, REG> CmdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Cmd::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Cmd::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dto {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Dto> for bool {
    #[inline(always)]
    fn from(variant: Dto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dto` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type DtoR = crate::BitReader<Dto>;
impl DtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dto {
        match self.bits {
            false => Dto::Inactive,
            true => Dto::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Dto::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Dto::Active
    }
}
#[doc = "Field `dto` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type DtoW<'a, REG> = crate::BitWriter1C<'a, REG, Dto>;
impl<'a, REG> DtoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Dto::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Dto::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txdr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txdr> for bool {
    #[inline(always)]
    fn from(variant: Txdr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txdr` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type TxdrR = crate::BitReader<Txdr>;
impl TxdrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txdr {
        match self.bits {
            false => Txdr::Inactive,
            true => Txdr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txdr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txdr::Active
    }
}
#[doc = "Field `txdr` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type TxdrW<'a, REG> = crate::BitWriter1C<'a, REG, Txdr>;
impl<'a, REG> TxdrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Txdr::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Txdr::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxdr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxdr> for bool {
    #[inline(always)]
    fn from(variant: Rxdr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxdr` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type RxdrR = crate::BitReader<Rxdr>;
impl RxdrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxdr {
        match self.bits {
            false => Rxdr::Inactive,
            true => Rxdr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxdr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxdr::Active
    }
}
#[doc = "Field `rxdr` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type RxdrW<'a, REG> = crate::BitWriter1C<'a, REG, Rxdr>;
impl<'a, REG> RxdrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Rxdr::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Rxdr::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcrc {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rcrc> for bool {
    #[inline(always)]
    fn from(variant: Rcrc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rcrc` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type RcrcR = crate::BitReader<Rcrc>;
impl RcrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rcrc {
        match self.bits {
            false => Rcrc::Inactive,
            true => Rcrc::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rcrc::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rcrc::Active
    }
}
#[doc = "Field `rcrc` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type RcrcW<'a, REG> = crate::BitWriter1C<'a, REG, Rcrc>;
impl<'a, REG> RcrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Rcrc::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Rcrc::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dcrc {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Dcrc> for bool {
    #[inline(always)]
    fn from(variant: Dcrc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dcrc` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type DcrcR = crate::BitReader<Dcrc>;
impl DcrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dcrc {
        match self.bits {
            false => Dcrc::Inactive,
            true => Dcrc::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Dcrc::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Dcrc::Active
    }
}
#[doc = "Field `dcrc` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type DcrcW<'a, REG> = crate::BitWriter1C<'a, REG, Dcrc>;
impl<'a, REG> DcrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Dcrc::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Dcrc::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Bar> for bool {
    #[inline(always)]
    fn from(variant: Bar) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bar` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type BarR = crate::BitReader<Bar>;
impl BarR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bar {
        match self.bits {
            false => Bar::Inactive,
            true => Bar::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Bar::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Bar::Active
    }
}
#[doc = "Field `bar` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type BarW<'a, REG> = crate::BitWriter1C<'a, REG, Bar>;
impl<'a, REG> BarW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Bar::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Bar::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bds {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Bds> for bool {
    #[inline(always)]
    fn from(variant: Bds) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bds` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type BdsR = crate::BitReader<Bds>;
impl BdsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bds {
        match self.bits {
            false => Bds::Inactive,
            true => Bds::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Bds::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Bds::Active
    }
}
#[doc = "Field `bds` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type BdsW<'a, REG> = crate::BitWriter1C<'a, REG, Bds>;
impl<'a, REG> BdsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Bds::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Bds::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hto {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Hto> for bool {
    #[inline(always)]
    fn from(variant: Hto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hto` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type HtoR = crate::BitReader<Hto>;
impl HtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hto {
        match self.bits {
            false => Hto::Inactive,
            true => Hto::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Hto::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Hto::Active
    }
}
#[doc = "Field `hto` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type HtoW<'a, REG> = crate::BitWriter1C<'a, REG, Hto>;
impl<'a, REG> HtoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Hto::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Hto::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frun {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Frun> for bool {
    #[inline(always)]
    fn from(variant: Frun) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `frun` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type FrunR = crate::BitReader<Frun>;
impl FrunR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Frun {
        match self.bits {
            false => Frun::Inactive,
            true => Frun::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Frun::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Frun::Active
    }
}
#[doc = "Field `frun` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type FrunW<'a, REG> = crate::BitWriter1C<'a, REG, Frun>;
impl<'a, REG> FrunW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Frun::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Frun::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hle {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Hle> for bool {
    #[inline(always)]
    fn from(variant: Hle) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hle` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type HleR = crate::BitReader<Hle>;
impl HleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hle {
        match self.bits {
            false => Hle::Inactive,
            true => Hle::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Hle::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Hle::Active
    }
}
#[doc = "Field `hle` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type HleW<'a, REG> = crate::BitWriter1C<'a, REG, Hle>;
impl<'a, REG> HleW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Hle::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Hle::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sbe {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Sbe> for bool {
    #[inline(always)]
    fn from(variant: Sbe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sbe` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type SbeR = crate::BitReader<Sbe>;
impl SbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sbe {
        match self.bits {
            false => Sbe::Inactive,
            true => Sbe::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Sbe::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Sbe::Active
    }
}
#[doc = "Field `sbe` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type SbeW<'a, REG> = crate::BitWriter1C<'a, REG, Sbe>;
impl<'a, REG> SbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Sbe::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Sbe::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Acd> for bool {
    #[inline(always)]
    fn from(variant: Acd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `acd` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type AcdR = crate::BitReader<Acd>;
impl AcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Acd {
        match self.bits {
            false => Acd::Inactive,
            true => Acd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Acd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Acd::Active
    }
}
#[doc = "Field `acd` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type AcdW<'a, REG> = crate::BitWriter1C<'a, REG, Acd>;
impl<'a, REG> AcdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Acd::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Acd::Active)
    }
}
#[doc = "Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ebe {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ebe> for bool {
    #[inline(always)]
    fn from(variant: Ebe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ebe` reader - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type EbeR = crate::BitReader<Ebe>;
impl EbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ebe {
        match self.bits {
            false => Ebe::Inactive,
            true => Ebe::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ebe::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ebe::Active
    }
}
#[doc = "Field `ebe` writer - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
pub type EbeW<'a, REG> = crate::BitWriter1C<'a, REG, Ebe>;
impl<'a, REG> EbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Ebe::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Ebe::Active)
    }
}
#[doc = "Interrupt from SDIO card.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdioInterrupt {
    #[doc = "1: `1`"]
    Active = 1,
    #[doc = "0: `0`"]
    Inactive = 0,
}
impl From<SdioInterrupt> for bool {
    #[inline(always)]
    fn from(variant: SdioInterrupt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sdio_interrupt` reader - Interrupt from SDIO card."]
pub type SdioInterruptR = crate::BitReader<SdioInterrupt>;
impl SdioInterruptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SdioInterrupt {
        match self.bits {
            true => SdioInterrupt::Active,
            false => SdioInterrupt::Inactive,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == SdioInterrupt::Active
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == SdioInterrupt::Inactive
    }
}
#[doc = "Field `sdio_interrupt` writer - Interrupt from SDIO card."]
pub type SdioInterruptW<'a, REG> = crate::BitWriter1C<'a, REG, SdioInterrupt>;
impl<'a, REG> SdioInterruptW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(SdioInterrupt::Active)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(SdioInterrupt::Inactive)
    }
}
impl R {
    #[doc = "Bit 0 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn re(&self) -> ReR {
        ReR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn cmd(&self) -> CmdR {
        CmdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn dto(&self) -> DtoR {
        DtoR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn txdr(&self) -> TxdrR {
        TxdrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn rxdr(&self) -> RxdrR {
        RxdrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn rcrc(&self) -> RcrcR {
        RcrcR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn dcrc(&self) -> DcrcR {
        DcrcR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn bar(&self) -> BarR {
        BarR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn bds(&self) -> BdsR {
        BdsR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn hto(&self) -> HtoR {
        HtoR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn frun(&self) -> FrunR {
        FrunR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn hle(&self) -> HleR {
        HleR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn sbe(&self) -> SbeR {
        SbeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn acd(&self) -> AcdR {
        AcdR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    pub fn ebe(&self) -> EbeR {
        EbeR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Interrupt from SDIO card."]
    #[inline(always)]
    pub fn sdio_interrupt(&self) -> SdioInterruptR {
        SdioInterruptR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<RintstsSpec> {
        CdW::new(self, 0)
    }
    #[doc = "Bit 1 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn re(&mut self) -> ReW<RintstsSpec> {
        ReW::new(self, 1)
    }
    #[doc = "Bit 2 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn cmd(&mut self) -> CmdW<RintstsSpec> {
        CmdW::new(self, 2)
    }
    #[doc = "Bit 3 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn dto(&mut self) -> DtoW<RintstsSpec> {
        DtoW::new(self, 3)
    }
    #[doc = "Bit 4 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn txdr(&mut self) -> TxdrW<RintstsSpec> {
        TxdrW::new(self, 4)
    }
    #[doc = "Bit 5 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn rxdr(&mut self) -> RxdrW<RintstsSpec> {
        RxdrW::new(self, 5)
    }
    #[doc = "Bit 6 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn rcrc(&mut self) -> RcrcW<RintstsSpec> {
        RcrcW::new(self, 6)
    }
    #[doc = "Bit 7 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn dcrc(&mut self) -> DcrcW<RintstsSpec> {
        DcrcW::new(self, 7)
    }
    #[doc = "Bit 8 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn bar(&mut self) -> BarW<RintstsSpec> {
        BarW::new(self, 8)
    }
    #[doc = "Bit 9 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn bds(&mut self) -> BdsW<RintstsSpec> {
        BdsW::new(self, 9)
    }
    #[doc = "Bit 10 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn hto(&mut self) -> HtoW<RintstsSpec> {
        HtoW::new(self, 10)
    }
    #[doc = "Bit 11 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn frun(&mut self) -> FrunW<RintstsSpec> {
        FrunW::new(self, 11)
    }
    #[doc = "Bit 12 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn hle(&mut self) -> HleW<RintstsSpec> {
        HleW::new(self, 12)
    }
    #[doc = "Bit 13 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn sbe(&mut self) -> SbeW<RintstsSpec> {
        SbeW::new(self, 13)
    }
    #[doc = "Bit 14 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn acd(&mut self) -> AcdW<RintstsSpec> {
        AcdW::new(self, 14)
    }
    #[doc = "Bit 15 - Writes to bits clear status bit. Value of 1 clears status bit, and value of 0 leaves bit intact. Bits are logged regardless of interrupt mask status."]
    #[inline(always)]
    #[must_use]
    pub fn ebe(&mut self) -> EbeW<RintstsSpec> {
        EbeW::new(self, 15)
    }
    #[doc = "Bit 16 - Interrupt from SDIO card."]
    #[inline(always)]
    #[must_use]
    pub fn sdio_interrupt(&mut self) -> SdioInterruptW<RintstsSpec> {
        SdioInterruptW::new(self, 16)
    }
}
#[doc = "Interrupt Status Before Masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rintsts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rintsts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RintstsSpec;
impl crate::RegisterSpec for RintstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`rintsts::R`](R) reader structure"]
impl crate::Readable for RintstsSpec {}
#[doc = "`write(|w| ..)` method takes [`rintsts::W`](W) writer structure"]
impl crate::Writable for RintstsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x0001_ffff;
}
#[doc = "`reset()` method sets rintsts to value 0"]
impl crate::Resettable for RintstsSpec {
    const RESET_VALUE: u32 = 0;
}
