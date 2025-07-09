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
#[doc = "Register `intmask` reader"]
pub type R = crate::R<IntmaskSpec>;
#[doc = "Register `intmask` writer"]
pub type W = crate::W<IntmaskSpec>;
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Mask,
            true => Cd::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Cd::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Cd::Nomask
    }
}
#[doc = "Field `cd` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG, Cd>;
impl<'a, REG> CdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Re {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Re> for bool {
    #[inline(always)]
    fn from(variant: Re) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `re` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type ReR = crate::BitReader<Re>;
impl ReR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Re {
        match self.bits {
            false => Re::Mask,
            true => Re::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Re::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Re::Nomask
    }
}
#[doc = "Field `re` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type ReW<'a, REG> = crate::BitWriter<'a, REG, Re>;
impl<'a, REG> ReW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Re::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Re::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Cmd> for bool {
    #[inline(always)]
    fn from(variant: Cmd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cmd` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type CmdR = crate::BitReader<Cmd>;
impl CmdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cmd {
        match self.bits {
            false => Cmd::Mask,
            true => Cmd::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Cmd::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Cmd::Nomask
    }
}
#[doc = "Field `cmd` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type CmdW<'a, REG> = crate::BitWriter<'a, REG, Cmd>;
impl<'a, REG> CmdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Cmd::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Cmd::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dto {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Dto> for bool {
    #[inline(always)]
    fn from(variant: Dto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dto` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type DtoR = crate::BitReader<Dto>;
impl DtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dto {
        match self.bits {
            false => Dto::Mask,
            true => Dto::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Dto::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Dto::Nomask
    }
}
#[doc = "Field `dto` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type DtoW<'a, REG> = crate::BitWriter<'a, REG, Dto>;
impl<'a, REG> DtoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Dto::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Dto::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txdr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Txdr> for bool {
    #[inline(always)]
    fn from(variant: Txdr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txdr` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type TxdrR = crate::BitReader<Txdr>;
impl TxdrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txdr {
        match self.bits {
            false => Txdr::Mask,
            true => Txdr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Txdr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Txdr::Nomask
    }
}
#[doc = "Field `txdr` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type TxdrW<'a, REG> = crate::BitWriter<'a, REG, Txdr>;
impl<'a, REG> TxdrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Txdr::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Txdr::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxdr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Rxdr> for bool {
    #[inline(always)]
    fn from(variant: Rxdr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxdr` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type RxdrR = crate::BitReader<Rxdr>;
impl RxdrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxdr {
        match self.bits {
            false => Rxdr::Mask,
            true => Rxdr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Rxdr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Rxdr::Nomask
    }
}
#[doc = "Field `rxdr` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type RxdrW<'a, REG> = crate::BitWriter<'a, REG, Rxdr>;
impl<'a, REG> RxdrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Rxdr::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Rxdr::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcrc {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Rcrc> for bool {
    #[inline(always)]
    fn from(variant: Rcrc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rcrc` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type RcrcR = crate::BitReader<Rcrc>;
impl RcrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rcrc {
        match self.bits {
            false => Rcrc::Mask,
            true => Rcrc::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Rcrc::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Rcrc::Nomask
    }
}
#[doc = "Field `rcrc` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type RcrcW<'a, REG> = crate::BitWriter<'a, REG, Rcrc>;
impl<'a, REG> RcrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Rcrc::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Rcrc::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dcrc {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Dcrc> for bool {
    #[inline(always)]
    fn from(variant: Dcrc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dcrc` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type DcrcR = crate::BitReader<Dcrc>;
impl DcrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dcrc {
        match self.bits {
            false => Dcrc::Mask,
            true => Dcrc::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Dcrc::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Dcrc::Nomask
    }
}
#[doc = "Field `dcrc` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type DcrcW<'a, REG> = crate::BitWriter<'a, REG, Dcrc>;
impl<'a, REG> DcrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Dcrc::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Dcrc::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rto {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Rto> for bool {
    #[inline(always)]
    fn from(variant: Rto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rto` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type RtoR = crate::BitReader<Rto>;
impl RtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rto {
        match self.bits {
            false => Rto::Mask,
            true => Rto::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Rto::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Rto::Nomask
    }
}
#[doc = "Field `rto` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type RtoW<'a, REG> = crate::BitWriter<'a, REG, Rto>;
impl<'a, REG> RtoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Rto::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Rto::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drt {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Drt> for bool {
    #[inline(always)]
    fn from(variant: Drt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `drt` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type DrtR = crate::BitReader<Drt>;
impl DrtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Drt {
        match self.bits {
            false => Drt::Mask,
            true => Drt::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Drt::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Drt::Nomask
    }
}
#[doc = "Field `drt` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type DrtW<'a, REG> = crate::BitWriter<'a, REG, Drt>;
impl<'a, REG> DrtW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Drt::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Drt::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hto {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Hto> for bool {
    #[inline(always)]
    fn from(variant: Hto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hto` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type HtoR = crate::BitReader<Hto>;
impl HtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hto {
        match self.bits {
            false => Hto::Mask,
            true => Hto::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Hto::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Hto::Nomask
    }
}
#[doc = "Field `hto` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type HtoW<'a, REG> = crate::BitWriter<'a, REG, Hto>;
impl<'a, REG> HtoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Hto::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Hto::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frun {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Frun> for bool {
    #[inline(always)]
    fn from(variant: Frun) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `frun` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type FrunR = crate::BitReader<Frun>;
impl FrunR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Frun {
        match self.bits {
            false => Frun::Mask,
            true => Frun::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Frun::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Frun::Nomask
    }
}
#[doc = "Field `frun` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type FrunW<'a, REG> = crate::BitWriter<'a, REG, Frun>;
impl<'a, REG> FrunW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Frun::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Frun::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hle {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Hle> for bool {
    #[inline(always)]
    fn from(variant: Hle) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hle` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type HleR = crate::BitReader<Hle>;
impl HleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hle {
        match self.bits {
            false => Hle::Mask,
            true => Hle::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Hle::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Hle::Nomask
    }
}
#[doc = "Field `hle` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type HleW<'a, REG> = crate::BitWriter<'a, REG, Hle>;
impl<'a, REG> HleW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Hle::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Hle::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sbe {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Sbe> for bool {
    #[inline(always)]
    fn from(variant: Sbe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sbe` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type SbeR = crate::BitReader<Sbe>;
impl SbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sbe {
        match self.bits {
            false => Sbe::Mask,
            true => Sbe::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Sbe::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Sbe::Nomask
    }
}
#[doc = "Field `sbe` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type SbeW<'a, REG> = crate::BitWriter<'a, REG, Sbe>;
impl<'a, REG> SbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Sbe::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Sbe::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acd {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Acd> for bool {
    #[inline(always)]
    fn from(variant: Acd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `acd` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type AcdR = crate::BitReader<Acd>;
impl AcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Acd {
        match self.bits {
            false => Acd::Mask,
            true => Acd::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Acd::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Acd::Nomask
    }
}
#[doc = "Field `acd` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type AcdW<'a, REG> = crate::BitWriter<'a, REG, Acd>;
impl<'a, REG> AcdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Acd::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Acd::Nomask)
    }
}
#[doc = "Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ebe {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ebe> for bool {
    #[inline(always)]
    fn from(variant: Ebe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ebe` reader - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type EbeR = crate::BitReader<Ebe>;
impl EbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ebe {
        match self.bits {
            false => Ebe::Mask,
            true => Ebe::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ebe::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ebe::Nomask
    }
}
#[doc = "Field `ebe` writer - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
pub type EbeW<'a, REG> = crate::BitWriter<'a, REG, Ebe>;
impl<'a, REG> EbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ebe::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ebe::Nomask)
    }
}
#[doc = "In current application, MMC-Ver3.3 only Bit 16 of this field is used. Bits 17 to 31 are unused and return 0\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdioIntMask {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<SdioIntMask> for bool {
    #[inline(always)]
    fn from(variant: SdioIntMask) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sdio_int_mask` reader - In current application, MMC-Ver3.3 only Bit 16 of this field is used. Bits 17 to 31 are unused and return 0"]
pub type SdioIntMaskR = crate::BitReader<SdioIntMask>;
impl SdioIntMaskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SdioIntMask {
        match self.bits {
            false => SdioIntMask::Disabled,
            true => SdioIntMask::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == SdioIntMask::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == SdioIntMask::Enabled
    }
}
#[doc = "Field `sdio_int_mask` writer - In current application, MMC-Ver3.3 only Bit 16 of this field is used. Bits 17 to 31 are unused and return 0"]
pub type SdioIntMaskW<'a, REG> = crate::BitWriter<'a, REG, SdioIntMask>;
impl<'a, REG> SdioIntMaskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(SdioIntMask::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(SdioIntMask::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn re(&self) -> ReR {
        ReR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn cmd(&self) -> CmdR {
        CmdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn dto(&self) -> DtoR {
        DtoR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn txdr(&self) -> TxdrR {
        TxdrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn rxdr(&self) -> RxdrR {
        RxdrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn rcrc(&self) -> RcrcR {
        RcrcR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn dcrc(&self) -> DcrcR {
        DcrcR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn rto(&self) -> RtoR {
        RtoR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn drt(&self) -> DrtR {
        DrtR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn hto(&self) -> HtoR {
        HtoR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn frun(&self) -> FrunR {
        FrunR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn hle(&self) -> HleR {
        HleR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn sbe(&self) -> SbeR {
        SbeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn acd(&self) -> AcdR {
        AcdR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    pub fn ebe(&self) -> EbeR {
        EbeR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - In current application, MMC-Ver3.3 only Bit 16 of this field is used. Bits 17 to 31 are unused and return 0"]
    #[inline(always)]
    pub fn sdio_int_mask(&self) -> SdioIntMaskR {
        SdioIntMaskR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<IntmaskSpec> {
        CdW::new(self, 0)
    }
    #[doc = "Bit 1 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn re(&mut self) -> ReW<IntmaskSpec> {
        ReW::new(self, 1)
    }
    #[doc = "Bit 2 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cmd(&mut self) -> CmdW<IntmaskSpec> {
        CmdW::new(self, 2)
    }
    #[doc = "Bit 3 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn dto(&mut self) -> DtoW<IntmaskSpec> {
        DtoW::new(self, 3)
    }
    #[doc = "Bit 4 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn txdr(&mut self) -> TxdrW<IntmaskSpec> {
        TxdrW::new(self, 4)
    }
    #[doc = "Bit 5 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn rxdr(&mut self) -> RxdrW<IntmaskSpec> {
        RxdrW::new(self, 5)
    }
    #[doc = "Bit 6 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn rcrc(&mut self) -> RcrcW<IntmaskSpec> {
        RcrcW::new(self, 6)
    }
    #[doc = "Bit 7 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn dcrc(&mut self) -> DcrcW<IntmaskSpec> {
        DcrcW::new(self, 7)
    }
    #[doc = "Bit 8 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn rto(&mut self) -> RtoW<IntmaskSpec> {
        RtoW::new(self, 8)
    }
    #[doc = "Bit 9 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn drt(&mut self) -> DrtW<IntmaskSpec> {
        DrtW::new(self, 9)
    }
    #[doc = "Bit 10 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn hto(&mut self) -> HtoW<IntmaskSpec> {
        HtoW::new(self, 10)
    }
    #[doc = "Bit 11 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn frun(&mut self) -> FrunW<IntmaskSpec> {
        FrunW::new(self, 11)
    }
    #[doc = "Bit 12 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn hle(&mut self) -> HleW<IntmaskSpec> {
        HleW::new(self, 12)
    }
    #[doc = "Bit 13 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn sbe(&mut self) -> SbeW<IntmaskSpec> {
        SbeW::new(self, 13)
    }
    #[doc = "Bit 14 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn acd(&mut self) -> AcdW<IntmaskSpec> {
        AcdW::new(self, 14)
    }
    #[doc = "Bit 15 - Bits used to mask unwanted interrupts. Value of 0 masks interrupts, value of 1 enables interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ebe(&mut self) -> EbeW<IntmaskSpec> {
        EbeW::new(self, 15)
    }
    #[doc = "Bit 16 - In current application, MMC-Ver3.3 only Bit 16 of this field is used. Bits 17 to 31 are unused and return 0"]
    #[inline(always)]
    #[must_use]
    pub fn sdio_int_mask(&mut self) -> SdioIntMaskW<IntmaskSpec> {
        SdioIntMaskW::new(self, 16)
    }
}
#[doc = "Allows Masking of Various Interrupts\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`intmask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`intmask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IntmaskSpec;
impl crate::RegisterSpec for IntmaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`intmask::R`](R) reader structure"]
impl crate::Readable for IntmaskSpec {}
#[doc = "`write(|w| ..)` method takes [`intmask::W`](W) writer structure"]
impl crate::Writable for IntmaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets intmask to value 0"]
impl crate::Resettable for IntmaskSpec {
    const RESET_VALUE: u32 = 0;
}
