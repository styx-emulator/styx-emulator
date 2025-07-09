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
#[doc = "Register `devgrp_daintmsk` reader"]
pub type R = crate::R<DevgrpDaintmskSpec>;
#[doc = "Register `devgrp_daintmsk` writer"]
pub type W = crate::W<DevgrpDaintmskSpec>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk0 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk0> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk0` reader - "]
pub type Inepmsk0R = crate::BitReader<Inepmsk0>;
impl Inepmsk0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk0 {
        match self.bits {
            true => Inepmsk0::Nomask,
            false => Inepmsk0::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk0::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk0::Mask
    }
}
#[doc = "Field `inepmsk0` writer - "]
pub type Inepmsk0W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk0>;
impl<'a, REG> Inepmsk0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk0::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk0::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk1 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk1> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk1` reader - "]
pub type Inepmsk1R = crate::BitReader<Inepmsk1>;
impl Inepmsk1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk1 {
        match self.bits {
            true => Inepmsk1::Nomask,
            false => Inepmsk1::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk1::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk1::Mask
    }
}
#[doc = "Field `inepmsk1` writer - "]
pub type Inepmsk1W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk1>;
impl<'a, REG> Inepmsk1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk1::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk1::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk2 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk2> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk2` reader - "]
pub type Inepmsk2R = crate::BitReader<Inepmsk2>;
impl Inepmsk2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk2 {
        match self.bits {
            true => Inepmsk2::Nomask,
            false => Inepmsk2::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk2::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk2::Mask
    }
}
#[doc = "Field `inepmsk2` writer - "]
pub type Inepmsk2W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk2>;
impl<'a, REG> Inepmsk2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk2::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk2::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk3 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk3> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk3` reader - "]
pub type Inepmsk3R = crate::BitReader<Inepmsk3>;
impl Inepmsk3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk3 {
        match self.bits {
            true => Inepmsk3::Nomask,
            false => Inepmsk3::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk3::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk3::Mask
    }
}
#[doc = "Field `inepmsk3` writer - "]
pub type Inepmsk3W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk3>;
impl<'a, REG> Inepmsk3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk3::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk3::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk4 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk4> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk4` reader - "]
pub type Inepmsk4R = crate::BitReader<Inepmsk4>;
impl Inepmsk4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk4 {
        match self.bits {
            true => Inepmsk4::Nomask,
            false => Inepmsk4::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk4::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk4::Mask
    }
}
#[doc = "Field `inepmsk4` writer - "]
pub type Inepmsk4W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk4>;
impl<'a, REG> Inepmsk4W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk4::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk4::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk5 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk5> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk5` reader - "]
pub type Inepmsk5R = crate::BitReader<Inepmsk5>;
impl Inepmsk5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk5 {
        match self.bits {
            true => Inepmsk5::Nomask,
            false => Inepmsk5::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk5::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk5::Mask
    }
}
#[doc = "Field `inepmsk5` writer - "]
pub type Inepmsk5W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk5>;
impl<'a, REG> Inepmsk5W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk5::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk5::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk6 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk6> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk6` reader - "]
pub type Inepmsk6R = crate::BitReader<Inepmsk6>;
impl Inepmsk6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk6 {
        match self.bits {
            true => Inepmsk6::Nomask,
            false => Inepmsk6::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk6::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk6::Mask
    }
}
#[doc = "Field `inepmsk6` writer - "]
pub type Inepmsk6W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk6>;
impl<'a, REG> Inepmsk6W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk6::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk6::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk7 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk7> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk7` reader - "]
pub type Inepmsk7R = crate::BitReader<Inepmsk7>;
impl Inepmsk7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk7 {
        match self.bits {
            true => Inepmsk7::Nomask,
            false => Inepmsk7::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk7::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk7::Mask
    }
}
#[doc = "Field `inepmsk7` writer - "]
pub type Inepmsk7W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk7>;
impl<'a, REG> Inepmsk7W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk7::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk7::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk8 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk8> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk8` reader - "]
pub type Inepmsk8R = crate::BitReader<Inepmsk8>;
impl Inepmsk8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk8 {
        match self.bits {
            true => Inepmsk8::Nomask,
            false => Inepmsk8::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk8::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk8::Mask
    }
}
#[doc = "Field `inepmsk8` writer - "]
pub type Inepmsk8W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk8>;
impl<'a, REG> Inepmsk8W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk8::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk8::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk9 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk9> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk9` reader - "]
pub type Inepmsk9R = crate::BitReader<Inepmsk9>;
impl Inepmsk9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk9 {
        match self.bits {
            true => Inepmsk9::Nomask,
            false => Inepmsk9::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk9::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk9::Mask
    }
}
#[doc = "Field `inepmsk9` writer - "]
pub type Inepmsk9W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk9>;
impl<'a, REG> Inepmsk9W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk9::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk9::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk10 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk10> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk10` reader - "]
pub type Inepmsk10R = crate::BitReader<Inepmsk10>;
impl Inepmsk10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk10 {
        match self.bits {
            true => Inepmsk10::Nomask,
            false => Inepmsk10::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk10::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk10::Mask
    }
}
#[doc = "Field `inepmsk10` writer - "]
pub type Inepmsk10W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk10>;
impl<'a, REG> Inepmsk10W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk10::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk10::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk11 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk11> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk11` reader - "]
pub type Inepmsk11R = crate::BitReader<Inepmsk11>;
impl Inepmsk11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk11 {
        match self.bits {
            true => Inepmsk11::Nomask,
            false => Inepmsk11::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk11::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk11::Mask
    }
}
#[doc = "Field `inepmsk11` writer - "]
pub type Inepmsk11W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk11>;
impl<'a, REG> Inepmsk11W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk11::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk11::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk12 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk12> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk12` reader - "]
pub type Inepmsk12R = crate::BitReader<Inepmsk12>;
impl Inepmsk12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk12 {
        match self.bits {
            true => Inepmsk12::Nomask,
            false => Inepmsk12::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk12::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk12::Mask
    }
}
#[doc = "Field `inepmsk12` writer - "]
pub type Inepmsk12W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk12>;
impl<'a, REG> Inepmsk12W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk12::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk12::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InEpMsk13 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<InEpMsk13> for bool {
    #[inline(always)]
    fn from(variant: InEpMsk13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `InEpMsk13` reader - "]
pub type InEpMsk13R = crate::BitReader<InEpMsk13>;
impl InEpMsk13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> InEpMsk13 {
        match self.bits {
            true => InEpMsk13::Nomask,
            false => InEpMsk13::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == InEpMsk13::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == InEpMsk13::Mask
    }
}
#[doc = "Field `InEpMsk13` writer - "]
pub type InEpMsk13W<'a, REG> = crate::BitWriter<'a, REG, InEpMsk13>;
impl<'a, REG> InEpMsk13W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(InEpMsk13::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(InEpMsk13::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepmsk14 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Inepmsk14> for bool {
    #[inline(always)]
    fn from(variant: Inepmsk14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepmsk14` reader - "]
pub type Inepmsk14R = crate::BitReader<Inepmsk14>;
impl Inepmsk14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepmsk14 {
        match self.bits {
            true => Inepmsk14::Nomask,
            false => Inepmsk14::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Inepmsk14::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Inepmsk14::Mask
    }
}
#[doc = "Field `inepmsk14` writer - "]
pub type Inepmsk14W<'a, REG> = crate::BitWriter<'a, REG, Inepmsk14>;
impl<'a, REG> Inepmsk14W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk14::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Inepmsk14::Mask)
    }
}
#[doc = "IN Endpoint 15 Interrupt mask Bit\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InEpMsk15 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<InEpMsk15> for bool {
    #[inline(always)]
    fn from(variant: InEpMsk15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `InEpMsk15` reader - IN Endpoint 15 Interrupt mask Bit"]
pub type InEpMsk15R = crate::BitReader<InEpMsk15>;
impl InEpMsk15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> InEpMsk15 {
        match self.bits {
            false => InEpMsk15::Inactive,
            true => InEpMsk15::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == InEpMsk15::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == InEpMsk15::Active
    }
}
#[doc = "Field `InEpMsk15` writer - IN Endpoint 15 Interrupt mask Bit"]
pub type InEpMsk15W<'a, REG> = crate::BitWriter<'a, REG, InEpMsk15>;
impl<'a, REG> InEpMsk15W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(InEpMsk15::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(InEpMsk15::Active)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk0 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk0> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk0` reader - "]
pub type Outepmsk0R = crate::BitReader<Outepmsk0>;
impl Outepmsk0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk0 {
        match self.bits {
            true => Outepmsk0::Nomask,
            false => Outepmsk0::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk0::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk0::Mask
    }
}
#[doc = "Field `outepmsk0` writer - "]
pub type Outepmsk0W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk0>;
impl<'a, REG> Outepmsk0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk0::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk0::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk1 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk1> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk1` reader - "]
pub type Outepmsk1R = crate::BitReader<Outepmsk1>;
impl Outepmsk1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk1 {
        match self.bits {
            true => Outepmsk1::Nomask,
            false => Outepmsk1::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk1::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk1::Mask
    }
}
#[doc = "Field `outepmsk1` writer - "]
pub type Outepmsk1W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk1>;
impl<'a, REG> Outepmsk1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk1::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk1::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk2 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk2> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk2` reader - "]
pub type Outepmsk2R = crate::BitReader<Outepmsk2>;
impl Outepmsk2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk2 {
        match self.bits {
            true => Outepmsk2::Nomask,
            false => Outepmsk2::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk2::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk2::Mask
    }
}
#[doc = "Field `outepmsk2` writer - "]
pub type Outepmsk2W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk2>;
impl<'a, REG> Outepmsk2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk2::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk2::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutEpmsk3 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<OutEpmsk3> for bool {
    #[inline(always)]
    fn from(variant: OutEpmsk3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `OutEPMsk3` reader - "]
pub type OutEpmsk3R = crate::BitReader<OutEpmsk3>;
impl OutEpmsk3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> OutEpmsk3 {
        match self.bits {
            true => OutEpmsk3::Nomask,
            false => OutEpmsk3::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == OutEpmsk3::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == OutEpmsk3::Mask
    }
}
#[doc = "Field `OutEPMsk3` writer - "]
pub type OutEpmsk3W<'a, REG> = crate::BitWriter<'a, REG, OutEpmsk3>;
impl<'a, REG> OutEpmsk3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(OutEpmsk3::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(OutEpmsk3::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk4 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk4> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk4` reader - "]
pub type Outepmsk4R = crate::BitReader<Outepmsk4>;
impl Outepmsk4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk4 {
        match self.bits {
            true => Outepmsk4::Nomask,
            false => Outepmsk4::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk4::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk4::Mask
    }
}
#[doc = "Field `outepmsk4` writer - "]
pub type Outepmsk4W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk4>;
impl<'a, REG> Outepmsk4W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk4::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk4::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk5 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk5> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk5` reader - "]
pub type Outepmsk5R = crate::BitReader<Outepmsk5>;
impl Outepmsk5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk5 {
        match self.bits {
            true => Outepmsk5::Nomask,
            false => Outepmsk5::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk5::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk5::Mask
    }
}
#[doc = "Field `outepmsk5` writer - "]
pub type Outepmsk5W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk5>;
impl<'a, REG> Outepmsk5W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk5::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk5::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk6 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk6> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk6` reader - "]
pub type Outepmsk6R = crate::BitReader<Outepmsk6>;
impl Outepmsk6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk6 {
        match self.bits {
            true => Outepmsk6::Nomask,
            false => Outepmsk6::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk6::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk6::Mask
    }
}
#[doc = "Field `outepmsk6` writer - "]
pub type Outepmsk6W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk6>;
impl<'a, REG> Outepmsk6W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk6::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk6::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk7 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk7> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk7` reader - "]
pub type Outepmsk7R = crate::BitReader<Outepmsk7>;
impl Outepmsk7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk7 {
        match self.bits {
            true => Outepmsk7::Nomask,
            false => Outepmsk7::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk7::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk7::Mask
    }
}
#[doc = "Field `outepmsk7` writer - "]
pub type Outepmsk7W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk7>;
impl<'a, REG> Outepmsk7W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk7::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk7::Mask)
    }
}
#[doc = "OUT Endpoint 8 Interrupt mask Bit\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk8 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk8> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk8` reader - OUT Endpoint 8 Interrupt mask Bit"]
pub type Outepmsk8R = crate::BitReader<Outepmsk8>;
impl Outepmsk8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk8 {
        match self.bits {
            true => Outepmsk8::Nomask,
            false => Outepmsk8::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk8::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk8::Mask
    }
}
#[doc = "Field `outepmsk8` writer - OUT Endpoint 8 Interrupt mask Bit"]
pub type Outepmsk8W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk8>;
impl<'a, REG> Outepmsk8W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk8::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk8::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk9 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk9> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk9` reader - "]
pub type Outepmsk9R = crate::BitReader<Outepmsk9>;
impl Outepmsk9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk9 {
        match self.bits {
            true => Outepmsk9::Nomask,
            false => Outepmsk9::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk9::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk9::Mask
    }
}
#[doc = "Field `outepmsk9` writer - "]
pub type Outepmsk9W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk9>;
impl<'a, REG> Outepmsk9W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk9::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk9::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk10 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk10> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk10` reader - "]
pub type Outepmsk10R = crate::BitReader<Outepmsk10>;
impl Outepmsk10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk10 {
        match self.bits {
            true => Outepmsk10::Nomask,
            false => Outepmsk10::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk10::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk10::Mask
    }
}
#[doc = "Field `outepmsk10` writer - "]
pub type Outepmsk10W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk10>;
impl<'a, REG> Outepmsk10W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk10::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk10::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk11 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk11> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk11` reader - "]
pub type Outepmsk11R = crate::BitReader<Outepmsk11>;
impl Outepmsk11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk11 {
        match self.bits {
            true => Outepmsk11::Nomask,
            false => Outepmsk11::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk11::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk11::Mask
    }
}
#[doc = "Field `outepmsk11` writer - "]
pub type Outepmsk11W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk11>;
impl<'a, REG> Outepmsk11W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk11::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk11::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk12 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk12> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk12` reader - "]
pub type Outepmsk12R = crate::BitReader<Outepmsk12>;
impl Outepmsk12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk12 {
        match self.bits {
            true => Outepmsk12::Nomask,
            false => Outepmsk12::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk12::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk12::Mask
    }
}
#[doc = "Field `outepmsk12` writer - "]
pub type Outepmsk12W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk12>;
impl<'a, REG> Outepmsk12W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk12::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk12::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk13 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk13> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk13` reader - "]
pub type Outepmsk13R = crate::BitReader<Outepmsk13>;
impl Outepmsk13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk13 {
        match self.bits {
            true => Outepmsk13::Nomask,
            false => Outepmsk13::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk13::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk13::Mask
    }
}
#[doc = "Field `outepmsk13` writer - "]
pub type Outepmsk13W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk13>;
impl<'a, REG> Outepmsk13W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk13::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk13::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutEpmsk14 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<OutEpmsk14> for bool {
    #[inline(always)]
    fn from(variant: OutEpmsk14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `OutEPMsk14` reader - "]
pub type OutEpmsk14R = crate::BitReader<OutEpmsk14>;
impl OutEpmsk14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> OutEpmsk14 {
        match self.bits {
            true => OutEpmsk14::Nomask,
            false => OutEpmsk14::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == OutEpmsk14::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == OutEpmsk14::Mask
    }
}
#[doc = "Field `OutEPMsk14` writer - "]
pub type OutEpmsk14W<'a, REG> = crate::BitWriter<'a, REG, OutEpmsk14>;
impl<'a, REG> OutEpmsk14W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(OutEpmsk14::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(OutEpmsk14::Mask)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepmsk15 {
    #[doc = "1: `1`"]
    Nomask = 1,
    #[doc = "0: `0`"]
    Mask = 0,
}
impl From<Outepmsk15> for bool {
    #[inline(always)]
    fn from(variant: Outepmsk15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepmsk15` reader - "]
pub type Outepmsk15R = crate::BitReader<Outepmsk15>;
impl Outepmsk15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepmsk15 {
        match self.bits {
            true => Outepmsk15::Nomask,
            false => Outepmsk15::Mask,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Outepmsk15::Nomask
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Outepmsk15::Mask
    }
}
#[doc = "Field `outepmsk15` writer - "]
pub type Outepmsk15W<'a, REG> = crate::BitWriter<'a, REG, Outepmsk15>;
impl<'a, REG> Outepmsk15W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk15::Nomask)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Outepmsk15::Mask)
    }
}
impl R {
    #[doc = "Bit 0"]
    #[inline(always)]
    pub fn inepmsk0(&self) -> Inepmsk0R {
        Inepmsk0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    pub fn inepmsk1(&self) -> Inepmsk1R {
        Inepmsk1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    pub fn inepmsk2(&self) -> Inepmsk2R {
        Inepmsk2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    pub fn inepmsk3(&self) -> Inepmsk3R {
        Inepmsk3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    pub fn inepmsk4(&self) -> Inepmsk4R {
        Inepmsk4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    pub fn inepmsk5(&self) -> Inepmsk5R {
        Inepmsk5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    pub fn inepmsk6(&self) -> Inepmsk6R {
        Inepmsk6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7"]
    #[inline(always)]
    pub fn inepmsk7(&self) -> Inepmsk7R {
        Inepmsk7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    pub fn inepmsk8(&self) -> Inepmsk8R {
        Inepmsk8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    pub fn inepmsk9(&self) -> Inepmsk9R {
        Inepmsk9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10"]
    #[inline(always)]
    pub fn inepmsk10(&self) -> Inepmsk10R {
        Inepmsk10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11"]
    #[inline(always)]
    pub fn inepmsk11(&self) -> Inepmsk11R {
        Inepmsk11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    pub fn inepmsk12(&self) -> Inepmsk12R {
        Inepmsk12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    pub fn in_ep_msk13(&self) -> InEpMsk13R {
        InEpMsk13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14"]
    #[inline(always)]
    pub fn inepmsk14(&self) -> Inepmsk14R {
        Inepmsk14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - IN Endpoint 15 Interrupt mask Bit"]
    #[inline(always)]
    pub fn in_ep_msk15(&self) -> InEpMsk15R {
        InEpMsk15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16"]
    #[inline(always)]
    pub fn outepmsk0(&self) -> Outepmsk0R {
        Outepmsk0R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17"]
    #[inline(always)]
    pub fn outepmsk1(&self) -> Outepmsk1R {
        Outepmsk1R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18"]
    #[inline(always)]
    pub fn outepmsk2(&self) -> Outepmsk2R {
        Outepmsk2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19"]
    #[inline(always)]
    pub fn out_epmsk3(&self) -> OutEpmsk3R {
        OutEpmsk3R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20"]
    #[inline(always)]
    pub fn outepmsk4(&self) -> Outepmsk4R {
        Outepmsk4R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21"]
    #[inline(always)]
    pub fn outepmsk5(&self) -> Outepmsk5R {
        Outepmsk5R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22"]
    #[inline(always)]
    pub fn outepmsk6(&self) -> Outepmsk6R {
        Outepmsk6R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23"]
    #[inline(always)]
    pub fn outepmsk7(&self) -> Outepmsk7R {
        Outepmsk7R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - OUT Endpoint 8 Interrupt mask Bit"]
    #[inline(always)]
    pub fn outepmsk8(&self) -> Outepmsk8R {
        Outepmsk8R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25"]
    #[inline(always)]
    pub fn outepmsk9(&self) -> Outepmsk9R {
        Outepmsk9R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26"]
    #[inline(always)]
    pub fn outepmsk10(&self) -> Outepmsk10R {
        Outepmsk10R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27"]
    #[inline(always)]
    pub fn outepmsk11(&self) -> Outepmsk11R {
        Outepmsk11R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28"]
    #[inline(always)]
    pub fn outepmsk12(&self) -> Outepmsk12R {
        Outepmsk12R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29"]
    #[inline(always)]
    pub fn outepmsk13(&self) -> Outepmsk13R {
        Outepmsk13R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30"]
    #[inline(always)]
    pub fn out_epmsk14(&self) -> OutEpmsk14R {
        OutEpmsk14R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31"]
    #[inline(always)]
    pub fn outepmsk15(&self) -> Outepmsk15R {
        Outepmsk15R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk0(&mut self) -> Inepmsk0W<DevgrpDaintmskSpec> {
        Inepmsk0W::new(self, 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk1(&mut self) -> Inepmsk1W<DevgrpDaintmskSpec> {
        Inepmsk1W::new(self, 1)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk2(&mut self) -> Inepmsk2W<DevgrpDaintmskSpec> {
        Inepmsk2W::new(self, 2)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk3(&mut self) -> Inepmsk3W<DevgrpDaintmskSpec> {
        Inepmsk3W::new(self, 3)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk4(&mut self) -> Inepmsk4W<DevgrpDaintmskSpec> {
        Inepmsk4W::new(self, 4)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk5(&mut self) -> Inepmsk5W<DevgrpDaintmskSpec> {
        Inepmsk5W::new(self, 5)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk6(&mut self) -> Inepmsk6W<DevgrpDaintmskSpec> {
        Inepmsk6W::new(self, 6)
    }
    #[doc = "Bit 7"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk7(&mut self) -> Inepmsk7W<DevgrpDaintmskSpec> {
        Inepmsk7W::new(self, 7)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk8(&mut self) -> Inepmsk8W<DevgrpDaintmskSpec> {
        Inepmsk8W::new(self, 8)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk9(&mut self) -> Inepmsk9W<DevgrpDaintmskSpec> {
        Inepmsk9W::new(self, 9)
    }
    #[doc = "Bit 10"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk10(&mut self) -> Inepmsk10W<DevgrpDaintmskSpec> {
        Inepmsk10W::new(self, 10)
    }
    #[doc = "Bit 11"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk11(&mut self) -> Inepmsk11W<DevgrpDaintmskSpec> {
        Inepmsk11W::new(self, 11)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk12(&mut self) -> Inepmsk12W<DevgrpDaintmskSpec> {
        Inepmsk12W::new(self, 12)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    #[must_use]
    pub fn in_ep_msk13(&mut self) -> InEpMsk13W<DevgrpDaintmskSpec> {
        InEpMsk13W::new(self, 13)
    }
    #[doc = "Bit 14"]
    #[inline(always)]
    #[must_use]
    pub fn inepmsk14(&mut self) -> Inepmsk14W<DevgrpDaintmskSpec> {
        Inepmsk14W::new(self, 14)
    }
    #[doc = "Bit 15 - IN Endpoint 15 Interrupt mask Bit"]
    #[inline(always)]
    #[must_use]
    pub fn in_ep_msk15(&mut self) -> InEpMsk15W<DevgrpDaintmskSpec> {
        InEpMsk15W::new(self, 15)
    }
    #[doc = "Bit 16"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk0(&mut self) -> Outepmsk0W<DevgrpDaintmskSpec> {
        Outepmsk0W::new(self, 16)
    }
    #[doc = "Bit 17"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk1(&mut self) -> Outepmsk1W<DevgrpDaintmskSpec> {
        Outepmsk1W::new(self, 17)
    }
    #[doc = "Bit 18"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk2(&mut self) -> Outepmsk2W<DevgrpDaintmskSpec> {
        Outepmsk2W::new(self, 18)
    }
    #[doc = "Bit 19"]
    #[inline(always)]
    #[must_use]
    pub fn out_epmsk3(&mut self) -> OutEpmsk3W<DevgrpDaintmskSpec> {
        OutEpmsk3W::new(self, 19)
    }
    #[doc = "Bit 20"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk4(&mut self) -> Outepmsk4W<DevgrpDaintmskSpec> {
        Outepmsk4W::new(self, 20)
    }
    #[doc = "Bit 21"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk5(&mut self) -> Outepmsk5W<DevgrpDaintmskSpec> {
        Outepmsk5W::new(self, 21)
    }
    #[doc = "Bit 22"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk6(&mut self) -> Outepmsk6W<DevgrpDaintmskSpec> {
        Outepmsk6W::new(self, 22)
    }
    #[doc = "Bit 23"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk7(&mut self) -> Outepmsk7W<DevgrpDaintmskSpec> {
        Outepmsk7W::new(self, 23)
    }
    #[doc = "Bit 24 - OUT Endpoint 8 Interrupt mask Bit"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk8(&mut self) -> Outepmsk8W<DevgrpDaintmskSpec> {
        Outepmsk8W::new(self, 24)
    }
    #[doc = "Bit 25"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk9(&mut self) -> Outepmsk9W<DevgrpDaintmskSpec> {
        Outepmsk9W::new(self, 25)
    }
    #[doc = "Bit 26"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk10(&mut self) -> Outepmsk10W<DevgrpDaintmskSpec> {
        Outepmsk10W::new(self, 26)
    }
    #[doc = "Bit 27"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk11(&mut self) -> Outepmsk11W<DevgrpDaintmskSpec> {
        Outepmsk11W::new(self, 27)
    }
    #[doc = "Bit 28"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk12(&mut self) -> Outepmsk12W<DevgrpDaintmskSpec> {
        Outepmsk12W::new(self, 28)
    }
    #[doc = "Bit 29"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk13(&mut self) -> Outepmsk13W<DevgrpDaintmskSpec> {
        Outepmsk13W::new(self, 29)
    }
    #[doc = "Bit 30"]
    #[inline(always)]
    #[must_use]
    pub fn out_epmsk14(&mut self) -> OutEpmsk14W<DevgrpDaintmskSpec> {
        OutEpmsk14W::new(self, 30)
    }
    #[doc = "Bit 31"]
    #[inline(always)]
    #[must_use]
    pub fn outepmsk15(&mut self) -> Outepmsk15W<DevgrpDaintmskSpec> {
        Outepmsk15W::new(self, 31)
    }
}
#[doc = "The Device Endpoint Interrupt Mask register works with the Device Endpoint Interrupt register to interrupt the application when an event occurs on a device endpoint. However, the Device All Endpoints Interrupt (DAINT) register bit corresponding to that interrupt is still set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_daintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_daintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDaintmskSpec;
impl crate::RegisterSpec for DevgrpDaintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 2076u64;
}
#[doc = "`read()` method returns [`devgrp_daintmsk::R`](R) reader structure"]
impl crate::Readable for DevgrpDaintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_daintmsk::W`](W) writer structure"]
impl crate::Writable for DevgrpDaintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_daintmsk to value 0"]
impl crate::Resettable for DevgrpDaintmskSpec {
    const RESET_VALUE: u32 = 0;
}
