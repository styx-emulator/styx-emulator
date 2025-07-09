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
#[doc = "Register `devgrp_diepempmsk` reader"]
pub type R = crate::R<DevgrpDiepempmskSpec>;
#[doc = "Register `devgrp_diepempmsk` writer"]
pub type W = crate::W<DevgrpDiepempmskSpec>;
#[doc = "This bit acts as mask bits for DIEPINT0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk0 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk0> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk0` reader - This bit acts as mask bits for DIEPINT0."]
pub type Ineptxfempmsk0R = crate::BitReader<Ineptxfempmsk0>;
impl Ineptxfempmsk0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk0 {
        match self.bits {
            false => Ineptxfempmsk0::Mask,
            true => Ineptxfempmsk0::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk0::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk0::Nomask
    }
}
#[doc = "Field `ineptxfempmsk0` writer - This bit acts as mask bits for DIEPINT0."]
pub type Ineptxfempmsk0W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk0>;
impl<'a, REG> Ineptxfempmsk0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk0::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk0::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk1 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk1> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk1` reader - This bit acts as mask bits for DIEPINT1."]
pub type Ineptxfempmsk1R = crate::BitReader<Ineptxfempmsk1>;
impl Ineptxfempmsk1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk1 {
        match self.bits {
            false => Ineptxfempmsk1::Mask,
            true => Ineptxfempmsk1::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk1::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk1::Nomask
    }
}
#[doc = "Field `ineptxfempmsk1` writer - This bit acts as mask bits for DIEPINT1."]
pub type Ineptxfempmsk1W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk1>;
impl<'a, REG> Ineptxfempmsk1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk1::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk1::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT2.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk2 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk2> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk2` reader - This bit acts as mask bits for DIEPINT2."]
pub type Ineptxfempmsk2R = crate::BitReader<Ineptxfempmsk2>;
impl Ineptxfempmsk2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk2 {
        match self.bits {
            false => Ineptxfempmsk2::Mask,
            true => Ineptxfempmsk2::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk2::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk2::Nomask
    }
}
#[doc = "Field `ineptxfempmsk2` writer - This bit acts as mask bits for DIEPINT2."]
pub type Ineptxfempmsk2W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk2>;
impl<'a, REG> Ineptxfempmsk2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk2::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk2::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT3.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk3 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk3> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk3` reader - This bit acts as mask bits for DIEPINT3."]
pub type Ineptxfempmsk3R = crate::BitReader<Ineptxfempmsk3>;
impl Ineptxfempmsk3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk3 {
        match self.bits {
            false => Ineptxfempmsk3::Mask,
            true => Ineptxfempmsk3::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk3::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk3::Nomask
    }
}
#[doc = "Field `ineptxfempmsk3` writer - This bit acts as mask bits for DIEPINT3."]
pub type Ineptxfempmsk3W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk3>;
impl<'a, REG> Ineptxfempmsk3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk3::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk3::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT4.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk4 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk4> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk4` reader - This bit acts as mask bits for DIEPINT4."]
pub type Ineptxfempmsk4R = crate::BitReader<Ineptxfempmsk4>;
impl Ineptxfempmsk4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk4 {
        match self.bits {
            false => Ineptxfempmsk4::Mask,
            true => Ineptxfempmsk4::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk4::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk4::Nomask
    }
}
#[doc = "Field `ineptxfempmsk4` writer - This bit acts as mask bits for DIEPINT4."]
pub type Ineptxfempmsk4W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk4>;
impl<'a, REG> Ineptxfempmsk4W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk4::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk4::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT5.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk5 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk5> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk5` reader - This bit acts as mask bits for DIEPINT5."]
pub type Ineptxfempmsk5R = crate::BitReader<Ineptxfempmsk5>;
impl Ineptxfempmsk5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk5 {
        match self.bits {
            false => Ineptxfempmsk5::Mask,
            true => Ineptxfempmsk5::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk5::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk5::Nomask
    }
}
#[doc = "Field `ineptxfempmsk5` writer - This bit acts as mask bits for DIEPINT5."]
pub type Ineptxfempmsk5W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk5>;
impl<'a, REG> Ineptxfempmsk5W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk5::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk5::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT6.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk6 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk6> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk6` reader - This bit acts as mask bits for DIEPINT6."]
pub type Ineptxfempmsk6R = crate::BitReader<Ineptxfempmsk6>;
impl Ineptxfempmsk6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk6 {
        match self.bits {
            false => Ineptxfempmsk6::Mask,
            true => Ineptxfempmsk6::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk6::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk6::Nomask
    }
}
#[doc = "Field `ineptxfempmsk6` writer - This bit acts as mask bits for DIEPINT6."]
pub type Ineptxfempmsk6W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk6>;
impl<'a, REG> Ineptxfempmsk6W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk6::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk6::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT7.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk7 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk7> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk7` reader - This bit acts as mask bits for DIEPINT7."]
pub type Ineptxfempmsk7R = crate::BitReader<Ineptxfempmsk7>;
impl Ineptxfempmsk7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk7 {
        match self.bits {
            false => Ineptxfempmsk7::Mask,
            true => Ineptxfempmsk7::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk7::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk7::Nomask
    }
}
#[doc = "Field `ineptxfempmsk7` writer - This bit acts as mask bits for DIEPINT7."]
pub type Ineptxfempmsk7W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk7>;
impl<'a, REG> Ineptxfempmsk7W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk7::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk7::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT8.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk8 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk8> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk8` reader - This bit acts as mask bits for DIEPINT8."]
pub type Ineptxfempmsk8R = crate::BitReader<Ineptxfempmsk8>;
impl Ineptxfempmsk8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk8 {
        match self.bits {
            false => Ineptxfempmsk8::Mask,
            true => Ineptxfempmsk8::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk8::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk8::Nomask
    }
}
#[doc = "Field `ineptxfempmsk8` writer - This bit acts as mask bits for DIEPINT8."]
pub type Ineptxfempmsk8W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk8>;
impl<'a, REG> Ineptxfempmsk8W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk8::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk8::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT9.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk9 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk9> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk9` reader - This bit acts as mask bits for DIEPINT9."]
pub type Ineptxfempmsk9R = crate::BitReader<Ineptxfempmsk9>;
impl Ineptxfempmsk9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk9 {
        match self.bits {
            false => Ineptxfempmsk9::Mask,
            true => Ineptxfempmsk9::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk9::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk9::Nomask
    }
}
#[doc = "Field `ineptxfempmsk9` writer - This bit acts as mask bits for DIEPINT9."]
pub type Ineptxfempmsk9W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk9>;
impl<'a, REG> Ineptxfempmsk9W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk9::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk9::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT10.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk10 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk10> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk10` reader - This bit acts as mask bits for DIEPINT10."]
pub type Ineptxfempmsk10R = crate::BitReader<Ineptxfempmsk10>;
impl Ineptxfempmsk10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk10 {
        match self.bits {
            false => Ineptxfempmsk10::Mask,
            true => Ineptxfempmsk10::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk10::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk10::Nomask
    }
}
#[doc = "Field `ineptxfempmsk10` writer - This bit acts as mask bits for DIEPINT10."]
pub type Ineptxfempmsk10W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk10>;
impl<'a, REG> Ineptxfempmsk10W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk10::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk10::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT11.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk11 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk11> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk11` reader - This bit acts as mask bits for DIEPINT11."]
pub type Ineptxfempmsk11R = crate::BitReader<Ineptxfempmsk11>;
impl Ineptxfempmsk11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk11 {
        match self.bits {
            false => Ineptxfempmsk11::Mask,
            true => Ineptxfempmsk11::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk11::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk11::Nomask
    }
}
#[doc = "Field `ineptxfempmsk11` writer - This bit acts as mask bits for DIEPINT11."]
pub type Ineptxfempmsk11W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk11>;
impl<'a, REG> Ineptxfempmsk11W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk11::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk11::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT12.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk12 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk12> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk12` reader - This bit acts as mask bits for DIEPINT12."]
pub type Ineptxfempmsk12R = crate::BitReader<Ineptxfempmsk12>;
impl Ineptxfempmsk12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk12 {
        match self.bits {
            false => Ineptxfempmsk12::Mask,
            true => Ineptxfempmsk12::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk12::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk12::Nomask
    }
}
#[doc = "Field `ineptxfempmsk12` writer - This bit acts as mask bits for DIEPINT12."]
pub type Ineptxfempmsk12W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk12>;
impl<'a, REG> Ineptxfempmsk12W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk12::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk12::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT13.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk13 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk13> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk13` reader - This bit acts as mask bits for DIEPINT13."]
pub type Ineptxfempmsk13R = crate::BitReader<Ineptxfempmsk13>;
impl Ineptxfempmsk13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk13 {
        match self.bits {
            false => Ineptxfempmsk13::Mask,
            true => Ineptxfempmsk13::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk13::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk13::Nomask
    }
}
#[doc = "Field `ineptxfempmsk13` writer - This bit acts as mask bits for DIEPINT13."]
pub type Ineptxfempmsk13W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk13>;
impl<'a, REG> Ineptxfempmsk13W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk13::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk13::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT14.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk14 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk14> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk14` reader - This bit acts as mask bits for DIEPINT14."]
pub type Ineptxfempmsk14R = crate::BitReader<Ineptxfempmsk14>;
impl Ineptxfempmsk14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk14 {
        match self.bits {
            false => Ineptxfempmsk14::Mask,
            true => Ineptxfempmsk14::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk14::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk14::Nomask
    }
}
#[doc = "Field `ineptxfempmsk14` writer - This bit acts as mask bits for DIEPINT14."]
pub type Ineptxfempmsk14W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk14>;
impl<'a, REG> Ineptxfempmsk14W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk14::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk14::Nomask)
    }
}
#[doc = "This bit acts as mask bits for DIEPINT15.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineptxfempmsk15 {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ineptxfempmsk15> for bool {
    #[inline(always)]
    fn from(variant: Ineptxfempmsk15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ineptxfempmsk15` reader - This bit acts as mask bits for DIEPINT15."]
pub type Ineptxfempmsk15R = crate::BitReader<Ineptxfempmsk15>;
impl Ineptxfempmsk15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineptxfempmsk15 {
        match self.bits {
            false => Ineptxfempmsk15::Mask,
            true => Ineptxfempmsk15::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ineptxfempmsk15::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ineptxfempmsk15::Nomask
    }
}
#[doc = "Field `ineptxfempmsk15` writer - This bit acts as mask bits for DIEPINT15."]
pub type Ineptxfempmsk15W<'a, REG> = crate::BitWriter<'a, REG, Ineptxfempmsk15>;
impl<'a, REG> Ineptxfempmsk15W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk15::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ineptxfempmsk15::Nomask)
    }
}
impl R {
    #[doc = "Bit 0 - This bit acts as mask bits for DIEPINT0."]
    #[inline(always)]
    pub fn ineptxfempmsk0(&self) -> Ineptxfempmsk0R {
        Ineptxfempmsk0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit acts as mask bits for DIEPINT1."]
    #[inline(always)]
    pub fn ineptxfempmsk1(&self) -> Ineptxfempmsk1R {
        Ineptxfempmsk1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit acts as mask bits for DIEPINT2."]
    #[inline(always)]
    pub fn ineptxfempmsk2(&self) -> Ineptxfempmsk2R {
        Ineptxfempmsk2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit acts as mask bits for DIEPINT3."]
    #[inline(always)]
    pub fn ineptxfempmsk3(&self) -> Ineptxfempmsk3R {
        Ineptxfempmsk3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit acts as mask bits for DIEPINT4."]
    #[inline(always)]
    pub fn ineptxfempmsk4(&self) -> Ineptxfempmsk4R {
        Ineptxfempmsk4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit acts as mask bits for DIEPINT5."]
    #[inline(always)]
    pub fn ineptxfempmsk5(&self) -> Ineptxfempmsk5R {
        Ineptxfempmsk5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit acts as mask bits for DIEPINT6."]
    #[inline(always)]
    pub fn ineptxfempmsk6(&self) -> Ineptxfempmsk6R {
        Ineptxfempmsk6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit acts as mask bits for DIEPINT7."]
    #[inline(always)]
    pub fn ineptxfempmsk7(&self) -> Ineptxfempmsk7R {
        Ineptxfempmsk7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit acts as mask bits for DIEPINT8."]
    #[inline(always)]
    pub fn ineptxfempmsk8(&self) -> Ineptxfempmsk8R {
        Ineptxfempmsk8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit acts as mask bits for DIEPINT9."]
    #[inline(always)]
    pub fn ineptxfempmsk9(&self) -> Ineptxfempmsk9R {
        Ineptxfempmsk9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit acts as mask bits for DIEPINT10."]
    #[inline(always)]
    pub fn ineptxfempmsk10(&self) -> Ineptxfempmsk10R {
        Ineptxfempmsk10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit acts as mask bits for DIEPINT11."]
    #[inline(always)]
    pub fn ineptxfempmsk11(&self) -> Ineptxfempmsk11R {
        Ineptxfempmsk11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit acts as mask bits for DIEPINT12."]
    #[inline(always)]
    pub fn ineptxfempmsk12(&self) -> Ineptxfempmsk12R {
        Ineptxfempmsk12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - This bit acts as mask bits for DIEPINT13."]
    #[inline(always)]
    pub fn ineptxfempmsk13(&self) -> Ineptxfempmsk13R {
        Ineptxfempmsk13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - This bit acts as mask bits for DIEPINT14."]
    #[inline(always)]
    pub fn ineptxfempmsk14(&self) -> Ineptxfempmsk14R {
        Ineptxfempmsk14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - This bit acts as mask bits for DIEPINT15."]
    #[inline(always)]
    pub fn ineptxfempmsk15(&self) -> Ineptxfempmsk15R {
        Ineptxfempmsk15R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit acts as mask bits for DIEPINT0."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk0(&mut self) -> Ineptxfempmsk0W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk0W::new(self, 0)
    }
    #[doc = "Bit 1 - This bit acts as mask bits for DIEPINT1."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk1(&mut self) -> Ineptxfempmsk1W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk1W::new(self, 1)
    }
    #[doc = "Bit 2 - This bit acts as mask bits for DIEPINT2."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk2(&mut self) -> Ineptxfempmsk2W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk2W::new(self, 2)
    }
    #[doc = "Bit 3 - This bit acts as mask bits for DIEPINT3."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk3(&mut self) -> Ineptxfempmsk3W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk3W::new(self, 3)
    }
    #[doc = "Bit 4 - This bit acts as mask bits for DIEPINT4."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk4(&mut self) -> Ineptxfempmsk4W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk4W::new(self, 4)
    }
    #[doc = "Bit 5 - This bit acts as mask bits for DIEPINT5."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk5(&mut self) -> Ineptxfempmsk5W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk5W::new(self, 5)
    }
    #[doc = "Bit 6 - This bit acts as mask bits for DIEPINT6."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk6(&mut self) -> Ineptxfempmsk6W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk6W::new(self, 6)
    }
    #[doc = "Bit 7 - This bit acts as mask bits for DIEPINT7."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk7(&mut self) -> Ineptxfempmsk7W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk7W::new(self, 7)
    }
    #[doc = "Bit 8 - This bit acts as mask bits for DIEPINT8."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk8(&mut self) -> Ineptxfempmsk8W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk8W::new(self, 8)
    }
    #[doc = "Bit 9 - This bit acts as mask bits for DIEPINT9."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk9(&mut self) -> Ineptxfempmsk9W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk9W::new(self, 9)
    }
    #[doc = "Bit 10 - This bit acts as mask bits for DIEPINT10."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk10(&mut self) -> Ineptxfempmsk10W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk10W::new(self, 10)
    }
    #[doc = "Bit 11 - This bit acts as mask bits for DIEPINT11."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk11(&mut self) -> Ineptxfempmsk11W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk11W::new(self, 11)
    }
    #[doc = "Bit 12 - This bit acts as mask bits for DIEPINT12."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk12(&mut self) -> Ineptxfempmsk12W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk12W::new(self, 12)
    }
    #[doc = "Bit 13 - This bit acts as mask bits for DIEPINT13."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk13(&mut self) -> Ineptxfempmsk13W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk13W::new(self, 13)
    }
    #[doc = "Bit 14 - This bit acts as mask bits for DIEPINT14."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk14(&mut self) -> Ineptxfempmsk14W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk14W::new(self, 14)
    }
    #[doc = "Bit 15 - This bit acts as mask bits for DIEPINT15."]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfempmsk15(&mut self) -> Ineptxfempmsk15W<DevgrpDiepempmskSpec> {
        Ineptxfempmsk15W::new(self, 15)
    }
}
#[doc = "This register is used to control the IN endpoint FIFO empty interrupt generation (DIEPINTn.TxfEmp).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepempmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepempmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepempmskSpec;
impl crate::RegisterSpec for DevgrpDiepempmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 2100u64;
}
#[doc = "`read()` method returns [`devgrp_diepempmsk::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepempmskSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_diepempmsk::W`](W) writer structure"]
impl crate::Writable for DevgrpDiepempmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_diepempmsk to value 0"]
impl crate::Resettable for DevgrpDiepempmskSpec {
    const RESET_VALUE: u32 = 0;
}
