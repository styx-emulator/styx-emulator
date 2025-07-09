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
#[doc = "Register `gmacgrp_MMC_Transmit_Interrupt_Mask` reader"]
pub type R = crate::R<GmacgrpMmcTransmitInterruptMaskSpec>;
#[doc = "Register `gmacgrp_MMC_Transmit_Interrupt_Mask` writer"]
pub type W = crate::W<GmacgrpMmcTransmitInterruptMaskSpec>;
#[doc = "Setting this bit masks the interrupt when the txoctetcount_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgboctim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txgboctim> for bool {
    #[inline(always)]
    fn from(variant: Txgboctim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgboctim` reader - Setting this bit masks the interrupt when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgboctimR = crate::BitReader<Txgboctim>;
impl TxgboctimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgboctim {
        match self.bits {
            false => Txgboctim::Nomaskintr,
            true => Txgboctim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txgboctim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txgboctim::Maskintr
    }
}
#[doc = "Field `txgboctim` writer - Setting this bit masks the interrupt when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgboctimW<'a, REG> = crate::BitWriter<'a, REG, Txgboctim>;
impl<'a, REG> TxgboctimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgboctim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgboctim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txframecount_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgbfrmim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txgbfrmim> for bool {
    #[inline(always)]
    fn from(variant: Txgbfrmim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgbfrmim` reader - Setting this bit masks the interrupt when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgbfrmimR = crate::BitReader<Txgbfrmim>;
impl TxgbfrmimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgbfrmim {
        match self.bits {
            false => Txgbfrmim::Nomaskintr,
            true => Txgbfrmim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txgbfrmim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txgbfrmim::Maskintr
    }
}
#[doc = "Field `txgbfrmim` writer - Setting this bit masks the interrupt when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgbfrmimW<'a, REG> = crate::BitWriter<'a, REG, Txgbfrmim>;
impl<'a, REG> TxgbfrmimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgbfrmim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgbfrmim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txbcgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txbcgfim> for bool {
    #[inline(always)]
    fn from(variant: Txbcgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txbcgfim` reader - Setting this bit masks the interrupt when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxbcgfimR = crate::BitReader<Txbcgfim>;
impl TxbcgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txbcgfim {
        match self.bits {
            false => Txbcgfim::Nomaskintr,
            true => Txbcgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txbcgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txbcgfim::Maskintr
    }
}
#[doc = "Field `txbcgfim` writer - Setting this bit masks the interrupt when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxbcgfimW<'a, REG> = crate::BitWriter<'a, REG, Txbcgfim>;
impl<'a, REG> TxbcgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txbcgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txbcgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txmulticastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txmcgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txmcgfim> for bool {
    #[inline(always)]
    fn from(variant: Txmcgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txmcgfim` reader - Setting this bit masks the interrupt when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcgfimR = crate::BitReader<Txmcgfim>;
impl TxmcgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txmcgfim {
        match self.bits {
            false => Txmcgfim::Nomaskintr,
            true => Txmcgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txmcgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txmcgfim::Maskintr
    }
}
#[doc = "Field `txmcgfim` writer - Setting this bit masks the interrupt when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcgfimW<'a, REG> = crate::BitWriter<'a, REG, Txmcgfim>;
impl<'a, REG> TxmcgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txmcgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txmcgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the tx64octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx64octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Tx64octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Tx64octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx64octgbfim` reader - Setting this bit masks the interrupt when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx64octgbfimR = crate::BitReader<Tx64octgbfim>;
impl Tx64octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx64octgbfim {
        match self.bits {
            false => Tx64octgbfim::Nomaskintr,
            true => Tx64octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Tx64octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Tx64octgbfim::Maskintr
    }
}
#[doc = "Field `tx64octgbfim` writer - Setting this bit masks the interrupt when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx64octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Tx64octgbfim>;
impl<'a, REG> Tx64octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx64octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx64octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx65t127octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Tx65t127octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Tx65t127octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx65t127octgbfim` reader - Setting this bit masks the interrupt when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx65t127octgbfimR = crate::BitReader<Tx65t127octgbfim>;
impl Tx65t127octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx65t127octgbfim {
        match self.bits {
            false => Tx65t127octgbfim::Nomaskintr,
            true => Tx65t127octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Tx65t127octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Tx65t127octgbfim::Maskintr
    }
}
#[doc = "Field `tx65t127octgbfim` writer - Setting this bit masks the interrupt when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx65t127octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Tx65t127octgbfim>;
impl<'a, REG> Tx65t127octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx65t127octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx65t127octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx128t255octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Tx128t255octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Tx128t255octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx128t255octgbfim` reader - Setting this bit masks the interrupt when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx128t255octgbfimR = crate::BitReader<Tx128t255octgbfim>;
impl Tx128t255octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx128t255octgbfim {
        match self.bits {
            false => Tx128t255octgbfim::Nomaskintr,
            true => Tx128t255octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Tx128t255octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Tx128t255octgbfim::Maskintr
    }
}
#[doc = "Field `tx128t255octgbfim` writer - Setting this bit masks the interrupt when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx128t255octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Tx128t255octgbfim>;
impl<'a, REG> Tx128t255octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx128t255octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx128t255octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx256t511octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Tx256t511octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Tx256t511octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx256t511octgbfim` reader - Setting this bit masks the interrupt when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx256t511octgbfimR = crate::BitReader<Tx256t511octgbfim>;
impl Tx256t511octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx256t511octgbfim {
        match self.bits {
            false => Tx256t511octgbfim::Nomaskintr,
            true => Tx256t511octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Tx256t511octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Tx256t511octgbfim::Maskintr
    }
}
#[doc = "Field `tx256t511octgbfim` writer - Setting this bit masks the interrupt when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx256t511octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Tx256t511octgbfim>;
impl<'a, REG> Tx256t511octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx256t511octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx256t511octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx512t1023octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Tx512t1023octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Tx512t1023octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx512t1023octgbfim` reader - Setting this bit masks the interrupt when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx512t1023octgbfimR = crate::BitReader<Tx512t1023octgbfim>;
impl Tx512t1023octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx512t1023octgbfim {
        match self.bits {
            false => Tx512t1023octgbfim::Nomaskintr,
            true => Tx512t1023octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Tx512t1023octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Tx512t1023octgbfim::Maskintr
    }
}
#[doc = "Field `tx512t1023octgbfim` writer - Setting this bit masks the interrupt when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx512t1023octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Tx512t1023octgbfim>;
impl<'a, REG> Tx512t1023octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx512t1023octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx512t1023octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx1024tmaxoctgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Tx1024tmaxoctgbfim> for bool {
    #[inline(always)]
    fn from(variant: Tx1024tmaxoctgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx1024tmaxoctgbfim` reader - Setting this bit masks the interrupt when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx1024tmaxoctgbfimR = crate::BitReader<Tx1024tmaxoctgbfim>;
impl Tx1024tmaxoctgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx1024tmaxoctgbfim {
        match self.bits {
            false => Tx1024tmaxoctgbfim::Nomaskintr,
            true => Tx1024tmaxoctgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Tx1024tmaxoctgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Tx1024tmaxoctgbfim::Maskintr
    }
}
#[doc = "Field `tx1024tmaxoctgbfim` writer - Setting this bit masks the interrupt when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx1024tmaxoctgbfimW<'a, REG> = crate::BitWriter<'a, REG, Tx1024tmaxoctgbfim>;
impl<'a, REG> Tx1024tmaxoctgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx1024tmaxoctgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Tx1024tmaxoctgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txunicastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txucgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txucgbfim> for bool {
    #[inline(always)]
    fn from(variant: Txucgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txucgbfim` reader - Setting this bit masks the interrupt when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxucgbfimR = crate::BitReader<Txucgbfim>;
impl TxucgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txucgbfim {
        match self.bits {
            false => Txucgbfim::Nomaskintr,
            true => Txucgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txucgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txucgbfim::Maskintr
    }
}
#[doc = "Field `txucgbfim` writer - Setting this bit masks the interrupt when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxucgbfimW<'a, REG> = crate::BitWriter<'a, REG, Txucgbfim>;
impl<'a, REG> TxucgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txucgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txucgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txmcgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txmcgbfim> for bool {
    #[inline(always)]
    fn from(variant: Txmcgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txmcgbfim` reader - Setting this bit masks the interrupt when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxmcgbfimR = crate::BitReader<Txmcgbfim>;
impl TxmcgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txmcgbfim {
        match self.bits {
            false => Txmcgbfim::Nomaskintr,
            true => Txmcgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txmcgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txmcgbfim::Maskintr
    }
}
#[doc = "Field `txmcgbfim` writer - Setting this bit masks the interrupt when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxmcgbfimW<'a, REG> = crate::BitWriter<'a, REG, Txmcgbfim>;
impl<'a, REG> TxmcgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txmcgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txmcgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txbcgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txbcgbfim> for bool {
    #[inline(always)]
    fn from(variant: Txbcgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txbcgbfim` reader - Setting this bit masks the interrupt when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxbcgbfimR = crate::BitReader<Txbcgbfim>;
impl TxbcgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txbcgbfim {
        match self.bits {
            false => Txbcgbfim::Nomaskintr,
            true => Txbcgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txbcgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txbcgbfim::Maskintr
    }
}
#[doc = "Field `txbcgbfim` writer - Setting this bit masks the interrupt when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxbcgbfimW<'a, REG> = crate::BitWriter<'a, REG, Txbcgbfim>;
impl<'a, REG> TxbcgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txbcgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txbcgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txunderflowerror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txuflowerfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txuflowerfim> for bool {
    #[inline(always)]
    fn from(variant: Txuflowerfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txuflowerfim` reader - Setting this bit masks the interrupt when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
pub type TxuflowerfimR = crate::BitReader<Txuflowerfim>;
impl TxuflowerfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txuflowerfim {
        match self.bits {
            false => Txuflowerfim::Nomaskintr,
            true => Txuflowerfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txuflowerfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txuflowerfim::Maskintr
    }
}
#[doc = "Field `txuflowerfim` writer - Setting this bit masks the interrupt when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
pub type TxuflowerfimW<'a, REG> = crate::BitWriter<'a, REG, Txuflowerfim>;
impl<'a, REG> TxuflowerfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txuflowerfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txuflowerfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txsinglecol_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txscolgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txscolgfim> for bool {
    #[inline(always)]
    fn from(variant: Txscolgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txscolgfim` reader - Setting this bit masks the interrupt when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
pub type TxscolgfimR = crate::BitReader<Txscolgfim>;
impl TxscolgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txscolgfim {
        match self.bits {
            false => Txscolgfim::Nomaskintr,
            true => Txscolgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txscolgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txscolgfim::Maskintr
    }
}
#[doc = "Field `txscolgfim` writer - Setting this bit masks the interrupt when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
pub type TxscolgfimW<'a, REG> = crate::BitWriter<'a, REG, Txscolgfim>;
impl<'a, REG> TxscolgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txscolgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txscolgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txmulticol_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txmcolgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txmcolgfim> for bool {
    #[inline(always)]
    fn from(variant: Txmcolgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txmcolgfim` reader - Setting this bit masks the interrupt when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcolgfimR = crate::BitReader<Txmcolgfim>;
impl TxmcolgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txmcolgfim {
        match self.bits {
            false => Txmcolgfim::Nomaskintr,
            true => Txmcolgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txmcolgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txmcolgfim::Maskintr
    }
}
#[doc = "Field `txmcolgfim` writer - Setting this bit masks the interrupt when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcolgfimW<'a, REG> = crate::BitWriter<'a, REG, Txmcolgfim>;
impl<'a, REG> TxmcolgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txmcolgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txmcolgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txdeferred counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txdeffim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txdeffim> for bool {
    #[inline(always)]
    fn from(variant: Txdeffim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txdeffim` reader - Setting this bit masks the interrupt when the txdeferred counter reaches half of the maximum value or the maximum value."]
pub type TxdeffimR = crate::BitReader<Txdeffim>;
impl TxdeffimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txdeffim {
        match self.bits {
            false => Txdeffim::Nomaskintr,
            true => Txdeffim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txdeffim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txdeffim::Maskintr
    }
}
#[doc = "Field `txdeffim` writer - Setting this bit masks the interrupt when the txdeferred counter reaches half of the maximum value or the maximum value."]
pub type TxdeffimW<'a, REG> = crate::BitWriter<'a, REG, Txdeffim>;
impl<'a, REG> TxdeffimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txdeffim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txdeffim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txlatecol counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txlatcolfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txlatcolfim> for bool {
    #[inline(always)]
    fn from(variant: Txlatcolfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txlatcolfim` reader - Setting this bit masks the interrupt when the txlatecol counter reaches half of the maximum value or the maximum value."]
pub type TxlatcolfimR = crate::BitReader<Txlatcolfim>;
impl TxlatcolfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txlatcolfim {
        match self.bits {
            false => Txlatcolfim::Nomaskintr,
            true => Txlatcolfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txlatcolfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txlatcolfim::Maskintr
    }
}
#[doc = "Field `txlatcolfim` writer - Setting this bit masks the interrupt when the txlatecol counter reaches half of the maximum value or the maximum value."]
pub type TxlatcolfimW<'a, REG> = crate::BitWriter<'a, REG, Txlatcolfim>;
impl<'a, REG> TxlatcolfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txlatcolfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txlatcolfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txexcesscol counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txexcolfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txexcolfim> for bool {
    #[inline(always)]
    fn from(variant: Txexcolfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txexcolfim` reader - Setting this bit masks the interrupt when the txexcesscol counter reaches half of the maximum value or the maximum value."]
pub type TxexcolfimR = crate::BitReader<Txexcolfim>;
impl TxexcolfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txexcolfim {
        match self.bits {
            false => Txexcolfim::Nomaskintr,
            true => Txexcolfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txexcolfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txexcolfim::Maskintr
    }
}
#[doc = "Field `txexcolfim` writer - Setting this bit masks the interrupt when the txexcesscol counter reaches half of the maximum value or the maximum value."]
pub type TxexcolfimW<'a, REG> = crate::BitWriter<'a, REG, Txexcolfim>;
impl<'a, REG> TxexcolfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txexcolfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txexcolfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txcarriererror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txcarerfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txcarerfim> for bool {
    #[inline(always)]
    fn from(variant: Txcarerfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txcarerfim` reader - Setting this bit masks the interrupt when the txcarriererror counter reaches half of the maximum value or the maximum value."]
pub type TxcarerfimR = crate::BitReader<Txcarerfim>;
impl TxcarerfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txcarerfim {
        match self.bits {
            false => Txcarerfim::Nomaskintr,
            true => Txcarerfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txcarerfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txcarerfim::Maskintr
    }
}
#[doc = "Field `txcarerfim` writer - Setting this bit masks the interrupt when the txcarriererror counter reaches half of the maximum value or the maximum value."]
pub type TxcarerfimW<'a, REG> = crate::BitWriter<'a, REG, Txcarerfim>;
impl<'a, REG> TxcarerfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txcarerfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txcarerfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txoctetcount_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgoctim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txgoctim> for bool {
    #[inline(always)]
    fn from(variant: Txgoctim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgoctim` reader - Setting this bit masks the interrupt when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgoctimR = crate::BitReader<Txgoctim>;
impl TxgoctimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgoctim {
        match self.bits {
            false => Txgoctim::Nomaskintr,
            true => Txgoctim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txgoctim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txgoctim::Maskintr
    }
}
#[doc = "Field `txgoctim` writer - Setting this bit masks the interrupt when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgoctimW<'a, REG> = crate::BitWriter<'a, REG, Txgoctim>;
impl<'a, REG> TxgoctimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgoctim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgoctim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txframecount_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgfrmim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txgfrmim> for bool {
    #[inline(always)]
    fn from(variant: Txgfrmim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgfrmim` reader - Setting this bit masks the interrupt when the txframecount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgfrmimR = crate::BitReader<Txgfrmim>;
impl TxgfrmimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgfrmim {
        match self.bits {
            false => Txgfrmim::Nomaskintr,
            true => Txgfrmim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txgfrmim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txgfrmim::Maskintr
    }
}
#[doc = "Field `txgfrmim` writer - Setting this bit masks the interrupt when the txframecount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgfrmimW<'a, REG> = crate::BitWriter<'a, REG, Txgfrmim>;
impl<'a, REG> TxgfrmimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgfrmim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txgfrmim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txexcessdef counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txexdeffim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txexdeffim> for bool {
    #[inline(always)]
    fn from(variant: Txexdeffim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txexdeffim` reader - Setting this bit masks the interrupt when the txexcessdef counter reaches half of the maximum value or the maximum value."]
pub type TxexdeffimR = crate::BitReader<Txexdeffim>;
impl TxexdeffimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txexdeffim {
        match self.bits {
            false => Txexdeffim::Nomaskintr,
            true => Txexdeffim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txexdeffim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txexdeffim::Maskintr
    }
}
#[doc = "Field `txexdeffim` writer - Setting this bit masks the interrupt when the txexcessdef counter reaches half of the maximum value or the maximum value."]
pub type TxexdeffimW<'a, REG> = crate::BitWriter<'a, REG, Txexdeffim>;
impl<'a, REG> TxexdeffimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txexdeffim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txexdeffim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txpauseframes counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txpausfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txpausfim> for bool {
    #[inline(always)]
    fn from(variant: Txpausfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txpausfim` reader - Setting this bit masks the interrupt when the txpauseframes counter reaches half of the maximum value or the maximum value."]
pub type TxpausfimR = crate::BitReader<Txpausfim>;
impl TxpausfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txpausfim {
        match self.bits {
            false => Txpausfim::Nomaskintr,
            true => Txpausfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txpausfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txpausfim::Maskintr
    }
}
#[doc = "Field `txpausfim` writer - Setting this bit masks the interrupt when the txpauseframes counter reaches half of the maximum value or the maximum value."]
pub type TxpausfimW<'a, REG> = crate::BitWriter<'a, REG, Txpausfim>;
impl<'a, REG> TxpausfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txpausfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txpausfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txvlanframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txvlangfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txvlangfim> for bool {
    #[inline(always)]
    fn from(variant: Txvlangfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txvlangfim` reader - Setting this bit masks the interrupt when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxvlangfimR = crate::BitReader<Txvlangfim>;
impl TxvlangfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txvlangfim {
        match self.bits {
            false => Txvlangfim::Nomaskintr,
            true => Txvlangfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txvlangfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txvlangfim::Maskintr
    }
}
#[doc = "Field `txvlangfim` writer - Setting this bit masks the interrupt when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxvlangfimW<'a, REG> = crate::BitWriter<'a, REG, Txvlangfim>;
impl<'a, REG> TxvlangfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txvlangfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txvlangfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the txoversize_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txosizegfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Txosizegfim> for bool {
    #[inline(always)]
    fn from(variant: Txosizegfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txosizegfim` reader - Setting this bit masks the interrupt when the txoversize_g counter reaches half of the maximum value or the maximum value."]
pub type TxosizegfimR = crate::BitReader<Txosizegfim>;
impl TxosizegfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txosizegfim {
        match self.bits {
            false => Txosizegfim::Nomaskintr,
            true => Txosizegfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Txosizegfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Txosizegfim::Maskintr
    }
}
#[doc = "Field `txosizegfim` writer - Setting this bit masks the interrupt when the txoversize_g counter reaches half of the maximum value or the maximum value."]
pub type TxosizegfimW<'a, REG> = crate::BitWriter<'a, REG, Txosizegfim>;
impl<'a, REG> TxosizegfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txosizegfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Txosizegfim::Maskintr)
    }
}
impl R {
    #[doc = "Bit 0 - Setting this bit masks the interrupt when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgboctim(&self) -> TxgboctimR {
        TxgboctimR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Setting this bit masks the interrupt when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgbfrmim(&self) -> TxgbfrmimR {
        TxgbfrmimR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Setting this bit masks the interrupt when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txbcgfim(&self) -> TxbcgfimR {
        TxbcgfimR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Setting this bit masks the interrupt when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txmcgfim(&self) -> TxmcgfimR {
        TxmcgfimR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Setting this bit masks the interrupt when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx64octgbfim(&self) -> Tx64octgbfimR {
        Tx64octgbfimR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Setting this bit masks the interrupt when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx65t127octgbfim(&self) -> Tx65t127octgbfimR {
        Tx65t127octgbfimR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Setting this bit masks the interrupt when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx128t255octgbfim(&self) -> Tx128t255octgbfimR {
        Tx128t255octgbfimR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Setting this bit masks the interrupt when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx256t511octgbfim(&self) -> Tx256t511octgbfimR {
        Tx256t511octgbfimR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Setting this bit masks the interrupt when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx512t1023octgbfim(&self) -> Tx512t1023octgbfimR {
        Tx512t1023octgbfimR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Setting this bit masks the interrupt when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx1024tmaxoctgbfim(&self) -> Tx1024tmaxoctgbfimR {
        Tx1024tmaxoctgbfimR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Setting this bit masks the interrupt when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txucgbfim(&self) -> TxucgbfimR {
        TxucgbfimR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Setting this bit masks the interrupt when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txmcgbfim(&self) -> TxmcgbfimR {
        TxmcgbfimR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Setting this bit masks the interrupt when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txbcgbfim(&self) -> TxbcgbfimR {
        TxbcgbfimR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Setting this bit masks the interrupt when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txuflowerfim(&self) -> TxuflowerfimR {
        TxuflowerfimR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Setting this bit masks the interrupt when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txscolgfim(&self) -> TxscolgfimR {
        TxscolgfimR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Setting this bit masks the interrupt when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txmcolgfim(&self) -> TxmcolgfimR {
        TxmcolgfimR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Setting this bit masks the interrupt when the txdeferred counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txdeffim(&self) -> TxdeffimR {
        TxdeffimR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Setting this bit masks the interrupt when the txlatecol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txlatcolfim(&self) -> TxlatcolfimR {
        TxlatcolfimR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Setting this bit masks the interrupt when the txexcesscol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txexcolfim(&self) -> TxexcolfimR {
        TxexcolfimR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Setting this bit masks the interrupt when the txcarriererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txcarerfim(&self) -> TxcarerfimR {
        TxcarerfimR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Setting this bit masks the interrupt when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgoctim(&self) -> TxgoctimR {
        TxgoctimR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Setting this bit masks the interrupt when the txframecount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgfrmim(&self) -> TxgfrmimR {
        TxgfrmimR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Setting this bit masks the interrupt when the txexcessdef counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txexdeffim(&self) -> TxexdeffimR {
        TxexdeffimR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Setting this bit masks the interrupt when the txpauseframes counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txpausfim(&self) -> TxpausfimR {
        TxpausfimR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Setting this bit masks the interrupt when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txvlangfim(&self) -> TxvlangfimR {
        TxvlangfimR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Setting this bit masks the interrupt when the txoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txosizegfim(&self) -> TxosizegfimR {
        TxosizegfimR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Setting this bit masks the interrupt when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgboctim(&mut self) -> TxgboctimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxgboctimW::new(self, 0)
    }
    #[doc = "Bit 1 - Setting this bit masks the interrupt when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgbfrmim(&mut self) -> TxgbfrmimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxgbfrmimW::new(self, 1)
    }
    #[doc = "Bit 2 - Setting this bit masks the interrupt when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txbcgfim(&mut self) -> TxbcgfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxbcgfimW::new(self, 2)
    }
    #[doc = "Bit 3 - Setting this bit masks the interrupt when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txmcgfim(&mut self) -> TxmcgfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxmcgfimW::new(self, 3)
    }
    #[doc = "Bit 4 - Setting this bit masks the interrupt when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx64octgbfim(&mut self) -> Tx64octgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        Tx64octgbfimW::new(self, 4)
    }
    #[doc = "Bit 5 - Setting this bit masks the interrupt when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx65t127octgbfim(&mut self) -> Tx65t127octgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        Tx65t127octgbfimW::new(self, 5)
    }
    #[doc = "Bit 6 - Setting this bit masks the interrupt when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx128t255octgbfim(&mut self) -> Tx128t255octgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        Tx128t255octgbfimW::new(self, 6)
    }
    #[doc = "Bit 7 - Setting this bit masks the interrupt when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx256t511octgbfim(&mut self) -> Tx256t511octgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        Tx256t511octgbfimW::new(self, 7)
    }
    #[doc = "Bit 8 - Setting this bit masks the interrupt when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx512t1023octgbfim(
        &mut self,
    ) -> Tx512t1023octgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        Tx512t1023octgbfimW::new(self, 8)
    }
    #[doc = "Bit 9 - Setting this bit masks the interrupt when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx1024tmaxoctgbfim(
        &mut self,
    ) -> Tx1024tmaxoctgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        Tx1024tmaxoctgbfimW::new(self, 9)
    }
    #[doc = "Bit 10 - Setting this bit masks the interrupt when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txucgbfim(&mut self) -> TxucgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxucgbfimW::new(self, 10)
    }
    #[doc = "Bit 11 - Setting this bit masks the interrupt when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txmcgbfim(&mut self) -> TxmcgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxmcgbfimW::new(self, 11)
    }
    #[doc = "Bit 12 - Setting this bit masks the interrupt when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txbcgbfim(&mut self) -> TxbcgbfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxbcgbfimW::new(self, 12)
    }
    #[doc = "Bit 13 - Setting this bit masks the interrupt when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txuflowerfim(&mut self) -> TxuflowerfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxuflowerfimW::new(self, 13)
    }
    #[doc = "Bit 14 - Setting this bit masks the interrupt when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txscolgfim(&mut self) -> TxscolgfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxscolgfimW::new(self, 14)
    }
    #[doc = "Bit 15 - Setting this bit masks the interrupt when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txmcolgfim(&mut self) -> TxmcolgfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxmcolgfimW::new(self, 15)
    }
    #[doc = "Bit 16 - Setting this bit masks the interrupt when the txdeferred counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txdeffim(&mut self) -> TxdeffimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxdeffimW::new(self, 16)
    }
    #[doc = "Bit 17 - Setting this bit masks the interrupt when the txlatecol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txlatcolfim(&mut self) -> TxlatcolfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxlatcolfimW::new(self, 17)
    }
    #[doc = "Bit 18 - Setting this bit masks the interrupt when the txexcesscol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txexcolfim(&mut self) -> TxexcolfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxexcolfimW::new(self, 18)
    }
    #[doc = "Bit 19 - Setting this bit masks the interrupt when the txcarriererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txcarerfim(&mut self) -> TxcarerfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxcarerfimW::new(self, 19)
    }
    #[doc = "Bit 20 - Setting this bit masks the interrupt when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgoctim(&mut self) -> TxgoctimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxgoctimW::new(self, 20)
    }
    #[doc = "Bit 21 - Setting this bit masks the interrupt when the txframecount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgfrmim(&mut self) -> TxgfrmimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxgfrmimW::new(self, 21)
    }
    #[doc = "Bit 22 - Setting this bit masks the interrupt when the txexcessdef counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txexdeffim(&mut self) -> TxexdeffimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxexdeffimW::new(self, 22)
    }
    #[doc = "Bit 23 - Setting this bit masks the interrupt when the txpauseframes counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txpausfim(&mut self) -> TxpausfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxpausfimW::new(self, 23)
    }
    #[doc = "Bit 24 - Setting this bit masks the interrupt when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txvlangfim(&mut self) -> TxvlangfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxvlangfimW::new(self, 24)
    }
    #[doc = "Bit 25 - Setting this bit masks the interrupt when the txoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txosizegfim(&mut self) -> TxosizegfimW<GmacgrpMmcTransmitInterruptMaskSpec> {
        TxosizegfimW::new(self, 25)
    }
}
#[doc = "The MMC Transmit Interrupt Mask register maintains the masks for the interrupts generated when the transmit statistic counters reach half of their maximum value or maximum value. This register is 32-bits wide.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_transmit_interrupt_mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_transmit_interrupt_mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcTransmitInterruptMaskSpec;
impl crate::RegisterSpec for GmacgrpMmcTransmitInterruptMaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 272u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_transmit_interrupt_mask::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcTransmitInterruptMaskSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mmc_transmit_interrupt_mask::W`](W) writer structure"]
impl crate::Writable for GmacgrpMmcTransmitInterruptMaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MMC_Transmit_Interrupt_Mask to value 0"]
impl crate::Resettable for GmacgrpMmcTransmitInterruptMaskSpec {
    const RESET_VALUE: u32 = 0;
}
