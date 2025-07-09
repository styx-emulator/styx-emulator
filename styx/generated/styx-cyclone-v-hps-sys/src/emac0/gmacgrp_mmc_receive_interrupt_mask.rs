// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MMC_Receive_Interrupt_Mask` reader"]
pub type R = crate::R<GmacgrpMmcReceiveInterruptMaskSpec>;
#[doc = "Register `gmacgrp_MMC_Receive_Interrupt_Mask` writer"]
pub type W = crate::W<GmacgrpMmcReceiveInterruptMaskSpec>;
#[doc = "Setting this bit masks the interrupt when the rxframecount_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxgbfrmim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxgbfrmim> for bool {
    #[inline(always)]
    fn from(variant: Rxgbfrmim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxgbfrmim` reader - Setting this bit masks the interrupt when the rxframecount_gb counter reaches half of the maximum value or the maximum value."]
pub type RxgbfrmimR = crate::BitReader<Rxgbfrmim>;
impl RxgbfrmimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxgbfrmim {
        match self.bits {
            false => Rxgbfrmim::Nomaskintr,
            true => Rxgbfrmim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxgbfrmim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxgbfrmim::Maskintr
    }
}
#[doc = "Field `rxgbfrmim` writer - Setting this bit masks the interrupt when the rxframecount_gb counter reaches half of the maximum value or the maximum value."]
pub type RxgbfrmimW<'a, REG> = crate::BitWriter<'a, REG, Rxgbfrmim>;
impl<'a, REG> RxgbfrmimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxgbfrmim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxgbfrmim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxoctetcount_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxgboctim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxgboctim> for bool {
    #[inline(always)]
    fn from(variant: Rxgboctim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxgboctim` reader - Setting this bit masks the interrupt when the rxoctetcount_gb counter reaches half of the maximum value or the maximum value."]
pub type RxgboctimR = crate::BitReader<Rxgboctim>;
impl RxgboctimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxgboctim {
        match self.bits {
            false => Rxgboctim::Nomaskintr,
            true => Rxgboctim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxgboctim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxgboctim::Maskintr
    }
}
#[doc = "Field `rxgboctim` writer - Setting this bit masks the interrupt when the rxoctetcount_gb counter reaches half of the maximum value or the maximum value."]
pub type RxgboctimW<'a, REG> = crate::BitWriter<'a, REG, Rxgboctim>;
impl<'a, REG> RxgboctimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxgboctim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxgboctim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxoctetcount_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxgoctim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxgoctim> for bool {
    #[inline(always)]
    fn from(variant: Rxgoctim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxgoctim` reader - Setting this bit masks the interrupt when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type RxgoctimR = crate::BitReader<Rxgoctim>;
impl RxgoctimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxgoctim {
        match self.bits {
            false => Rxgoctim::Nomaskintr,
            true => Rxgoctim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxgoctim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxgoctim::Maskintr
    }
}
#[doc = "Field `rxgoctim` writer - Setting this bit masks the interrupt when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type RxgoctimW<'a, REG> = crate::BitWriter<'a, REG, Rxgoctim>;
impl<'a, REG> RxgoctimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxgoctim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxgoctim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxbcgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxbcgfim> for bool {
    #[inline(always)]
    fn from(variant: Rxbcgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxbcgfim` reader - Setting this bit masks the interrupt when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxbcgfimR = crate::BitReader<Rxbcgfim>;
impl RxbcgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxbcgfim {
        match self.bits {
            false => Rxbcgfim::Nomaskintr,
            true => Rxbcgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxbcgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxbcgfim::Maskintr
    }
}
#[doc = "Field `rxbcgfim` writer - Setting this bit masks the interrupt when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxbcgfimW<'a, REG> = crate::BitWriter<'a, REG, Rxbcgfim>;
impl<'a, REG> RxbcgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxbcgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxbcgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxmcgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxmcgfim> for bool {
    #[inline(always)]
    fn from(variant: Rxmcgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxmcgfim` reader - Setting this bit masks the interrupt when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxmcgfimR = crate::BitReader<Rxmcgfim>;
impl RxmcgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxmcgfim {
        match self.bits {
            false => Rxmcgfim::Nomaskintr,
            true => Rxmcgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxmcgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxmcgfim::Maskintr
    }
}
#[doc = "Field `rxmcgfim` writer - Setting this bit masks the interrupt when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxmcgfimW<'a, REG> = crate::BitWriter<'a, REG, Rxmcgfim>;
impl<'a, REG> RxmcgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxmcgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxmcgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxcrcerror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxcrcerfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxcrcerfim> for bool {
    #[inline(always)]
    fn from(variant: Rxcrcerfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxcrcerfim` reader - Setting this bit masks the interrupt when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
pub type RxcrcerfimR = crate::BitReader<Rxcrcerfim>;
impl RxcrcerfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxcrcerfim {
        match self.bits {
            false => Rxcrcerfim::Nomaskintr,
            true => Rxcrcerfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxcrcerfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxcrcerfim::Maskintr
    }
}
#[doc = "Field `rxcrcerfim` writer - Setting this bit masks the interrupt when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
pub type RxcrcerfimW<'a, REG> = crate::BitWriter<'a, REG, Rxcrcerfim>;
impl<'a, REG> RxcrcerfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxcrcerfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxcrcerfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxalignmenterror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxalgnerfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxalgnerfim> for bool {
    #[inline(always)]
    fn from(variant: Rxalgnerfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxalgnerfim` reader - Setting this bit masks the interrupt when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
pub type RxalgnerfimR = crate::BitReader<Rxalgnerfim>;
impl RxalgnerfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxalgnerfim {
        match self.bits {
            false => Rxalgnerfim::Nomaskintr,
            true => Rxalgnerfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxalgnerfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxalgnerfim::Maskintr
    }
}
#[doc = "Field `rxalgnerfim` writer - Setting this bit masks the interrupt when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
pub type RxalgnerfimW<'a, REG> = crate::BitWriter<'a, REG, Rxalgnerfim>;
impl<'a, REG> RxalgnerfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxalgnerfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxalgnerfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxrunterror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxruntfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxruntfim> for bool {
    #[inline(always)]
    fn from(variant: Rxruntfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxruntfim` reader - Setting this bit masks the interrupt when the rxrunterror counter reaches half of the maximum value or the maximum value."]
pub type RxruntfimR = crate::BitReader<Rxruntfim>;
impl RxruntfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxruntfim {
        match self.bits {
            false => Rxruntfim::Nomaskintr,
            true => Rxruntfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxruntfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxruntfim::Maskintr
    }
}
#[doc = "Field `rxruntfim` writer - Setting this bit masks the interrupt when the rxrunterror counter reaches half of the maximum value or the maximum value."]
pub type RxruntfimW<'a, REG> = crate::BitWriter<'a, REG, Rxruntfim>;
impl<'a, REG> RxruntfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxruntfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxruntfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxjabbererror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxjaberfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxjaberfim> for bool {
    #[inline(always)]
    fn from(variant: Rxjaberfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxjaberfim` reader - Setting this bit masks the interrupt when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
pub type RxjaberfimR = crate::BitReader<Rxjaberfim>;
impl RxjaberfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxjaberfim {
        match self.bits {
            false => Rxjaberfim::Nomaskintr,
            true => Rxjaberfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxjaberfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxjaberfim::Maskintr
    }
}
#[doc = "Field `rxjaberfim` writer - Setting this bit masks the interrupt when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
pub type RxjaberfimW<'a, REG> = crate::BitWriter<'a, REG, Rxjaberfim>;
impl<'a, REG> RxjaberfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxjaberfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxjaberfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxundersize_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxusizegfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxusizegfim> for bool {
    #[inline(always)]
    fn from(variant: Rxusizegfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxusizegfim` reader - Setting this bit masks the interrupt when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
pub type RxusizegfimR = crate::BitReader<Rxusizegfim>;
impl RxusizegfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxusizegfim {
        match self.bits {
            false => Rxusizegfim::Nomaskintr,
            true => Rxusizegfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxusizegfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxusizegfim::Maskintr
    }
}
#[doc = "Field `rxusizegfim` writer - Setting this bit masks the interrupt when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
pub type RxusizegfimW<'a, REG> = crate::BitWriter<'a, REG, Rxusizegfim>;
impl<'a, REG> RxusizegfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxusizegfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxusizegfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxoversize_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxosizegfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxosizegfim> for bool {
    #[inline(always)]
    fn from(variant: Rxosizegfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxosizegfim` reader - Setting this bit masks the interrupt when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
pub type RxosizegfimR = crate::BitReader<Rxosizegfim>;
impl RxosizegfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxosizegfim {
        match self.bits {
            false => Rxosizegfim::Nomaskintr,
            true => Rxosizegfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxosizegfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxosizegfim::Maskintr
    }
}
#[doc = "Field `rxosizegfim` writer - Setting this bit masks the interrupt when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
pub type RxosizegfimW<'a, REG> = crate::BitWriter<'a, REG, Rxosizegfim>;
impl<'a, REG> RxosizegfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxosizegfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxosizegfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rx64octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx64octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rx64octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Rx64octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx64octgbfim` reader - Setting this bit masks the interrupt when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx64octgbfimR = crate::BitReader<Rx64octgbfim>;
impl Rx64octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx64octgbfim {
        match self.bits {
            false => Rx64octgbfim::Nomaskintr,
            true => Rx64octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rx64octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rx64octgbfim::Maskintr
    }
}
#[doc = "Field `rx64octgbfim` writer - Setting this bit masks the interrupt when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx64octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Rx64octgbfim>;
impl<'a, REG> Rx64octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx64octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx64octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx65t127octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rx65t127octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Rx65t127octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx65t127octgbfim` reader - Setting this bit masks the interrupt when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx65t127octgbfimR = crate::BitReader<Rx65t127octgbfim>;
impl Rx65t127octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx65t127octgbfim {
        match self.bits {
            false => Rx65t127octgbfim::Nomaskintr,
            true => Rx65t127octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rx65t127octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rx65t127octgbfim::Maskintr
    }
}
#[doc = "Field `rx65t127octgbfim` writer - Setting this bit masks the interrupt when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx65t127octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Rx65t127octgbfim>;
impl<'a, REG> Rx65t127octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx65t127octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx65t127octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx128t255octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rx128t255octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Rx128t255octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx128t255octgbfim` reader - Setting this bit masks the interrupt when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx128t255octgbfimR = crate::BitReader<Rx128t255octgbfim>;
impl Rx128t255octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx128t255octgbfim {
        match self.bits {
            false => Rx128t255octgbfim::Nomaskintr,
            true => Rx128t255octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rx128t255octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rx128t255octgbfim::Maskintr
    }
}
#[doc = "Field `rx128t255octgbfim` writer - Setting this bit masks the interrupt when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx128t255octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Rx128t255octgbfim>;
impl<'a, REG> Rx128t255octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx128t255octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx128t255octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx256t511octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rx256t511octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Rx256t511octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx256t511octgbfim` reader - Setting this bit masks the interrupt when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx256t511octgbfimR = crate::BitReader<Rx256t511octgbfim>;
impl Rx256t511octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx256t511octgbfim {
        match self.bits {
            false => Rx256t511octgbfim::Nomaskintr,
            true => Rx256t511octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rx256t511octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rx256t511octgbfim::Maskintr
    }
}
#[doc = "Field `rx256t511octgbfim` writer - Setting this bit masks the interrupt when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx256t511octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Rx256t511octgbfim>;
impl<'a, REG> Rx256t511octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx256t511octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx256t511octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx512t1023octgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rx512t1023octgbfim> for bool {
    #[inline(always)]
    fn from(variant: Rx512t1023octgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx512t1023octgbfim` reader - Setting this bit masks the interrupt when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx512t1023octgbfimR = crate::BitReader<Rx512t1023octgbfim>;
impl Rx512t1023octgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx512t1023octgbfim {
        match self.bits {
            false => Rx512t1023octgbfim::Nomaskintr,
            true => Rx512t1023octgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rx512t1023octgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rx512t1023octgbfim::Maskintr
    }
}
#[doc = "Field `rx512t1023octgbfim` writer - Setting this bit masks the interrupt when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx512t1023octgbfimW<'a, REG> = crate::BitWriter<'a, REG, Rx512t1023octgbfim>;
impl<'a, REG> Rx512t1023octgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx512t1023octgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx512t1023octgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx1024tmaxoctgbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rx1024tmaxoctgbfim> for bool {
    #[inline(always)]
    fn from(variant: Rx1024tmaxoctgbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx1024tmaxoctgbfim` reader - Setting this bit masks the interrupt when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx1024tmaxoctgbfimR = crate::BitReader<Rx1024tmaxoctgbfim>;
impl Rx1024tmaxoctgbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx1024tmaxoctgbfim {
        match self.bits {
            false => Rx1024tmaxoctgbfim::Nomaskintr,
            true => Rx1024tmaxoctgbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rx1024tmaxoctgbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rx1024tmaxoctgbfim::Maskintr
    }
}
#[doc = "Field `rx1024tmaxoctgbfim` writer - Setting this bit masks the interrupt when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx1024tmaxoctgbfimW<'a, REG> = crate::BitWriter<'a, REG, Rx1024tmaxoctgbfim>;
impl<'a, REG> Rx1024tmaxoctgbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx1024tmaxoctgbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rx1024tmaxoctgbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxunicastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxucgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxucgfim> for bool {
    #[inline(always)]
    fn from(variant: Rxucgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxucgfim` reader - Setting this bit masks the interrupt when the rxunicastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxucgfimR = crate::BitReader<Rxucgfim>;
impl RxucgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxucgfim {
        match self.bits {
            false => Rxucgfim::Nomaskintr,
            true => Rxucgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxucgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxucgfim::Maskintr
    }
}
#[doc = "Field `rxucgfim` writer - Setting this bit masks the interrupt when the rxunicastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxucgfimW<'a, REG> = crate::BitWriter<'a, REG, Rxucgfim>;
impl<'a, REG> RxucgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxucgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxucgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxlengtherror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxlenerfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxlenerfim> for bool {
    #[inline(always)]
    fn from(variant: Rxlenerfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxlenerfim` reader - Setting this bit masks the interrupt when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
pub type RxlenerfimR = crate::BitReader<Rxlenerfim>;
impl RxlenerfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxlenerfim {
        match self.bits {
            false => Rxlenerfim::Nomaskintr,
            true => Rxlenerfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxlenerfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxlenerfim::Maskintr
    }
}
#[doc = "Field `rxlenerfim` writer - Setting this bit masks the interrupt when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
pub type RxlenerfimW<'a, REG> = crate::BitWriter<'a, REG, Rxlenerfim>;
impl<'a, REG> RxlenerfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxlenerfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxlenerfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxoutofrangetype counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxorangefim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxorangefim> for bool {
    #[inline(always)]
    fn from(variant: Rxorangefim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxorangefim` reader - Setting this bit masks the interrupt when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
pub type RxorangefimR = crate::BitReader<Rxorangefim>;
impl RxorangefimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxorangefim {
        match self.bits {
            false => Rxorangefim::Nomaskintr,
            true => Rxorangefim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxorangefim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxorangefim::Maskintr
    }
}
#[doc = "Field `rxorangefim` writer - Setting this bit masks the interrupt when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
pub type RxorangefimW<'a, REG> = crate::BitWriter<'a, REG, Rxorangefim>;
impl<'a, REG> RxorangefimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxorangefim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxorangefim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxpauseframes counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxpausfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxpausfim> for bool {
    #[inline(always)]
    fn from(variant: Rxpausfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxpausfim` reader - Setting this bit masks the interrupt when the rxpauseframes counter reaches half of the maximum value or the maximum value."]
pub type RxpausfimR = crate::BitReader<Rxpausfim>;
impl RxpausfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxpausfim {
        match self.bits {
            false => Rxpausfim::Nomaskintr,
            true => Rxpausfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxpausfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxpausfim::Maskintr
    }
}
#[doc = "Field `rxpausfim` writer - Setting this bit masks the interrupt when the rxpauseframes counter reaches half of the maximum value or the maximum value."]
pub type RxpausfimW<'a, REG> = crate::BitWriter<'a, REG, Rxpausfim>;
impl<'a, REG> RxpausfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxpausfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxpausfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxfifooverflow counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfovfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxfovfim> for bool {
    #[inline(always)]
    fn from(variant: Rxfovfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfovfim` reader - Setting this bit masks the interrupt when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
pub type RxfovfimR = crate::BitReader<Rxfovfim>;
impl RxfovfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfovfim {
        match self.bits {
            false => Rxfovfim::Nomaskintr,
            true => Rxfovfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxfovfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxfovfim::Maskintr
    }
}
#[doc = "Field `rxfovfim` writer - Setting this bit masks the interrupt when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
pub type RxfovfimW<'a, REG> = crate::BitWriter<'a, REG, Rxfovfim>;
impl<'a, REG> RxfovfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfovfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfovfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxvlangbfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxvlangbfim> for bool {
    #[inline(always)]
    fn from(variant: Rxvlangbfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxvlangbfim` reader - Setting this bit masks the interrupt when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
pub type RxvlangbfimR = crate::BitReader<Rxvlangbfim>;
impl RxvlangbfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxvlangbfim {
        match self.bits {
            false => Rxvlangbfim::Nomaskintr,
            true => Rxvlangbfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxvlangbfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxvlangbfim::Maskintr
    }
}
#[doc = "Field `rxvlangbfim` writer - Setting this bit masks the interrupt when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
pub type RxvlangbfimW<'a, REG> = crate::BitWriter<'a, REG, Rxvlangbfim>;
impl<'a, REG> RxvlangbfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxvlangbfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxvlangbfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxwatchdog counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxwdogfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxwdogfim> for bool {
    #[inline(always)]
    fn from(variant: Rxwdogfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxwdogfim` reader - Setting this bit masks the interrupt when the rxwatchdog counter reaches half of the maximum value or the maximum value."]
pub type RxwdogfimR = crate::BitReader<Rxwdogfim>;
impl RxwdogfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxwdogfim {
        match self.bits {
            false => Rxwdogfim::Nomaskintr,
            true => Rxwdogfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxwdogfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxwdogfim::Maskintr
    }
}
#[doc = "Field `rxwdogfim` writer - Setting this bit masks the interrupt when the rxwatchdog counter reaches half of the maximum value or the maximum value."]
pub type RxwdogfimW<'a, REG> = crate::BitWriter<'a, REG, Rxwdogfim>;
impl<'a, REG> RxwdogfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxwdogfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxwdogfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxrcverror error counter reaches half the maximum value, and also when it reaches the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxrcverrfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxrcverrfim> for bool {
    #[inline(always)]
    fn from(variant: Rxrcverrfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxrcverrfim` reader - Setting this bit masks the interrupt when the rxrcverror error counter reaches half the maximum value, and also when it reaches the maximum value."]
pub type RxrcverrfimR = crate::BitReader<Rxrcverrfim>;
impl RxrcverrfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxrcverrfim {
        match self.bits {
            false => Rxrcverrfim::Nomaskintr,
            true => Rxrcverrfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxrcverrfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxrcverrfim::Maskintr
    }
}
#[doc = "Field `rxrcverrfim` writer - Setting this bit masks the interrupt when the rxrcverror error counter reaches half the maximum value, and also when it reaches the maximum value."]
pub type RxrcverrfimW<'a, REG> = crate::BitWriter<'a, REG, Rxrcverrfim>;
impl<'a, REG> RxrcverrfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxrcverrfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxrcverrfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxctrlframes counter reaches half the maximum value, and also when it reaches the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxctrlfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxctrlfim> for bool {
    #[inline(always)]
    fn from(variant: Rxctrlfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxctrlfim` reader - Setting this bit masks the interrupt when the rxctrlframes counter reaches half the maximum value, and also when it reaches the maximum value."]
pub type RxctrlfimR = crate::BitReader<Rxctrlfim>;
impl RxctrlfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxctrlfim {
        match self.bits {
            false => Rxctrlfim::Nomaskintr,
            true => Rxctrlfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxctrlfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxctrlfim::Maskintr
    }
}
#[doc = "Field `rxctrlfim` writer - Setting this bit masks the interrupt when the rxctrlframes counter reaches half the maximum value, and also when it reaches the maximum value."]
pub type RxctrlfimW<'a, REG> = crate::BitWriter<'a, REG, Rxctrlfim>;
impl<'a, REG> RxctrlfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxctrlfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxctrlfim::Maskintr)
    }
}
impl R {
    #[doc = "Bit 0 - Setting this bit masks the interrupt when the rxframecount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxgbfrmim(&self) -> RxgbfrmimR {
        RxgbfrmimR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Setting this bit masks the interrupt when the rxoctetcount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxgboctim(&self) -> RxgboctimR {
        RxgboctimR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Setting this bit masks the interrupt when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxgoctim(&self) -> RxgoctimR {
        RxgoctimR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Setting this bit masks the interrupt when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxbcgfim(&self) -> RxbcgfimR {
        RxbcgfimR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Setting this bit masks the interrupt when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxmcgfim(&self) -> RxmcgfimR {
        RxmcgfimR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Setting this bit masks the interrupt when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxcrcerfim(&self) -> RxcrcerfimR {
        RxcrcerfimR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Setting this bit masks the interrupt when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxalgnerfim(&self) -> RxalgnerfimR {
        RxalgnerfimR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Setting this bit masks the interrupt when the rxrunterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxruntfim(&self) -> RxruntfimR {
        RxruntfimR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Setting this bit masks the interrupt when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxjaberfim(&self) -> RxjaberfimR {
        RxjaberfimR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Setting this bit masks the interrupt when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxusizegfim(&self) -> RxusizegfimR {
        RxusizegfimR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Setting this bit masks the interrupt when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxosizegfim(&self) -> RxosizegfimR {
        RxosizegfimR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Setting this bit masks the interrupt when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx64octgbfim(&self) -> Rx64octgbfimR {
        Rx64octgbfimR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Setting this bit masks the interrupt when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx65t127octgbfim(&self) -> Rx65t127octgbfimR {
        Rx65t127octgbfimR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Setting this bit masks the interrupt when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx128t255octgbfim(&self) -> Rx128t255octgbfimR {
        Rx128t255octgbfimR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Setting this bit masks the interrupt when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx256t511octgbfim(&self) -> Rx256t511octgbfimR {
        Rx256t511octgbfimR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Setting this bit masks the interrupt when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx512t1023octgbfim(&self) -> Rx512t1023octgbfimR {
        Rx512t1023octgbfimR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Setting this bit masks the interrupt when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx1024tmaxoctgbfim(&self) -> Rx1024tmaxoctgbfimR {
        Rx1024tmaxoctgbfimR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Setting this bit masks the interrupt when the rxunicastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxucgfim(&self) -> RxucgfimR {
        RxucgfimR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Setting this bit masks the interrupt when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxlenerfim(&self) -> RxlenerfimR {
        RxlenerfimR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Setting this bit masks the interrupt when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxorangefim(&self) -> RxorangefimR {
        RxorangefimR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Setting this bit masks the interrupt when the rxpauseframes counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxpausfim(&self) -> RxpausfimR {
        RxpausfimR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Setting this bit masks the interrupt when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxfovfim(&self) -> RxfovfimR {
        RxfovfimR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Setting this bit masks the interrupt when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxvlangbfim(&self) -> RxvlangbfimR {
        RxvlangbfimR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Setting this bit masks the interrupt when the rxwatchdog counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxwdogfim(&self) -> RxwdogfimR {
        RxwdogfimR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Setting this bit masks the interrupt when the rxrcverror error counter reaches half the maximum value, and also when it reaches the maximum value."]
    #[inline(always)]
    pub fn rxrcverrfim(&self) -> RxrcverrfimR {
        RxrcverrfimR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Setting this bit masks the interrupt when the rxctrlframes counter reaches half the maximum value, and also when it reaches the maximum value."]
    #[inline(always)]
    pub fn rxctrlfim(&self) -> RxctrlfimR {
        RxctrlfimR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Setting this bit masks the interrupt when the rxframecount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxgbfrmim(&mut self) -> RxgbfrmimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxgbfrmimW::new(self, 0)
    }
    #[doc = "Bit 1 - Setting this bit masks the interrupt when the rxoctetcount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxgboctim(&mut self) -> RxgboctimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxgboctimW::new(self, 1)
    }
    #[doc = "Bit 2 - Setting this bit masks the interrupt when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxgoctim(&mut self) -> RxgoctimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxgoctimW::new(self, 2)
    }
    #[doc = "Bit 3 - Setting this bit masks the interrupt when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxbcgfim(&mut self) -> RxbcgfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxbcgfimW::new(self, 3)
    }
    #[doc = "Bit 4 - Setting this bit masks the interrupt when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxmcgfim(&mut self) -> RxmcgfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxmcgfimW::new(self, 4)
    }
    #[doc = "Bit 5 - Setting this bit masks the interrupt when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxcrcerfim(&mut self) -> RxcrcerfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxcrcerfimW::new(self, 5)
    }
    #[doc = "Bit 6 - Setting this bit masks the interrupt when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxalgnerfim(&mut self) -> RxalgnerfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxalgnerfimW::new(self, 6)
    }
    #[doc = "Bit 7 - Setting this bit masks the interrupt when the rxrunterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxruntfim(&mut self) -> RxruntfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxruntfimW::new(self, 7)
    }
    #[doc = "Bit 8 - Setting this bit masks the interrupt when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxjaberfim(&mut self) -> RxjaberfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxjaberfimW::new(self, 8)
    }
    #[doc = "Bit 9 - Setting this bit masks the interrupt when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxusizegfim(&mut self) -> RxusizegfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxusizegfimW::new(self, 9)
    }
    #[doc = "Bit 10 - Setting this bit masks the interrupt when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxosizegfim(&mut self) -> RxosizegfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxosizegfimW::new(self, 10)
    }
    #[doc = "Bit 11 - Setting this bit masks the interrupt when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx64octgbfim(&mut self) -> Rx64octgbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        Rx64octgbfimW::new(self, 11)
    }
    #[doc = "Bit 12 - Setting this bit masks the interrupt when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx65t127octgbfim(&mut self) -> Rx65t127octgbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        Rx65t127octgbfimW::new(self, 12)
    }
    #[doc = "Bit 13 - Setting this bit masks the interrupt when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx128t255octgbfim(&mut self) -> Rx128t255octgbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        Rx128t255octgbfimW::new(self, 13)
    }
    #[doc = "Bit 14 - Setting this bit masks the interrupt when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx256t511octgbfim(&mut self) -> Rx256t511octgbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        Rx256t511octgbfimW::new(self, 14)
    }
    #[doc = "Bit 15 - Setting this bit masks the interrupt when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx512t1023octgbfim(
        &mut self,
    ) -> Rx512t1023octgbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        Rx512t1023octgbfimW::new(self, 15)
    }
    #[doc = "Bit 16 - Setting this bit masks the interrupt when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx1024tmaxoctgbfim(
        &mut self,
    ) -> Rx1024tmaxoctgbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        Rx1024tmaxoctgbfimW::new(self, 16)
    }
    #[doc = "Bit 17 - Setting this bit masks the interrupt when the rxunicastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxucgfim(&mut self) -> RxucgfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxucgfimW::new(self, 17)
    }
    #[doc = "Bit 18 - Setting this bit masks the interrupt when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxlenerfim(&mut self) -> RxlenerfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxlenerfimW::new(self, 18)
    }
    #[doc = "Bit 19 - Setting this bit masks the interrupt when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxorangefim(&mut self) -> RxorangefimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxorangefimW::new(self, 19)
    }
    #[doc = "Bit 20 - Setting this bit masks the interrupt when the rxpauseframes counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxpausfim(&mut self) -> RxpausfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxpausfimW::new(self, 20)
    }
    #[doc = "Bit 21 - Setting this bit masks the interrupt when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxfovfim(&mut self) -> RxfovfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxfovfimW::new(self, 21)
    }
    #[doc = "Bit 22 - Setting this bit masks the interrupt when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxvlangbfim(&mut self) -> RxvlangbfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxvlangbfimW::new(self, 22)
    }
    #[doc = "Bit 23 - Setting this bit masks the interrupt when the rxwatchdog counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxwdogfim(&mut self) -> RxwdogfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxwdogfimW::new(self, 23)
    }
    #[doc = "Bit 24 - Setting this bit masks the interrupt when the rxrcverror error counter reaches half the maximum value, and also when it reaches the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxrcverrfim(&mut self) -> RxrcverrfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxrcverrfimW::new(self, 24)
    }
    #[doc = "Bit 25 - Setting this bit masks the interrupt when the rxctrlframes counter reaches half the maximum value, and also when it reaches the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxctrlfim(&mut self) -> RxctrlfimW<GmacgrpMmcReceiveInterruptMaskSpec> {
        RxctrlfimW::new(self, 25)
    }
}
#[doc = "The MMC Receive Interrupt Mask register maintains the masks for the interrupts generated when the receive statistic counters reach half of their maximum value, or maximum value. This register is 32-bits wide.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_receive_interrupt_mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_receive_interrupt_mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcReceiveInterruptMaskSpec;
impl crate::RegisterSpec for GmacgrpMmcReceiveInterruptMaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 268u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_receive_interrupt_mask::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcReceiveInterruptMaskSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mmc_receive_interrupt_mask::W`](W) writer structure"]
impl crate::Writable for GmacgrpMmcReceiveInterruptMaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MMC_Receive_Interrupt_Mask to value 0"]
impl crate::Resettable for GmacgrpMmcReceiveInterruptMaskSpec {
    const RESET_VALUE: u32 = 0;
}
