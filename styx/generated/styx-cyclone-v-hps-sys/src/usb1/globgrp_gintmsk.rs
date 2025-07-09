// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_gintmsk` reader"]
pub type R = crate::R<GlobgrpGintmskSpec>;
#[doc = "Register `globgrp_gintmsk` writer"]
pub type W = crate::W<GlobgrpGintmskSpec>;
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modemismsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Modemismsk> for bool {
    #[inline(always)]
    fn from(variant: Modemismsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `modemismsk` reader - Mode: Host and Device."]
pub type ModemismskR = crate::BitReader<Modemismsk>;
impl ModemismskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Modemismsk {
        match self.bits {
            false => Modemismsk::Mask,
            true => Modemismsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Modemismsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Modemismsk::Nomask
    }
}
#[doc = "Field `modemismsk` writer - Mode: Host and Device."]
pub type ModemismskW<'a, REG> = crate::BitWriter<'a, REG, Modemismsk>;
impl<'a, REG> ModemismskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Modemismsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Modemismsk::Nomask)
    }
}
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Otgintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Otgintmsk> for bool {
    #[inline(always)]
    fn from(variant: Otgintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `otgintmsk` reader - Mode: Host and Device."]
pub type OtgintmskR = crate::BitReader<Otgintmsk>;
impl OtgintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Otgintmsk {
        match self.bits {
            false => Otgintmsk::Mask,
            true => Otgintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Otgintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Otgintmsk::Nomask
    }
}
#[doc = "Field `otgintmsk` writer - Mode: Host and Device."]
pub type OtgintmskW<'a, REG> = crate::BitWriter<'a, REG, Otgintmsk>;
impl<'a, REG> OtgintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Otgintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Otgintmsk::Nomask)
    }
}
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sofmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Sofmsk> for bool {
    #[inline(always)]
    fn from(variant: Sofmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sofmsk` reader - Mode: Host and Device."]
pub type SofmskR = crate::BitReader<Sofmsk>;
impl SofmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sofmsk {
        match self.bits {
            false => Sofmsk::Mask,
            true => Sofmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Sofmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Sofmsk::Nomask
    }
}
#[doc = "Field `sofmsk` writer - Mode: Host and Device."]
pub type SofmskW<'a, REG> = crate::BitWriter<'a, REG, Sofmsk>;
impl<'a, REG> SofmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Sofmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Sofmsk::Nomask)
    }
}
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxflvlmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Rxflvlmsk> for bool {
    #[inline(always)]
    fn from(variant: Rxflvlmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxflvlmsk` reader - Mode: Host and Device."]
pub type RxflvlmskR = crate::BitReader<Rxflvlmsk>;
impl RxflvlmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxflvlmsk {
        match self.bits {
            false => Rxflvlmsk::Mask,
            true => Rxflvlmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Rxflvlmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Rxflvlmsk::Nomask
    }
}
#[doc = "Field `rxflvlmsk` writer - Mode: Host and Device."]
pub type RxflvlmskW<'a, REG> = crate::BitWriter<'a, REG, Rxflvlmsk>;
impl<'a, REG> RxflvlmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Rxflvlmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Rxflvlmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ginnakeffmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ginnakeffmsk> for bool {
    #[inline(always)]
    fn from(variant: Ginnakeffmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ginnakeffmsk` reader - Mode: Device only."]
pub type GinnakeffmskR = crate::BitReader<Ginnakeffmsk>;
impl GinnakeffmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ginnakeffmsk {
        match self.bits {
            false => Ginnakeffmsk::Mask,
            true => Ginnakeffmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ginnakeffmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ginnakeffmsk::Nomask
    }
}
#[doc = "Field `ginnakeffmsk` writer - Mode: Device only."]
pub type GinnakeffmskW<'a, REG> = crate::BitWriter<'a, REG, Ginnakeffmsk>;
impl<'a, REG> GinnakeffmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ginnakeffmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ginnakeffmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Goutnakeffmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomaks = 1,
}
impl From<Goutnakeffmsk> for bool {
    #[inline(always)]
    fn from(variant: Goutnakeffmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `goutnakeffmsk` reader - Mode: Device only."]
pub type GoutnakeffmskR = crate::BitReader<Goutnakeffmsk>;
impl GoutnakeffmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Goutnakeffmsk {
        match self.bits {
            false => Goutnakeffmsk::Mask,
            true => Goutnakeffmsk::Nomaks,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Goutnakeffmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomaks(&self) -> bool {
        *self == Goutnakeffmsk::Nomaks
    }
}
#[doc = "Field `goutnakeffmsk` writer - Mode: Device only."]
pub type GoutnakeffmskW<'a, REG> = crate::BitWriter<'a, REG, Goutnakeffmsk>;
impl<'a, REG> GoutnakeffmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Goutnakeffmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomaks(self) -> &'a mut crate::W<REG> {
        self.variant(Goutnakeffmsk::Nomaks)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erlysuspmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Erlysuspmsk> for bool {
    #[inline(always)]
    fn from(variant: Erlysuspmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `erlysuspmsk` reader - Mode: Device only."]
pub type ErlysuspmskR = crate::BitReader<Erlysuspmsk>;
impl ErlysuspmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Erlysuspmsk {
        match self.bits {
            false => Erlysuspmsk::Mask,
            true => Erlysuspmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Erlysuspmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Erlysuspmsk::Nomask
    }
}
#[doc = "Field `erlysuspmsk` writer - Mode: Device only."]
pub type ErlysuspmskW<'a, REG> = crate::BitWriter<'a, REG, Erlysuspmsk>;
impl<'a, REG> ErlysuspmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Erlysuspmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Erlysuspmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbsuspmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Usbsuspmsk> for bool {
    #[inline(always)]
    fn from(variant: Usbsuspmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbsuspmsk` reader - Mode: Device only."]
pub type UsbsuspmskR = crate::BitReader<Usbsuspmsk>;
impl UsbsuspmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usbsuspmsk {
        match self.bits {
            false => Usbsuspmsk::Mask,
            true => Usbsuspmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Usbsuspmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Usbsuspmsk::Nomask
    }
}
#[doc = "Field `usbsuspmsk` writer - Mode: Device only."]
pub type UsbsuspmskW<'a, REG> = crate::BitWriter<'a, REG, Usbsuspmsk>;
impl<'a, REG> UsbsuspmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Usbsuspmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Usbsuspmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbrstmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Usbrstmsk> for bool {
    #[inline(always)]
    fn from(variant: Usbrstmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbrstmsk` reader - Mode: Device only."]
pub type UsbrstmskR = crate::BitReader<Usbrstmsk>;
impl UsbrstmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usbrstmsk {
        match self.bits {
            false => Usbrstmsk::Mask,
            true => Usbrstmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Usbrstmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Usbrstmsk::Nomask
    }
}
#[doc = "Field `usbrstmsk` writer - Mode: Device only."]
pub type UsbrstmskW<'a, REG> = crate::BitWriter<'a, REG, Usbrstmsk>;
impl<'a, REG> UsbrstmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Usbrstmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Usbrstmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enumdonemsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Enumdonemsk> for bool {
    #[inline(always)]
    fn from(variant: Enumdonemsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enumdonemsk` reader - Mode: Device only."]
pub type EnumdonemskR = crate::BitReader<Enumdonemsk>;
impl EnumdonemskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enumdonemsk {
        match self.bits {
            false => Enumdonemsk::Mask,
            true => Enumdonemsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Enumdonemsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Enumdonemsk::Nomask
    }
}
#[doc = "Field `enumdonemsk` writer - Mode: Device only."]
pub type EnumdonemskW<'a, REG> = crate::BitWriter<'a, REG, Enumdonemsk>;
impl<'a, REG> EnumdonemskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Enumdonemsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Enumdonemsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isooutdropmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Isooutdropmsk> for bool {
    #[inline(always)]
    fn from(variant: Isooutdropmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `isooutdropmsk` reader - Mode: Device only."]
pub type IsooutdropmskR = crate::BitReader<Isooutdropmsk>;
impl IsooutdropmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Isooutdropmsk {
        match self.bits {
            false => Isooutdropmsk::Mask,
            true => Isooutdropmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Isooutdropmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Isooutdropmsk::Nomask
    }
}
#[doc = "Field `isooutdropmsk` writer - Mode: Device only."]
pub type IsooutdropmskW<'a, REG> = crate::BitWriter<'a, REG, Isooutdropmsk>;
impl<'a, REG> IsooutdropmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Isooutdropmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Isooutdropmsk::Nomask)
    }
}
#[doc = "Mode: Device only. End of Periodic Frame Interrupt Mask (EOPFMsk)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eopfmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Eopfmsk> for bool {
    #[inline(always)]
    fn from(variant: Eopfmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `eopfmsk` reader - Mode: Device only. End of Periodic Frame Interrupt Mask (EOPFMsk)"]
pub type EopfmskR = crate::BitReader<Eopfmsk>;
impl EopfmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eopfmsk {
        match self.bits {
            false => Eopfmsk::Mask,
            true => Eopfmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Eopfmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Eopfmsk::Nomask
    }
}
#[doc = "Field `eopfmsk` writer - Mode: Device only. End of Periodic Frame Interrupt Mask (EOPFMsk)"]
pub type EopfmskW<'a, REG> = crate::BitWriter<'a, REG, Eopfmsk>;
impl<'a, REG> EopfmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Eopfmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Eopfmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epmismsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Epmismsk> for bool {
    #[inline(always)]
    fn from(variant: Epmismsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epmismsk` reader - Mode: Device only."]
pub type EpmismskR = crate::BitReader<Epmismsk>;
impl EpmismskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epmismsk {
        match self.bits {
            false => Epmismsk::Mask,
            true => Epmismsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Epmismsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Epmismsk::Nomask
    }
}
#[doc = "Field `epmismsk` writer - Mode: Device only."]
pub type EpmismskW<'a, REG> = crate::BitWriter<'a, REG, Epmismsk>;
impl<'a, REG> EpmismskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Epmismsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Epmismsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Iepintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomaks = 1,
}
impl From<Iepintmsk> for bool {
    #[inline(always)]
    fn from(variant: Iepintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `iepintmsk` reader - Mode: Device only."]
pub type IepintmskR = crate::BitReader<Iepintmsk>;
impl IepintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Iepintmsk {
        match self.bits {
            false => Iepintmsk::Mask,
            true => Iepintmsk::Nomaks,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Iepintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomaks(&self) -> bool {
        *self == Iepintmsk::Nomaks
    }
}
#[doc = "Field `iepintmsk` writer - Mode: Device only."]
pub type IepintmskW<'a, REG> = crate::BitWriter<'a, REG, Iepintmsk>;
impl<'a, REG> IepintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Iepintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomaks(self) -> &'a mut crate::W<REG> {
        self.variant(Iepintmsk::Nomaks)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oepintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Oepintmsk> for bool {
    #[inline(always)]
    fn from(variant: Oepintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `oepintmsk` reader - Mode: Device only."]
pub type OepintmskR = crate::BitReader<Oepintmsk>;
impl OepintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Oepintmsk {
        match self.bits {
            false => Oepintmsk::Mask,
            true => Oepintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Oepintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Oepintmsk::Nomask
    }
}
#[doc = "Field `oepintmsk` writer - Mode: Device only."]
pub type OepintmskW<'a, REG> = crate::BitWriter<'a, REG, Oepintmsk>;
impl<'a, REG> OepintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Oepintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Oepintmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incompisoinmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Incompisoinmsk> for bool {
    #[inline(always)]
    fn from(variant: Incompisoinmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `incompisoinmsk` reader - Mode: Device only."]
pub type IncompisoinmskR = crate::BitReader<Incompisoinmsk>;
impl IncompisoinmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Incompisoinmsk {
        match self.bits {
            false => Incompisoinmsk::Mask,
            true => Incompisoinmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Incompisoinmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Incompisoinmsk::Nomask
    }
}
#[doc = "Field `incompisoinmsk` writer - Mode: Device only."]
pub type IncompisoinmskW<'a, REG> = crate::BitWriter<'a, REG, Incompisoinmsk>;
impl<'a, REG> IncompisoinmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Incompisoinmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Incompisoinmsk::Nomask)
    }
}
#[doc = "Mode: Host only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incomplpmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Incomplpmsk> for bool {
    #[inline(always)]
    fn from(variant: Incomplpmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `incomplpmsk` reader - Mode: Host only."]
pub type IncomplpmskR = crate::BitReader<Incomplpmsk>;
impl IncomplpmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Incomplpmsk {
        match self.bits {
            false => Incomplpmsk::Mask,
            true => Incomplpmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Incomplpmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Incomplpmsk::Nomask
    }
}
#[doc = "Field `incomplpmsk` writer - Mode: Host only."]
pub type IncomplpmskW<'a, REG> = crate::BitWriter<'a, REG, Incomplpmsk>;
impl<'a, REG> IncomplpmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Incomplpmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Incomplpmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetsuspmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Fetsuspmsk> for bool {
    #[inline(always)]
    fn from(variant: Fetsuspmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fetsuspmsk` reader - Mode: Device only."]
pub type FetsuspmskR = crate::BitReader<Fetsuspmsk>;
impl FetsuspmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fetsuspmsk {
        match self.bits {
            false => Fetsuspmsk::Mask,
            true => Fetsuspmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Fetsuspmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Fetsuspmsk::Nomask
    }
}
#[doc = "Field `fetsuspmsk` writer - Mode: Device only."]
pub type FetsuspmskW<'a, REG> = crate::BitWriter<'a, REG, Fetsuspmsk>;
impl<'a, REG> FetsuspmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Fetsuspmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Fetsuspmsk::Nomask)
    }
}
#[doc = "Mode: Device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resetdetmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Resetdetmsk> for bool {
    #[inline(always)]
    fn from(variant: Resetdetmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `resetdetmsk` reader - Mode: Device only."]
pub type ResetdetmskR = crate::BitReader<Resetdetmsk>;
impl ResetdetmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Resetdetmsk {
        match self.bits {
            false => Resetdetmsk::Mask,
            true => Resetdetmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Resetdetmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Resetdetmsk::Nomask
    }
}
#[doc = "Field `resetdetmsk` writer - Mode: Device only."]
pub type ResetdetmskW<'a, REG> = crate::BitWriter<'a, REG, Resetdetmsk>;
impl<'a, REG> ResetdetmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Resetdetmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Resetdetmsk::Nomask)
    }
}
#[doc = "Mode: Host only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Prtintmsk> for bool {
    #[inline(always)]
    fn from(variant: Prtintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtintmsk` reader - Mode: Host only."]
pub type PrtintmskR = crate::BitReader<Prtintmsk>;
impl PrtintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtintmsk {
        match self.bits {
            false => Prtintmsk::Mask,
            true => Prtintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Prtintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Prtintmsk::Nomask
    }
}
#[doc = "Field `prtintmsk` writer - Mode: Host only."]
pub type PrtintmskW<'a, REG> = crate::BitWriter<'a, REG, Prtintmsk>;
impl<'a, REG> PrtintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Prtintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Prtintmsk::Nomask)
    }
}
#[doc = "Mode: Host only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hchintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Hchintmsk> for bool {
    #[inline(always)]
    fn from(variant: Hchintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hchintmsk` reader - Mode: Host only."]
pub type HchintmskR = crate::BitReader<Hchintmsk>;
impl HchintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hchintmsk {
        match self.bits {
            false => Hchintmsk::Mask,
            true => Hchintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Hchintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Hchintmsk::Nomask
    }
}
#[doc = "Field `hchintmsk` writer - Mode: Host only."]
pub type HchintmskW<'a, REG> = crate::BitWriter<'a, REG, Hchintmsk>;
impl<'a, REG> HchintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Hchintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Hchintmsk::Nomask)
    }
}
#[doc = "Mode: Host only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ptxfempmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ptxfempmsk> for bool {
    #[inline(always)]
    fn from(variant: Ptxfempmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ptxfempmsk` reader - Mode: Host only."]
pub type PtxfempmskR = crate::BitReader<Ptxfempmsk>;
impl PtxfempmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ptxfempmsk {
        match self.bits {
            false => Ptxfempmsk::Mask,
            true => Ptxfempmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ptxfempmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ptxfempmsk::Nomask
    }
}
#[doc = "Field `ptxfempmsk` writer - Mode: Host only."]
pub type PtxfempmskW<'a, REG> = crate::BitWriter<'a, REG, Ptxfempmsk>;
impl<'a, REG> PtxfempmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ptxfempmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ptxfempmsk::Nomask)
    }
}
#[doc = "Mode: Host and Device. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conidstschngmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Conidstschngmsk> for bool {
    #[inline(always)]
    fn from(variant: Conidstschngmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `conidstschngmsk` reader - Mode: Host and Device. This bit can be set only by the core and the application should write 1 to clear it."]
pub type ConidstschngmskR = crate::BitReader<Conidstschngmsk>;
impl ConidstschngmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Conidstschngmsk {
        match self.bits {
            false => Conidstschngmsk::Mask,
            true => Conidstschngmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Conidstschngmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Conidstschngmsk::Nomask
    }
}
#[doc = "Field `conidstschngmsk` writer - Mode: Host and Device. This bit can be set only by the core and the application should write 1 to clear it."]
pub type ConidstschngmskW<'a, REG> = crate::BitWriter<'a, REG, Conidstschngmsk>;
impl<'a, REG> ConidstschngmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Conidstschngmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Conidstschngmsk::Nomask)
    }
}
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disconnintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Disconnintmsk> for bool {
    #[inline(always)]
    fn from(variant: Disconnintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `disconnintmsk` reader - Mode: Host and Device."]
pub type DisconnintmskR = crate::BitReader<Disconnintmsk>;
impl DisconnintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Disconnintmsk {
        match self.bits {
            false => Disconnintmsk::Mask,
            true => Disconnintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Disconnintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Disconnintmsk::Nomask
    }
}
#[doc = "Field `disconnintmsk` writer - Mode: Host and Device."]
pub type DisconnintmskW<'a, REG> = crate::BitWriter<'a, REG, Disconnintmsk>;
impl<'a, REG> DisconnintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Disconnintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Disconnintmsk::Nomask)
    }
}
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sessreqintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Sessreqintmsk> for bool {
    #[inline(always)]
    fn from(variant: Sessreqintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sessreqintmsk` reader - Mode: Host and Device."]
pub type SessreqintmskR = crate::BitReader<Sessreqintmsk>;
impl SessreqintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sessreqintmsk {
        match self.bits {
            false => Sessreqintmsk::Mask,
            true => Sessreqintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Sessreqintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Sessreqintmsk::Nomask
    }
}
#[doc = "Field `sessreqintmsk` writer - Mode: Host and Device."]
pub type SessreqintmskW<'a, REG> = crate::BitWriter<'a, REG, Sessreqintmsk>;
impl<'a, REG> SessreqintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Sessreqintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Sessreqintmsk::Nomask)
    }
}
#[doc = "Mode: Host and Device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wkupintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Wkupintmsk> for bool {
    #[inline(always)]
    fn from(variant: Wkupintmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wkupintmsk` reader - Mode: Host and Device."]
pub type WkupintmskR = crate::BitReader<Wkupintmsk>;
impl WkupintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wkupintmsk {
        match self.bits {
            false => Wkupintmsk::Mask,
            true => Wkupintmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Wkupintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Wkupintmsk::Nomask
    }
}
#[doc = "Field `wkupintmsk` writer - Mode: Host and Device."]
pub type WkupintmskW<'a, REG> = crate::BitWriter<'a, REG, Wkupintmsk>;
impl<'a, REG> WkupintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Wkupintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Wkupintmsk::Nomask)
    }
}
impl R {
    #[doc = "Bit 1 - Mode: Host and Device."]
    #[inline(always)]
    pub fn modemismsk(&self) -> ModemismskR {
        ModemismskR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Mode: Host and Device."]
    #[inline(always)]
    pub fn otgintmsk(&self) -> OtgintmskR {
        OtgintmskR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Mode: Host and Device."]
    #[inline(always)]
    pub fn sofmsk(&self) -> SofmskR {
        SofmskR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Mode: Host and Device."]
    #[inline(always)]
    pub fn rxflvlmsk(&self) -> RxflvlmskR {
        RxflvlmskR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Mode: Device only."]
    #[inline(always)]
    pub fn ginnakeffmsk(&self) -> GinnakeffmskR {
        GinnakeffmskR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Mode: Device only."]
    #[inline(always)]
    pub fn goutnakeffmsk(&self) -> GoutnakeffmskR {
        GoutnakeffmskR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 10 - Mode: Device only."]
    #[inline(always)]
    pub fn erlysuspmsk(&self) -> ErlysuspmskR {
        ErlysuspmskR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Mode: Device only."]
    #[inline(always)]
    pub fn usbsuspmsk(&self) -> UsbsuspmskR {
        UsbsuspmskR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Mode: Device only."]
    #[inline(always)]
    pub fn usbrstmsk(&self) -> UsbrstmskR {
        UsbrstmskR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Mode: Device only."]
    #[inline(always)]
    pub fn enumdonemsk(&self) -> EnumdonemskR {
        EnumdonemskR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Mode: Device only."]
    #[inline(always)]
    pub fn isooutdropmsk(&self) -> IsooutdropmskR {
        IsooutdropmskR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Mode: Device only. End of Periodic Frame Interrupt Mask (EOPFMsk)"]
    #[inline(always)]
    pub fn eopfmsk(&self) -> EopfmskR {
        EopfmskR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - Mode: Device only."]
    #[inline(always)]
    pub fn epmismsk(&self) -> EpmismskR {
        EpmismskR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Mode: Device only."]
    #[inline(always)]
    pub fn iepintmsk(&self) -> IepintmskR {
        IepintmskR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Mode: Device only."]
    #[inline(always)]
    pub fn oepintmsk(&self) -> OepintmskR {
        OepintmskR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Mode: Device only."]
    #[inline(always)]
    pub fn incompisoinmsk(&self) -> IncompisoinmskR {
        IncompisoinmskR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Mode: Host only."]
    #[inline(always)]
    pub fn incomplpmsk(&self) -> IncomplpmskR {
        IncomplpmskR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Mode: Device only."]
    #[inline(always)]
    pub fn fetsuspmsk(&self) -> FetsuspmskR {
        FetsuspmskR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Mode: Device only."]
    #[inline(always)]
    pub fn resetdetmsk(&self) -> ResetdetmskR {
        ResetdetmskR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Mode: Host only."]
    #[inline(always)]
    pub fn prtintmsk(&self) -> PrtintmskR {
        PrtintmskR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Mode: Host only."]
    #[inline(always)]
    pub fn hchintmsk(&self) -> HchintmskR {
        HchintmskR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Mode: Host only."]
    #[inline(always)]
    pub fn ptxfempmsk(&self) -> PtxfempmskR {
        PtxfempmskR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Mode: Host and Device. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn conidstschngmsk(&self) -> ConidstschngmskR {
        ConidstschngmskR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Mode: Host and Device."]
    #[inline(always)]
    pub fn disconnintmsk(&self) -> DisconnintmskR {
        DisconnintmskR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Mode: Host and Device."]
    #[inline(always)]
    pub fn sessreqintmsk(&self) -> SessreqintmskR {
        SessreqintmskR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Mode: Host and Device."]
    #[inline(always)]
    pub fn wkupintmsk(&self) -> WkupintmskR {
        WkupintmskR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn modemismsk(&mut self) -> ModemismskW<GlobgrpGintmskSpec> {
        ModemismskW::new(self, 1)
    }
    #[doc = "Bit 2 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn otgintmsk(&mut self) -> OtgintmskW<GlobgrpGintmskSpec> {
        OtgintmskW::new(self, 2)
    }
    #[doc = "Bit 3 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn sofmsk(&mut self) -> SofmskW<GlobgrpGintmskSpec> {
        SofmskW::new(self, 3)
    }
    #[doc = "Bit 4 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn rxflvlmsk(&mut self) -> RxflvlmskW<GlobgrpGintmskSpec> {
        RxflvlmskW::new(self, 4)
    }
    #[doc = "Bit 6 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn ginnakeffmsk(&mut self) -> GinnakeffmskW<GlobgrpGintmskSpec> {
        GinnakeffmskW::new(self, 6)
    }
    #[doc = "Bit 7 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn goutnakeffmsk(&mut self) -> GoutnakeffmskW<GlobgrpGintmskSpec> {
        GoutnakeffmskW::new(self, 7)
    }
    #[doc = "Bit 10 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn erlysuspmsk(&mut self) -> ErlysuspmskW<GlobgrpGintmskSpec> {
        ErlysuspmskW::new(self, 10)
    }
    #[doc = "Bit 11 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn usbsuspmsk(&mut self) -> UsbsuspmskW<GlobgrpGintmskSpec> {
        UsbsuspmskW::new(self, 11)
    }
    #[doc = "Bit 12 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn usbrstmsk(&mut self) -> UsbrstmskW<GlobgrpGintmskSpec> {
        UsbrstmskW::new(self, 12)
    }
    #[doc = "Bit 13 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn enumdonemsk(&mut self) -> EnumdonemskW<GlobgrpGintmskSpec> {
        EnumdonemskW::new(self, 13)
    }
    #[doc = "Bit 14 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn isooutdropmsk(&mut self) -> IsooutdropmskW<GlobgrpGintmskSpec> {
        IsooutdropmskW::new(self, 14)
    }
    #[doc = "Bit 15 - Mode: Device only. End of Periodic Frame Interrupt Mask (EOPFMsk)"]
    #[inline(always)]
    #[must_use]
    pub fn eopfmsk(&mut self) -> EopfmskW<GlobgrpGintmskSpec> {
        EopfmskW::new(self, 15)
    }
    #[doc = "Bit 17 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn epmismsk(&mut self) -> EpmismskW<GlobgrpGintmskSpec> {
        EpmismskW::new(self, 17)
    }
    #[doc = "Bit 18 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn iepintmsk(&mut self) -> IepintmskW<GlobgrpGintmskSpec> {
        IepintmskW::new(self, 18)
    }
    #[doc = "Bit 19 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn oepintmsk(&mut self) -> OepintmskW<GlobgrpGintmskSpec> {
        OepintmskW::new(self, 19)
    }
    #[doc = "Bit 20 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn incompisoinmsk(&mut self) -> IncompisoinmskW<GlobgrpGintmskSpec> {
        IncompisoinmskW::new(self, 20)
    }
    #[doc = "Bit 21 - Mode: Host only."]
    #[inline(always)]
    #[must_use]
    pub fn incomplpmsk(&mut self) -> IncomplpmskW<GlobgrpGintmskSpec> {
        IncomplpmskW::new(self, 21)
    }
    #[doc = "Bit 22 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn fetsuspmsk(&mut self) -> FetsuspmskW<GlobgrpGintmskSpec> {
        FetsuspmskW::new(self, 22)
    }
    #[doc = "Bit 23 - Mode: Device only."]
    #[inline(always)]
    #[must_use]
    pub fn resetdetmsk(&mut self) -> ResetdetmskW<GlobgrpGintmskSpec> {
        ResetdetmskW::new(self, 23)
    }
    #[doc = "Bit 24 - Mode: Host only."]
    #[inline(always)]
    #[must_use]
    pub fn prtintmsk(&mut self) -> PrtintmskW<GlobgrpGintmskSpec> {
        PrtintmskW::new(self, 24)
    }
    #[doc = "Bit 25 - Mode: Host only."]
    #[inline(always)]
    #[must_use]
    pub fn hchintmsk(&mut self) -> HchintmskW<GlobgrpGintmskSpec> {
        HchintmskW::new(self, 25)
    }
    #[doc = "Bit 26 - Mode: Host only."]
    #[inline(always)]
    #[must_use]
    pub fn ptxfempmsk(&mut self) -> PtxfempmskW<GlobgrpGintmskSpec> {
        PtxfempmskW::new(self, 26)
    }
    #[doc = "Bit 28 - Mode: Host and Device. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn conidstschngmsk(&mut self) -> ConidstschngmskW<GlobgrpGintmskSpec> {
        ConidstschngmskW::new(self, 28)
    }
    #[doc = "Bit 29 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn disconnintmsk(&mut self) -> DisconnintmskW<GlobgrpGintmskSpec> {
        DisconnintmskW::new(self, 29)
    }
    #[doc = "Bit 30 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn sessreqintmsk(&mut self) -> SessreqintmskW<GlobgrpGintmskSpec> {
        SessreqintmskW::new(self, 30)
    }
    #[doc = "Bit 31 - Mode: Host and Device."]
    #[inline(always)]
    #[must_use]
    pub fn wkupintmsk(&mut self) -> WkupintmskW<GlobgrpGintmskSpec> {
        WkupintmskW::new(self, 31)
    }
}
#[doc = "This register works with the Interrupt Register (GINTSTS) to interrupt the application. When an interrupt bit is masked, the interrupt associated with that bit is not generated. However, the GINTSTS register bit corresponding to that interrupt is still set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGintmskSpec;
impl crate::RegisterSpec for GlobgrpGintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`globgrp_gintmsk::R`](R) reader structure"]
impl crate::Readable for GlobgrpGintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gintmsk::W`](W) writer structure"]
impl crate::Writable for GlobgrpGintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gintmsk to value 0"]
impl crate::Resettable for GlobgrpGintmskSpec {
    const RESET_VALUE: u32 = 0;
}
