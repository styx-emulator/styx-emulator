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
#[doc = "Register `gmacgrp_MAC_Address73_High` reader"]
pub type R = crate::R<GmacgrpMacAddress73HighSpec>;
#[doc = "Register `gmacgrp_MAC_Address73_High` writer"]
pub type W = crate::W<GmacgrpMacAddress73HighSpec>;
#[doc = "Field `addrhi` reader - This field contains the upper 16 bits (47:32) of the 74th 6-byte MAC address."]
pub type AddrhiR = crate::FieldReader<u16>;
#[doc = "Field `addrhi` writer - This field contains the upper 16 bits (47:32) of the 74th 6-byte MAC address."]
pub type AddrhiW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mbc0 {
    #[doc = "0: `0`"]
    Unmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Mbc0> for bool {
    #[inline(always)]
    fn from(variant: Mbc0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mbc_0` reader - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc0R = crate::BitReader<Mbc0>;
impl Mbc0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mbc0 {
        match self.bits {
            false => Mbc0::Unmasked,
            true => Mbc0::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unmasked(&self) -> bool {
        *self == Mbc0::Unmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Mbc0::Masked
    }
}
#[doc = "Field `mbc_0` writer - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc0W<'a, REG> = crate::BitWriter<'a, REG, Mbc0>;
impl<'a, REG> Mbc0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc0::Unmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc0::Masked)
    }
}
#[doc = "This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mbc1 {
    #[doc = "0: `0`"]
    Unmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Mbc1> for bool {
    #[inline(always)]
    fn from(variant: Mbc1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mbc_1` reader - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc1R = crate::BitReader<Mbc1>;
impl Mbc1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mbc1 {
        match self.bits {
            false => Mbc1::Unmasked,
            true => Mbc1::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unmasked(&self) -> bool {
        *self == Mbc1::Unmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Mbc1::Masked
    }
}
#[doc = "Field `mbc_1` writer - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc1W<'a, REG> = crate::BitWriter<'a, REG, Mbc1>;
impl<'a, REG> Mbc1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc1::Unmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc1::Masked)
    }
}
#[doc = "This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mbc2 {
    #[doc = "0: `0`"]
    Unmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Mbc2> for bool {
    #[inline(always)]
    fn from(variant: Mbc2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mbc_2` reader - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc2R = crate::BitReader<Mbc2>;
impl Mbc2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mbc2 {
        match self.bits {
            false => Mbc2::Unmasked,
            true => Mbc2::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unmasked(&self) -> bool {
        *self == Mbc2::Unmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Mbc2::Masked
    }
}
#[doc = "Field `mbc_2` writer - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc2W<'a, REG> = crate::BitWriter<'a, REG, Mbc2>;
impl<'a, REG> Mbc2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc2::Unmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc2::Masked)
    }
}
#[doc = "This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mbc3 {
    #[doc = "0: `0`"]
    Unmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Mbc3> for bool {
    #[inline(always)]
    fn from(variant: Mbc3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mbc_3` reader - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc3R = crate::BitReader<Mbc3>;
impl Mbc3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mbc3 {
        match self.bits {
            false => Mbc3::Unmasked,
            true => Mbc3::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unmasked(&self) -> bool {
        *self == Mbc3::Unmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Mbc3::Masked
    }
}
#[doc = "Field `mbc_3` writer - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc3W<'a, REG> = crate::BitWriter<'a, REG, Mbc3>;
impl<'a, REG> Mbc3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc3::Unmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc3::Masked)
    }
}
#[doc = "This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mbc4 {
    #[doc = "0: `0`"]
    Unmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Mbc4> for bool {
    #[inline(always)]
    fn from(variant: Mbc4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mbc_4` reader - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc4R = crate::BitReader<Mbc4>;
impl Mbc4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mbc4 {
        match self.bits {
            false => Mbc4::Unmasked,
            true => Mbc4::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unmasked(&self) -> bool {
        *self == Mbc4::Unmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Mbc4::Masked
    }
}
#[doc = "Field `mbc_4` writer - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc4W<'a, REG> = crate::BitWriter<'a, REG, Mbc4>;
impl<'a, REG> Mbc4W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc4::Unmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc4::Masked)
    }
}
#[doc = "This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mbc5 {
    #[doc = "0: `0`"]
    Unmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Mbc5> for bool {
    #[inline(always)]
    fn from(variant: Mbc5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mbc_5` reader - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc5R = crate::BitReader<Mbc5>;
impl Mbc5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mbc5 {
        match self.bits {
            false => Mbc5::Unmasked,
            true => Mbc5::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unmasked(&self) -> bool {
        *self == Mbc5::Unmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Mbc5::Masked
    }
}
#[doc = "Field `mbc_5` writer - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
pub type Mbc5W<'a, REG> = crate::BitWriter<'a, REG, Mbc5>;
impl<'a, REG> Mbc5W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc5::Unmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Mbc5::Masked)
    }
}
#[doc = "When this bit is enabled, the MAC Address73\\[47:0\\]
is used to compare with the SA fields of the received frame. When this bit is disabled, the MAC Address73\\[47:0\\]
is used to compare with the DA fields of the received frame.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sa {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sa> for bool {
    #[inline(always)]
    fn from(variant: Sa) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sa` reader - When this bit is enabled, the MAC Address73\\[47:0\\]
is used to compare with the SA fields of the received frame. When this bit is disabled, the MAC Address73\\[47:0\\]
is used to compare with the DA fields of the received frame."]
pub type SaR = crate::BitReader<Sa>;
impl SaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sa {
        match self.bits {
            false => Sa::Disabled,
            true => Sa::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Sa::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Sa::Enabled
    }
}
#[doc = "Field `sa` writer - When this bit is enabled, the MAC Address73\\[47:0\\]
is used to compare with the SA fields of the received frame. When this bit is disabled, the MAC Address73\\[47:0\\]
is used to compare with the DA fields of the received frame."]
pub type SaW<'a, REG> = crate::BitWriter<'a, REG, Sa>;
impl<'a, REG> SaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sa::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sa::Enabled)
    }
}
#[doc = "When this bit is enabled, the address filter block uses the 74th MAC address for perfect filtering. When this bit is disabled, the address filter block ignores the address for filtering.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ae {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ae> for bool {
    #[inline(always)]
    fn from(variant: Ae) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ae` reader - When this bit is enabled, the address filter block uses the 74th MAC address for perfect filtering. When this bit is disabled, the address filter block ignores the address for filtering."]
pub type AeR = crate::BitReader<Ae>;
impl AeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ae {
        match self.bits {
            false => Ae::Disabled,
            true => Ae::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ae::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ae::Enabled
    }
}
#[doc = "Field `ae` writer - When this bit is enabled, the address filter block uses the 74th MAC address for perfect filtering. When this bit is disabled, the address filter block ignores the address for filtering."]
pub type AeW<'a, REG> = crate::BitWriter<'a, REG, Ae>;
impl<'a, REG> AeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ae::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ae::Enabled)
    }
}
impl R {
    #[doc = "Bits 0:15 - This field contains the upper 16 bits (47:32) of the 74th 6-byte MAC address."]
    #[inline(always)]
    pub fn addrhi(&self) -> AddrhiR {
        AddrhiR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 24 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    pub fn mbc_0(&self) -> Mbc0R {
        Mbc0R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    pub fn mbc_1(&self) -> Mbc1R {
        Mbc1R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    pub fn mbc_2(&self) -> Mbc2R {
        Mbc2R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    pub fn mbc_3(&self) -> Mbc3R {
        Mbc3R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    pub fn mbc_4(&self) -> Mbc4R {
        Mbc4R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    pub fn mbc_5(&self) -> Mbc5R {
        Mbc5R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - When this bit is enabled, the MAC Address73\\[47:0\\]
is used to compare with the SA fields of the received frame. When this bit is disabled, the MAC Address73\\[47:0\\]
is used to compare with the DA fields of the received frame."]
    #[inline(always)]
    pub fn sa(&self) -> SaR {
        SaR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - When this bit is enabled, the address filter block uses the 74th MAC address for perfect filtering. When this bit is disabled, the address filter block ignores the address for filtering."]
    #[inline(always)]
    pub fn ae(&self) -> AeR {
        AeR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the upper 16 bits (47:32) of the 74th 6-byte MAC address."]
    #[inline(always)]
    #[must_use]
    pub fn addrhi(&mut self) -> AddrhiW<GmacgrpMacAddress73HighSpec> {
        AddrhiW::new(self, 0)
    }
    #[doc = "Bit 24 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    #[must_use]
    pub fn mbc_0(&mut self) -> Mbc0W<GmacgrpMacAddress73HighSpec> {
        Mbc0W::new(self, 24)
    }
    #[doc = "Bit 25 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    #[must_use]
    pub fn mbc_1(&mut self) -> Mbc1W<GmacgrpMacAddress73HighSpec> {
        Mbc1W::new(self, 25)
    }
    #[doc = "Bit 26 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    #[must_use]
    pub fn mbc_2(&mut self) -> Mbc2W<GmacgrpMacAddress73HighSpec> {
        Mbc2W::new(self, 26)
    }
    #[doc = "Bit 27 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    #[must_use]
    pub fn mbc_3(&mut self) -> Mbc3W<GmacgrpMacAddress73HighSpec> {
        Mbc3W::new(self, 27)
    }
    #[doc = "Bit 28 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    #[must_use]
    pub fn mbc_4(&mut self) -> Mbc4W<GmacgrpMacAddress73HighSpec> {
        Mbc4W::new(self, 28)
    }
    #[doc = "Bit 29 - This array of bits are mask control bits for comparison of each of the MAC Address bytes. When masked, the MAC does not compare the corresponding byte of received DA or SA with the contents of MAC Address73 high and low registers. Each bit controls the masking of the bytes. You can filter a group of addresses (known as group address filtering) by masking one or more bytes of the address. The array index corresponds to the byte (e.g. index 0 is for bits 7:0)."]
    #[inline(always)]
    #[must_use]
    pub fn mbc_5(&mut self) -> Mbc5W<GmacgrpMacAddress73HighSpec> {
        Mbc5W::new(self, 29)
    }
    #[doc = "Bit 30 - When this bit is enabled, the MAC Address73\\[47:0\\]
is used to compare with the SA fields of the received frame. When this bit is disabled, the MAC Address73\\[47:0\\]
is used to compare with the DA fields of the received frame."]
    #[inline(always)]
    #[must_use]
    pub fn sa(&mut self) -> SaW<GmacgrpMacAddress73HighSpec> {
        SaW::new(self, 30)
    }
    #[doc = "Bit 31 - When this bit is enabled, the address filter block uses the 74th MAC address for perfect filtering. When this bit is disabled, the address filter block ignores the address for filtering."]
    #[inline(always)]
    #[must_use]
    pub fn ae(&mut self) -> AeW<GmacgrpMacAddress73HighSpec> {
        AeW::new(self, 31)
    }
}
#[doc = "The MAC Address73 High register holds the upper 16 bits of the 74th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address73 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address73_high::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address73_high::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMacAddress73HighSpec;
impl crate::RegisterSpec for GmacgrpMacAddress73HighSpec {
    type Ux = u32;
    const OFFSET: u64 = 2504u64;
}
#[doc = "`read()` method returns [`gmacgrp_mac_address73_high::R`](R) reader structure"]
impl crate::Readable for GmacgrpMacAddress73HighSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mac_address73_high::W`](W) writer structure"]
impl crate::Writable for GmacgrpMacAddress73HighSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MAC_Address73_High to value 0xffff"]
impl crate::Resettable for GmacgrpMacAddress73HighSpec {
    const RESET_VALUE: u32 = 0xffff;
}
