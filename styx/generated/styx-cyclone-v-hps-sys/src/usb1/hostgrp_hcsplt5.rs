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
#[doc = "Register `hostgrp_hcsplt5` reader"]
pub type R = crate::R<HostgrpHcsplt5Spec>;
#[doc = "Register `hostgrp_hcsplt5` writer"]
pub type W = crate::W<HostgrpHcsplt5Spec>;
#[doc = "Field `prtaddr` reader - This field is the port number of the recipient transactiontranslator."]
pub type PrtaddrR = crate::FieldReader;
#[doc = "Field `prtaddr` writer - This field is the port number of the recipient transactiontranslator."]
pub type PrtaddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `hubaddr` reader - This field holds the device address of the transaction translator's hub."]
pub type HubaddrR = crate::FieldReader;
#[doc = "Field `hubaddr` writer - This field holds the device address of the transaction translator's hub."]
pub type HubaddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "This field is used to determine whether to send all, first, middle, or last payloads with each OUT transaction.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Xactpos {
    #[doc = "0: `0`"]
    Middle = 0,
    #[doc = "1: `1`"]
    End = 1,
    #[doc = "2: `10`"]
    Begin = 2,
    #[doc = "3: `11`"]
    All = 3,
}
impl From<Xactpos> for u8 {
    #[inline(always)]
    fn from(variant: Xactpos) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Xactpos {
    type Ux = u8;
}
#[doc = "Field `xactpos` reader - This field is used to determine whether to send all, first, middle, or last payloads with each OUT transaction."]
pub type XactposR = crate::FieldReader<Xactpos>;
impl XactposR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xactpos {
        match self.bits {
            0 => Xactpos::Middle,
            1 => Xactpos::End,
            2 => Xactpos::Begin,
            3 => Xactpos::All,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_middle(&self) -> bool {
        *self == Xactpos::Middle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_end(&self) -> bool {
        *self == Xactpos::End
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_begin(&self) -> bool {
        *self == Xactpos::Begin
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_all(&self) -> bool {
        *self == Xactpos::All
    }
}
#[doc = "Field `xactpos` writer - This field is used to determine whether to send all, first, middle, or last payloads with each OUT transaction."]
pub type XactposW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Xactpos>;
impl<'a, REG> XactposW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn middle(self) -> &'a mut crate::W<REG> {
        self.variant(Xactpos::Middle)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn end(self) -> &'a mut crate::W<REG> {
        self.variant(Xactpos::End)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn begin(self) -> &'a mut crate::W<REG> {
        self.variant(Xactpos::Begin)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn all(self) -> &'a mut crate::W<REG> {
        self.variant(Xactpos::All)
    }
}
#[doc = "The application sets this field to request the OTG host to perform a complete split transaction.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compsplt {
    #[doc = "0: `0`"]
    Nosplit = 0,
    #[doc = "1: `1`"]
    Split = 1,
}
impl From<Compsplt> for bool {
    #[inline(always)]
    fn from(variant: Compsplt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `compsplt` reader - The application sets this field to request the OTG host to perform a complete split transaction."]
pub type CompspltR = crate::BitReader<Compsplt>;
impl CompspltR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Compsplt {
        match self.bits {
            false => Compsplt::Nosplit,
            true => Compsplt::Split,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nosplit(&self) -> bool {
        *self == Compsplt::Nosplit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_split(&self) -> bool {
        *self == Compsplt::Split
    }
}
#[doc = "Field `compsplt` writer - The application sets this field to request the OTG host to perform a complete split transaction."]
pub type CompspltW<'a, REG> = crate::BitWriter<'a, REG, Compsplt>;
impl<'a, REG> CompspltW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nosplit(self) -> &'a mut crate::W<REG> {
        self.variant(Compsplt::Nosplit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn split(self) -> &'a mut crate::W<REG> {
        self.variant(Compsplt::Split)
    }
}
#[doc = "The application sets this field to indicate that this channel is enabled to perform split transactions.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spltena {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Spltena> for bool {
    #[inline(always)]
    fn from(variant: Spltena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `spltena` reader - The application sets this field to indicate that this channel is enabled to perform split transactions."]
pub type SpltenaR = crate::BitReader<Spltena>;
impl SpltenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Spltena {
        match self.bits {
            false => Spltena::Disabled,
            true => Spltena::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Spltena::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Spltena::Enabled
    }
}
#[doc = "Field `spltena` writer - The application sets this field to indicate that this channel is enabled to perform split transactions."]
pub type SpltenaW<'a, REG> = crate::BitWriter<'a, REG, Spltena>;
impl<'a, REG> SpltenaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Spltena::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Spltena::Enabled)
    }
}
impl R {
    #[doc = "Bits 0:6 - This field is the port number of the recipient transactiontranslator."]
    #[inline(always)]
    pub fn prtaddr(&self) -> PrtaddrR {
        PrtaddrR::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bits 7:13 - This field holds the device address of the transaction translator's hub."]
    #[inline(always)]
    pub fn hubaddr(&self) -> HubaddrR {
        HubaddrR::new(((self.bits >> 7) & 0x7f) as u8)
    }
    #[doc = "Bits 14:15 - This field is used to determine whether to send all, first, middle, or last payloads with each OUT transaction."]
    #[inline(always)]
    pub fn xactpos(&self) -> XactposR {
        XactposR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bit 16 - The application sets this field to request the OTG host to perform a complete split transaction."]
    #[inline(always)]
    pub fn compsplt(&self) -> CompspltR {
        CompspltR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 31 - The application sets this field to indicate that this channel is enabled to perform split transactions."]
    #[inline(always)]
    pub fn spltena(&self) -> SpltenaR {
        SpltenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:6 - This field is the port number of the recipient transactiontranslator."]
    #[inline(always)]
    #[must_use]
    pub fn prtaddr(&mut self) -> PrtaddrW<HostgrpHcsplt5Spec> {
        PrtaddrW::new(self, 0)
    }
    #[doc = "Bits 7:13 - This field holds the device address of the transaction translator's hub."]
    #[inline(always)]
    #[must_use]
    pub fn hubaddr(&mut self) -> HubaddrW<HostgrpHcsplt5Spec> {
        HubaddrW::new(self, 7)
    }
    #[doc = "Bits 14:15 - This field is used to determine whether to send all, first, middle, or last payloads with each OUT transaction."]
    #[inline(always)]
    #[must_use]
    pub fn xactpos(&mut self) -> XactposW<HostgrpHcsplt5Spec> {
        XactposW::new(self, 14)
    }
    #[doc = "Bit 16 - The application sets this field to request the OTG host to perform a complete split transaction."]
    #[inline(always)]
    #[must_use]
    pub fn compsplt(&mut self) -> CompspltW<HostgrpHcsplt5Spec> {
        CompspltW::new(self, 16)
    }
    #[doc = "Bit 31 - The application sets this field to indicate that this channel is enabled to perform split transactions."]
    #[inline(always)]
    #[must_use]
    pub fn spltena(&mut self) -> SpltenaW<HostgrpHcsplt5Spec> {
        SpltenaW::new(self, 31)
    }
}
#[doc = "Channel_number 5\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcsplt5Spec;
impl crate::RegisterSpec for HostgrpHcsplt5Spec {
    type Ux = u32;
    const OFFSET: u64 = 1444u64;
}
#[doc = "`read()` method returns [`hostgrp_hcsplt5::R`](R) reader structure"]
impl crate::Readable for HostgrpHcsplt5Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcsplt5::W`](W) writer structure"]
impl crate::Writable for HostgrpHcsplt5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcsplt5 to value 0"]
impl crate::Resettable for HostgrpHcsplt5Spec {
    const RESET_VALUE: u32 = 0;
}
