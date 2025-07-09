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
#[doc = "Register `usbgrp_l3master` reader"]
pub type R = crate::R<UsbgrpL3masterSpec>;
#[doc = "Register `usbgrp_l3master` writer"]
pub type W = crate::W<UsbgrpL3masterSpec>;
#[doc = "Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hprotdata0 {
    #[doc = "0: `0`"]
    Opcode = 0,
    #[doc = "1: `1`"]
    Data = 1,
}
impl From<Hprotdata0> for bool {
    #[inline(always)]
    fn from(variant: Hprotdata0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hprotdata_0` reader - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
pub type Hprotdata0R = crate::BitReader<Hprotdata0>;
impl Hprotdata0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hprotdata0 {
        match self.bits {
            false => Hprotdata0::Opcode,
            true => Hprotdata0::Data,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_opcode(&self) -> bool {
        *self == Hprotdata0::Opcode
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_data(&self) -> bool {
        *self == Hprotdata0::Data
    }
}
#[doc = "Field `hprotdata_0` writer - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
pub type Hprotdata0W<'a, REG> = crate::BitWriter<'a, REG, Hprotdata0>;
impl<'a, REG> Hprotdata0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn opcode(self) -> &'a mut crate::W<REG> {
        self.variant(Hprotdata0::Opcode)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn data(self) -> &'a mut crate::W<REG> {
        self.variant(Hprotdata0::Data)
    }
}
#[doc = "Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hprotdata1 {
    #[doc = "0: `0`"]
    Opcode = 0,
    #[doc = "1: `1`"]
    Data = 1,
}
impl From<Hprotdata1> for bool {
    #[inline(always)]
    fn from(variant: Hprotdata1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hprotdata_1` reader - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
pub type Hprotdata1R = crate::BitReader<Hprotdata1>;
impl Hprotdata1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hprotdata1 {
        match self.bits {
            false => Hprotdata1::Opcode,
            true => Hprotdata1::Data,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_opcode(&self) -> bool {
        *self == Hprotdata1::Opcode
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_data(&self) -> bool {
        *self == Hprotdata1::Data
    }
}
#[doc = "Field `hprotdata_1` writer - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
pub type Hprotdata1W<'a, REG> = crate::BitWriter<'a, REG, Hprotdata1>;
impl<'a, REG> Hprotdata1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn opcode(self) -> &'a mut crate::W<REG> {
        self.variant(Hprotdata1::Opcode)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn data(self) -> &'a mut crate::W<REG> {
        self.variant(Hprotdata1::Data)
    }
}
#[doc = "Field `hprotpriv_0` reader - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
pub type Hprotpriv0R = crate::BitReader;
#[doc = "Field `hprotpriv_0` writer - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
pub type Hprotpriv0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `hprotpriv_1` reader - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
pub type Hprotpriv1R = crate::BitReader;
#[doc = "Field `hprotpriv_1` writer - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
pub type Hprotpriv1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `hprotbuff_0` reader - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
pub type Hprotbuff0R = crate::BitReader;
#[doc = "Field `hprotbuff_0` writer - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
pub type Hprotbuff0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `hprotbuff_1` reader - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
pub type Hprotbuff1R = crate::BitReader;
#[doc = "Field `hprotbuff_1` writer - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
pub type Hprotbuff1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `hprotcache_0` reader - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
pub type Hprotcache0R = crate::BitReader;
#[doc = "Field `hprotcache_0` writer - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
pub type Hprotcache0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `hprotcache_1` reader - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
pub type Hprotcache1R = crate::BitReader;
#[doc = "Field `hprotcache_1` writer - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
pub type Hprotcache1W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotdata_0(&self) -> Hprotdata0R {
        Hprotdata0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotdata_1(&self) -> Hprotdata1R {
        Hprotdata1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotpriv_0(&self) -> Hprotpriv0R {
        Hprotpriv0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotpriv_1(&self) -> Hprotpriv1R {
        Hprotpriv1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotbuff_0(&self) -> Hprotbuff0R {
        Hprotbuff0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotbuff_1(&self) -> Hprotbuff1R {
        Hprotbuff1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotcache_0(&self) -> Hprotcache0R {
        Hprotcache0R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
    #[inline(always)]
    pub fn hprotcache_1(&self) -> Hprotcache1R {
        Hprotcache1R::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotdata_0(&mut self) -> Hprotdata0W<UsbgrpL3masterSpec> {
        Hprotdata0W::new(self, 0)
    }
    #[doc = "Bit 1 - Specifies if the L3 master access is for data or opcode for the USB modules. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotdata_1(&mut self) -> Hprotdata1W<UsbgrpL3masterSpec> {
        Hprotdata1W::new(self, 1)
    }
    #[doc = "Bit 2 - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotpriv_0(&mut self) -> Hprotpriv0W<UsbgrpL3masterSpec> {
        Hprotpriv0W::new(self, 2)
    }
    #[doc = "Bit 3 - If 1, L3 master accesses for the USB modules are privileged. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotpriv_1(&mut self) -> Hprotpriv1W<UsbgrpL3masterSpec> {
        Hprotpriv1W::new(self, 3)
    }
    #[doc = "Bit 4 - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotbuff_0(&mut self) -> Hprotbuff0W<UsbgrpL3masterSpec> {
        Hprotbuff0W::new(self, 4)
    }
    #[doc = "Bit 5 - If 1, L3 master accesses for the USB modules are bufferable. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotbuff_1(&mut self) -> Hprotbuff1W<UsbgrpL3masterSpec> {
        Hprotbuff1W::new(self, 5)
    }
    #[doc = "Bit 6 - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotcache_0(&mut self) -> Hprotcache0W<UsbgrpL3masterSpec> {
        Hprotcache0W::new(self, 6)
    }
    #[doc = "Bit 7 - If 1, L3 master accesses for the USB modules are cacheable. The field array index corresponds to the USB index."]
    #[inline(always)]
    #[must_use]
    pub fn hprotcache_1(&mut self) -> Hprotcache1W<UsbgrpL3masterSpec> {
        Hprotcache1W::new(self, 7)
    }
}
#[doc = "Controls the L3 master HPROT AHB-Lite signal. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`usbgrp_l3master::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`usbgrp_l3master::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct UsbgrpL3masterSpec;
impl crate::RegisterSpec for UsbgrpL3masterSpec {
    type Ux = u32;
    const OFFSET: u64 = 280u64;
}
#[doc = "`read()` method returns [`usbgrp_l3master::R`](R) reader structure"]
impl crate::Readable for UsbgrpL3masterSpec {}
#[doc = "`write(|w| ..)` method takes [`usbgrp_l3master::W`](W) writer structure"]
impl crate::Writable for UsbgrpL3masterSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets usbgrp_l3master to value 0x0f"]
impl crate::Resettable for UsbgrpL3masterSpec {
    const RESET_VALUE: u32 = 0x0f;
}
