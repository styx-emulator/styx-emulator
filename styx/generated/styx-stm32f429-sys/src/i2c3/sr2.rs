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
#[doc = "Register `SR2` reader"]
pub type R = crate::R<Sr2Spec>;
#[doc = "Register `SR2` writer"]
pub type W = crate::W<Sr2Spec>;
#[doc = "Field `MSL` reader - Master/slave"]
pub type MslR = crate::BitReader;
#[doc = "Field `MSL` writer - Master/slave"]
pub type MslW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSY` reader - Bus busy"]
pub type BusyR = crate::BitReader;
#[doc = "Field `BUSY` writer - Bus busy"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TRA` reader - Transmitter/receiver"]
pub type TraR = crate::BitReader;
#[doc = "Field `TRA` writer - Transmitter/receiver"]
pub type TraW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GENCALL` reader - General call address (Slave mode)"]
pub type GencallR = crate::BitReader;
#[doc = "Field `GENCALL` writer - General call address (Slave mode)"]
pub type GencallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMBDEFAULT` reader - SMBus device default address (Slave mode)"]
pub type SmbdefaultR = crate::BitReader;
#[doc = "Field `SMBDEFAULT` writer - SMBus device default address (Slave mode)"]
pub type SmbdefaultW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMBHOST` reader - SMBus host header (Slave mode)"]
pub type SmbhostR = crate::BitReader;
#[doc = "Field `SMBHOST` writer - SMBus host header (Slave mode)"]
pub type SmbhostW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DUALF` reader - Dual flag (Slave mode)"]
pub type DualfR = crate::BitReader;
#[doc = "Field `DUALF` writer - Dual flag (Slave mode)"]
pub type DualfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PEC` reader - acket error checking register"]
pub type PecR = crate::FieldReader;
#[doc = "Field `PEC` writer - acket error checking register"]
pub type PecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bit 0 - Master/slave"]
    #[inline(always)]
    pub fn msl(&self) -> MslR {
        MslR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Bus busy"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transmitter/receiver"]
    #[inline(always)]
    pub fn tra(&self) -> TraR {
        TraR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - General call address (Slave mode)"]
    #[inline(always)]
    pub fn gencall(&self) -> GencallR {
        GencallR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - SMBus device default address (Slave mode)"]
    #[inline(always)]
    pub fn smbdefault(&self) -> SmbdefaultR {
        SmbdefaultR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - SMBus host header (Slave mode)"]
    #[inline(always)]
    pub fn smbhost(&self) -> SmbhostR {
        SmbhostR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Dual flag (Slave mode)"]
    #[inline(always)]
    pub fn dualf(&self) -> DualfR {
        DualfR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:15 - acket error checking register"]
    #[inline(always)]
    pub fn pec(&self) -> PecR {
        PecR::new(((self.bits >> 8) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Master/slave"]
    #[inline(always)]
    #[must_use]
    pub fn msl(&mut self) -> MslW<Sr2Spec> {
        MslW::new(self, 0)
    }
    #[doc = "Bit 1 - Bus busy"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<Sr2Spec> {
        BusyW::new(self, 1)
    }
    #[doc = "Bit 2 - Transmitter/receiver"]
    #[inline(always)]
    #[must_use]
    pub fn tra(&mut self) -> TraW<Sr2Spec> {
        TraW::new(self, 2)
    }
    #[doc = "Bit 4 - General call address (Slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn gencall(&mut self) -> GencallW<Sr2Spec> {
        GencallW::new(self, 4)
    }
    #[doc = "Bit 5 - SMBus device default address (Slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn smbdefault(&mut self) -> SmbdefaultW<Sr2Spec> {
        SmbdefaultW::new(self, 5)
    }
    #[doc = "Bit 6 - SMBus host header (Slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn smbhost(&mut self) -> SmbhostW<Sr2Spec> {
        SmbhostW::new(self, 6)
    }
    #[doc = "Bit 7 - Dual flag (Slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn dualf(&mut self) -> DualfW<Sr2Spec> {
        DualfW::new(self, 7)
    }
    #[doc = "Bits 8:15 - acket error checking register"]
    #[inline(always)]
    #[must_use]
    pub fn pec(&mut self) -> PecW<Sr2Spec> {
        PecW::new(self, 8)
    }
}
#[doc = "Status register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sr2Spec;
impl crate::RegisterSpec for Sr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`sr2::R`](R) reader structure"]
impl crate::Readable for Sr2Spec {}
#[doc = "`reset()` method sets SR2 to value 0"]
impl crate::Resettable for Sr2Spec {
    const RESET_VALUE: u32 = 0;
}
