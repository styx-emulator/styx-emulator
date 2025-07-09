// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DR` reader"]
pub type R = crate::R<DrSpec>;
#[doc = "Register `DR` writer"]
pub type W = crate::W<DrSpec>;
#[doc = "Field `DR` reader - Parity Error bit"]
pub type DrR = crate::FieldReader<u32>;
#[doc = "Field `DR` writer - Parity Error bit"]
pub type DrW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
#[doc = "Field `PE` reader - Parity Error bit"]
pub type PeR = crate::BitReader;
#[doc = "Field `PE` writer - Parity Error bit"]
pub type PeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `V` reader - Validity bit"]
pub type VR = crate::BitReader;
#[doc = "Field `V` writer - Validity bit"]
pub type VW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `U` reader - User bit"]
pub type UR = crate::BitReader;
#[doc = "Field `U` writer - User bit"]
pub type UW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `C` reader - Channel Status bit"]
pub type CR = crate::BitReader;
#[doc = "Field `C` writer - Channel Status bit"]
pub type CW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PT` reader - Preamble Type"]
pub type PtR = crate::FieldReader;
#[doc = "Field `PT` writer - Preamble Type"]
pub type PtW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:23 - Parity Error bit"]
    #[inline(always)]
    pub fn dr(&self) -> DrR {
        DrR::new(self.bits & 0x00ff_ffff)
    }
    #[doc = "Bit 24 - Parity Error bit"]
    #[inline(always)]
    pub fn pe(&self) -> PeR {
        PeR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Validity bit"]
    #[inline(always)]
    pub fn v(&self) -> VR {
        VR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - User bit"]
    #[inline(always)]
    pub fn u(&self) -> UR {
        UR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Channel Status bit"]
    #[inline(always)]
    pub fn c(&self) -> CR {
        CR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bits 28:29 - Preamble Type"]
    #[inline(always)]
    pub fn pt(&self) -> PtR {
        PtR::new(((self.bits >> 28) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:23 - Parity Error bit"]
    #[inline(always)]
    #[must_use]
    pub fn dr(&mut self) -> DrW<DrSpec> {
        DrW::new(self, 0)
    }
    #[doc = "Bit 24 - Parity Error bit"]
    #[inline(always)]
    #[must_use]
    pub fn pe(&mut self) -> PeW<DrSpec> {
        PeW::new(self, 24)
    }
    #[doc = "Bit 25 - Validity bit"]
    #[inline(always)]
    #[must_use]
    pub fn v(&mut self) -> VW<DrSpec> {
        VW::new(self, 25)
    }
    #[doc = "Bit 26 - User bit"]
    #[inline(always)]
    #[must_use]
    pub fn u(&mut self) -> UW<DrSpec> {
        UW::new(self, 26)
    }
    #[doc = "Bit 27 - Channel Status bit"]
    #[inline(always)]
    #[must_use]
    pub fn c(&mut self) -> CW<DrSpec> {
        CW::new(self, 27)
    }
    #[doc = "Bits 28:29 - Preamble Type"]
    #[inline(always)]
    #[must_use]
    pub fn pt(&mut self) -> PtW<DrSpec> {
        PtW::new(self, 28)
    }
}
#[doc = "Data input register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DrSpec;
impl crate::RegisterSpec for DrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`dr::R`](R) reader structure"]
impl crate::Readable for DrSpec {}
#[doc = "`reset()` method sets DR to value 0"]
impl crate::Resettable for DrSpec {
    const RESET_VALUE: u32 = 0;
}
