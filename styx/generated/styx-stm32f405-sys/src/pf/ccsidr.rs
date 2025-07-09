// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCSIDR` reader"]
pub type R = crate::R<CcsidrSpec>;
#[doc = "Register `CCSIDR` writer"]
pub type W = crate::W<CcsidrSpec>;
#[doc = "Field `LineSize` reader - LineSize"]
pub type LineSizeR = crate::FieldReader;
#[doc = "Field `LineSize` writer - LineSize"]
pub type LineSizeW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `Associativity` reader - Associativity"]
pub type AssociativityR = crate::FieldReader<u16>;
#[doc = "Field `Associativity` writer - Associativity"]
pub type AssociativityW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `NumSets` reader - NumSets"]
pub type NumSetsR = crate::FieldReader<u16>;
#[doc = "Field `NumSets` writer - NumSets"]
pub type NumSetsW<'a, REG> = crate::FieldWriter<'a, REG, 15, u16>;
#[doc = "Field `WA` reader - WA"]
pub type WaR = crate::BitReader;
#[doc = "Field `WA` writer - WA"]
pub type WaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RA` reader - RA"]
pub type RaR = crate::BitReader;
#[doc = "Field `RA` writer - RA"]
pub type RaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WB` reader - WB"]
pub type WbR = crate::BitReader;
#[doc = "Field `WB` writer - WB"]
pub type WbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WT` reader - WT"]
pub type WtR = crate::BitReader;
#[doc = "Field `WT` writer - WT"]
pub type WtW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - LineSize"]
    #[inline(always)]
    pub fn line_size(&self) -> LineSizeR {
        LineSizeR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:12 - Associativity"]
    #[inline(always)]
    pub fn associativity(&self) -> AssociativityR {
        AssociativityR::new(((self.bits >> 3) & 0x03ff) as u16)
    }
    #[doc = "Bits 13:27 - NumSets"]
    #[inline(always)]
    pub fn num_sets(&self) -> NumSetsR {
        NumSetsR::new(((self.bits >> 13) & 0x7fff) as u16)
    }
    #[doc = "Bit 28 - WA"]
    #[inline(always)]
    pub fn wa(&self) -> WaR {
        WaR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - RA"]
    #[inline(always)]
    pub fn ra(&self) -> RaR {
        RaR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - WB"]
    #[inline(always)]
    pub fn wb(&self) -> WbR {
        WbR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - WT"]
    #[inline(always)]
    pub fn wt(&self) -> WtR {
        WtR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - LineSize"]
    #[inline(always)]
    #[must_use]
    pub fn line_size(&mut self) -> LineSizeW<CcsidrSpec> {
        LineSizeW::new(self, 0)
    }
    #[doc = "Bits 3:12 - Associativity"]
    #[inline(always)]
    #[must_use]
    pub fn associativity(&mut self) -> AssociativityW<CcsidrSpec> {
        AssociativityW::new(self, 3)
    }
    #[doc = "Bits 13:27 - NumSets"]
    #[inline(always)]
    #[must_use]
    pub fn num_sets(&mut self) -> NumSetsW<CcsidrSpec> {
        NumSetsW::new(self, 13)
    }
    #[doc = "Bit 28 - WA"]
    #[inline(always)]
    #[must_use]
    pub fn wa(&mut self) -> WaW<CcsidrSpec> {
        WaW::new(self, 28)
    }
    #[doc = "Bit 29 - RA"]
    #[inline(always)]
    #[must_use]
    pub fn ra(&mut self) -> RaW<CcsidrSpec> {
        RaW::new(self, 29)
    }
    #[doc = "Bit 30 - WB"]
    #[inline(always)]
    #[must_use]
    pub fn wb(&mut self) -> WbW<CcsidrSpec> {
        WbW::new(self, 30)
    }
    #[doc = "Bit 31 - WT"]
    #[inline(always)]
    #[must_use]
    pub fn wt(&mut self) -> WtW<CcsidrSpec> {
        WtW::new(self, 31)
    }
}
#[doc = "Cache Size ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccsidr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CcsidrSpec;
impl crate::RegisterSpec for CcsidrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ccsidr::R`](R) reader structure"]
impl crate::Readable for CcsidrSpec {}
#[doc = "`reset()` method sets CCSIDR to value 0"]
impl crate::Resettable for CcsidrSpec {
    const RESET_VALUE: u32 = 0;
}
