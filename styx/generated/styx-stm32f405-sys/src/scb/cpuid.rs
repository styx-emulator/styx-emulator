// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CPUID` reader"]
pub type R = crate::R<CpuidSpec>;
#[doc = "Register `CPUID` writer"]
pub type W = crate::W<CpuidSpec>;
#[doc = "Field `Revision` reader - Revision number"]
pub type RevisionR = crate::FieldReader;
#[doc = "Field `Revision` writer - Revision number"]
pub type RevisionW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PartNo` reader - Part number of the processor"]
pub type PartNoR = crate::FieldReader<u16>;
#[doc = "Field `PartNo` writer - Part number of the processor"]
pub type PartNoW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `Constant` reader - Reads as 0xF"]
pub type ConstantR = crate::FieldReader;
#[doc = "Field `Constant` writer - Reads as 0xF"]
pub type ConstantW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `Variant` reader - Variant number"]
pub type VariantR = crate::FieldReader;
#[doc = "Field `Variant` writer - Variant number"]
pub type VariantW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `Implementer` reader - Implementer code"]
pub type ImplementerR = crate::FieldReader;
#[doc = "Field `Implementer` writer - Implementer code"]
pub type ImplementerW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:3 - Revision number"]
    #[inline(always)]
    pub fn revision(&self) -> RevisionR {
        RevisionR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:15 - Part number of the processor"]
    #[inline(always)]
    pub fn part_no(&self) -> PartNoR {
        PartNoR::new(((self.bits >> 4) & 0x0fff) as u16)
    }
    #[doc = "Bits 16:19 - Reads as 0xF"]
    #[inline(always)]
    pub fn constant(&self) -> ConstantR {
        ConstantR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - Variant number"]
    #[inline(always)]
    pub fn variant(&self) -> VariantR {
        VariantR::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bits 24:31 - Implementer code"]
    #[inline(always)]
    pub fn implementer(&self) -> ImplementerR {
        ImplementerR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Revision number"]
    #[inline(always)]
    #[must_use]
    pub fn revision(&mut self) -> RevisionW<CpuidSpec> {
        RevisionW::new(self, 0)
    }
    #[doc = "Bits 4:15 - Part number of the processor"]
    #[inline(always)]
    #[must_use]
    pub fn part_no(&mut self) -> PartNoW<CpuidSpec> {
        PartNoW::new(self, 4)
    }
    #[doc = "Bits 16:19 - Reads as 0xF"]
    #[inline(always)]
    #[must_use]
    pub fn constant(&mut self) -> ConstantW<CpuidSpec> {
        ConstantW::new(self, 16)
    }
    #[doc = "Bits 20:23 - Variant number"]
    #[inline(always)]
    #[must_use]
    pub fn variant(&mut self) -> VariantW<CpuidSpec> {
        VariantW::new(self, 20)
    }
    #[doc = "Bits 24:31 - Implementer code"]
    #[inline(always)]
    #[must_use]
    pub fn implementer(&mut self) -> ImplementerW<CpuidSpec> {
        ImplementerW::new(self, 24)
    }
}
#[doc = "CPUID base register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cpuid::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpuidSpec;
impl crate::RegisterSpec for CpuidSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cpuid::R`](R) reader structure"]
impl crate::Readable for CpuidSpec {}
#[doc = "`reset()` method sets CPUID to value 0x410f_c241"]
impl crate::Resettable for CpuidSpec {
    const RESET_VALUE: u32 = 0x410f_c241;
}
