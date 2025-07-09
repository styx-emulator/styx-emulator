// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `IFCR` reader"]
pub type R = crate::R<IfcrSpec>;
#[doc = "Register `IFCR` writer"]
pub type W = crate::W<IfcrSpec>;
#[doc = "Field `CTEIF` reader - Clear Transfer error interrupt flag"]
pub type CteifR = crate::BitReader;
#[doc = "Field `CTEIF` writer - Clear Transfer error interrupt flag"]
pub type CteifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF` reader - Clear transfer complete interrupt flag"]
pub type CtcifR = crate::BitReader;
#[doc = "Field `CTCIF` writer - Clear transfer complete interrupt flag"]
pub type CtcifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTWIF` reader - Clear transfer watermark interrupt flag"]
pub type CtwifR = crate::BitReader;
#[doc = "Field `CTWIF` writer - Clear transfer watermark interrupt flag"]
pub type CtwifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAECIF` reader - Clear CLUT access error interrupt flag"]
pub type CaecifR = crate::BitReader;
#[doc = "Field `CAECIF` writer - Clear CLUT access error interrupt flag"]
pub type CaecifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CCTCIF` reader - Clear CLUT transfer complete interrupt flag"]
pub type CctcifR = crate::BitReader;
#[doc = "Field `CCTCIF` writer - Clear CLUT transfer complete interrupt flag"]
pub type CctcifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CCEIF` reader - Clear configuration error interrupt flag"]
pub type CceifR = crate::BitReader;
#[doc = "Field `CCEIF` writer - Clear configuration error interrupt flag"]
pub type CceifW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clear Transfer error interrupt flag"]
    #[inline(always)]
    pub fn cteif(&self) -> CteifR {
        CteifR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Clear transfer complete interrupt flag"]
    #[inline(always)]
    pub fn ctcif(&self) -> CtcifR {
        CtcifR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Clear transfer watermark interrupt flag"]
    #[inline(always)]
    pub fn ctwif(&self) -> CtwifR {
        CtwifR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Clear CLUT access error interrupt flag"]
    #[inline(always)]
    pub fn caecif(&self) -> CaecifR {
        CaecifR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Clear CLUT transfer complete interrupt flag"]
    #[inline(always)]
    pub fn cctcif(&self) -> CctcifR {
        CctcifR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Clear configuration error interrupt flag"]
    #[inline(always)]
    pub fn cceif(&self) -> CceifR {
        CceifR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clear Transfer error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn cteif(&mut self) -> CteifW<IfcrSpec> {
        CteifW::new(self, 0)
    }
    #[doc = "Bit 1 - Clear transfer complete interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif(&mut self) -> CtcifW<IfcrSpec> {
        CtcifW::new(self, 1)
    }
    #[doc = "Bit 2 - Clear transfer watermark interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn ctwif(&mut self) -> CtwifW<IfcrSpec> {
        CtwifW::new(self, 2)
    }
    #[doc = "Bit 3 - Clear CLUT access error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn caecif(&mut self) -> CaecifW<IfcrSpec> {
        CaecifW::new(self, 3)
    }
    #[doc = "Bit 4 - Clear CLUT transfer complete interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn cctcif(&mut self) -> CctcifW<IfcrSpec> {
        CctcifW::new(self, 4)
    }
    #[doc = "Bit 5 - Clear configuration error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn cceif(&mut self) -> CceifW<IfcrSpec> {
        CceifW::new(self, 5)
    }
}
#[doc = "interrupt flag clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ifcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ifcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IfcrSpec;
impl crate::RegisterSpec for IfcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ifcr::R`](R) reader structure"]
impl crate::Readable for IfcrSpec {}
#[doc = "`write(|w| ..)` method takes [`ifcr::W`](W) writer structure"]
impl crate::Writable for IfcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets IFCR to value 0"]
impl crate::Resettable for IfcrSpec {
    const RESET_VALUE: u32 = 0;
}
