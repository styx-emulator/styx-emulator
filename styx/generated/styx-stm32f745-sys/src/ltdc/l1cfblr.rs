// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1CFBLR` reader"]
pub type R = crate::R<L1cfblrSpec>;
#[doc = "Register `L1CFBLR` writer"]
pub type W = crate::W<L1cfblrSpec>;
#[doc = "Field `CFBLL` reader - Color Frame Buffer Line Length"]
pub type CfbllR = crate::FieldReader<u16>;
#[doc = "Field `CFBLL` writer - Color Frame Buffer Line Length"]
pub type CfbllW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
#[doc = "Field `CFBP` reader - Color Frame Buffer Pitch in bytes"]
pub type CfbpR = crate::FieldReader<u16>;
#[doc = "Field `CFBP` writer - Color Frame Buffer Pitch in bytes"]
pub type CfbpW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
impl R {
    #[doc = "Bits 0:12 - Color Frame Buffer Line Length"]
    #[inline(always)]
    pub fn cfbll(&self) -> CfbllR {
        CfbllR::new((self.bits & 0x1fff) as u16)
    }
    #[doc = "Bits 16:28 - Color Frame Buffer Pitch in bytes"]
    #[inline(always)]
    pub fn cfbp(&self) -> CfbpR {
        CfbpR::new(((self.bits >> 16) & 0x1fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:12 - Color Frame Buffer Line Length"]
    #[inline(always)]
    #[must_use]
    pub fn cfbll(&mut self) -> CfbllW<L1cfblrSpec> {
        CfbllW::new(self, 0)
    }
    #[doc = "Bits 16:28 - Color Frame Buffer Pitch in bytes"]
    #[inline(always)]
    #[must_use]
    pub fn cfbp(&mut self) -> CfbpW<L1cfblrSpec> {
        CfbpW::new(self, 16)
    }
}
#[doc = "Layerx Color Frame Buffer Length Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cfblr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cfblr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1cfblrSpec;
impl crate::RegisterSpec for L1cfblrSpec {
    type Ux = u32;
    const OFFSET: u64 = 176u64;
}
#[doc = "`read()` method returns [`l1cfblr::R`](R) reader structure"]
impl crate::Readable for L1cfblrSpec {}
#[doc = "`write(|w| ..)` method takes [`l1cfblr::W`](W) writer structure"]
impl crate::Writable for L1cfblrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1CFBLR to value 0"]
impl crate::Resettable for L1cfblrSpec {
    const RESET_VALUE: u32 = 0;
}
