// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1WHPCR` reader"]
pub type R = crate::R<L1whpcrSpec>;
#[doc = "Register `L1WHPCR` writer"]
pub type W = crate::W<L1whpcrSpec>;
#[doc = "Field `WHSTPOS` reader - Window Horizontal Start Position"]
pub type WhstposR = crate::FieldReader<u16>;
#[doc = "Field `WHSTPOS` writer - Window Horizontal Start Position"]
pub type WhstposW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `WHSPPOS` reader - Window Horizontal Stop Position"]
pub type WhspposR = crate::FieldReader<u16>;
#[doc = "Field `WHSPPOS` writer - Window Horizontal Stop Position"]
pub type WhspposW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Window Horizontal Start Position"]
    #[inline(always)]
    pub fn whstpos(&self) -> WhstposR {
        WhstposR::new((self.bits & 0x0fff) as u16)
    }
    #[doc = "Bits 16:27 - Window Horizontal Stop Position"]
    #[inline(always)]
    pub fn whsppos(&self) -> WhspposR {
        WhspposR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Window Horizontal Start Position"]
    #[inline(always)]
    #[must_use]
    pub fn whstpos(&mut self) -> WhstposW<L1whpcrSpec> {
        WhstposW::new(self, 0)
    }
    #[doc = "Bits 16:27 - Window Horizontal Stop Position"]
    #[inline(always)]
    #[must_use]
    pub fn whsppos(&mut self) -> WhspposW<L1whpcrSpec> {
        WhspposW::new(self, 16)
    }
}
#[doc = "Layerx Window Horizontal Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1whpcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1whpcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1whpcrSpec;
impl crate::RegisterSpec for L1whpcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`l1whpcr::R`](R) reader structure"]
impl crate::Readable for L1whpcrSpec {}
#[doc = "`write(|w| ..)` method takes [`l1whpcr::W`](W) writer structure"]
impl crate::Writable for L1whpcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1WHPCR to value 0"]
impl crate::Resettable for L1whpcrSpec {
    const RESET_VALUE: u32 = 0;
}
