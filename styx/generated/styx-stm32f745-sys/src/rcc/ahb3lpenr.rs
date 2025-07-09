// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB3LPENR` reader"]
pub type R = crate::R<Ahb3lpenrSpec>;
#[doc = "Register `AHB3LPENR` writer"]
pub type W = crate::W<Ahb3lpenrSpec>;
#[doc = "Field `FMCLPEN` reader - Flexible memory controller module clock enable during Sleep mode"]
pub type FmclpenR = crate::BitReader;
#[doc = "Field `FMCLPEN` writer - Flexible memory controller module clock enable during Sleep mode"]
pub type FmclpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `QSPILPEN` reader - Quand SPI memory controller clock enable during Sleep mode"]
pub type QspilpenR = crate::BitReader;
#[doc = "Field `QSPILPEN` writer - Quand SPI memory controller clock enable during Sleep mode"]
pub type QspilpenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Flexible memory controller module clock enable during Sleep mode"]
    #[inline(always)]
    pub fn fmclpen(&self) -> FmclpenR {
        FmclpenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Quand SPI memory controller clock enable during Sleep mode"]
    #[inline(always)]
    pub fn qspilpen(&self) -> QspilpenR {
        QspilpenR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Flexible memory controller module clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn fmclpen(&mut self) -> FmclpenW<Ahb3lpenrSpec> {
        FmclpenW::new(self, 0)
    }
    #[doc = "Bit 1 - Quand SPI memory controller clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn qspilpen(&mut self) -> QspilpenW<Ahb3lpenrSpec> {
        QspilpenW::new(self, 1)
    }
}
#[doc = "AHB3 peripheral clock enable in low power mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb3lpenr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb3lpenr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb3lpenrSpec;
impl crate::RegisterSpec for Ahb3lpenrSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`ahb3lpenr::R`](R) reader structure"]
impl crate::Readable for Ahb3lpenrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb3lpenr::W`](W) writer structure"]
impl crate::Writable for Ahb3lpenrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB3LPENR to value 0x01"]
impl crate::Resettable for Ahb3lpenrSpec {
    const RESET_VALUE: u32 = 0x01;
}
