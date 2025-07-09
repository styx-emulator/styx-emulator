// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACMIIAR` reader"]
pub type R = crate::R<MacmiiarSpec>;
#[doc = "Register `MACMIIAR` writer"]
pub type W = crate::W<MacmiiarSpec>;
#[doc = "Field `MB` reader - MB"]
pub type MbR = crate::BitReader;
#[doc = "Field `MB` writer - MB"]
pub type MbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MW` reader - MW"]
pub type MwR = crate::BitReader;
#[doc = "Field `MW` writer - MW"]
pub type MwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CR` reader - CR"]
pub type CrR = crate::FieldReader;
#[doc = "Field `CR` writer - CR"]
pub type CrW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `MR` reader - MR"]
pub type MrR = crate::FieldReader;
#[doc = "Field `MR` writer - MR"]
pub type MrW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `PA` reader - PA"]
pub type PaR = crate::FieldReader;
#[doc = "Field `PA` writer - PA"]
pub type PaW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bit 0 - MB"]
    #[inline(always)]
    pub fn mb(&self) -> MbR {
        MbR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - MW"]
    #[inline(always)]
    pub fn mw(&self) -> MwR {
        MwR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:4 - CR"]
    #[inline(always)]
    pub fn cr(&self) -> CrR {
        CrR::new(((self.bits >> 2) & 7) as u8)
    }
    #[doc = "Bits 6:10 - MR"]
    #[inline(always)]
    pub fn mr(&self) -> MrR {
        MrR::new(((self.bits >> 6) & 0x1f) as u8)
    }
    #[doc = "Bits 11:15 - PA"]
    #[inline(always)]
    pub fn pa(&self) -> PaR {
        PaR::new(((self.bits >> 11) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - MB"]
    #[inline(always)]
    #[must_use]
    pub fn mb(&mut self) -> MbW<MacmiiarSpec> {
        MbW::new(self, 0)
    }
    #[doc = "Bit 1 - MW"]
    #[inline(always)]
    #[must_use]
    pub fn mw(&mut self) -> MwW<MacmiiarSpec> {
        MwW::new(self, 1)
    }
    #[doc = "Bits 2:4 - CR"]
    #[inline(always)]
    #[must_use]
    pub fn cr(&mut self) -> CrW<MacmiiarSpec> {
        CrW::new(self, 2)
    }
    #[doc = "Bits 6:10 - MR"]
    #[inline(always)]
    #[must_use]
    pub fn mr(&mut self) -> MrW<MacmiiarSpec> {
        MrW::new(self, 6)
    }
    #[doc = "Bits 11:15 - PA"]
    #[inline(always)]
    #[must_use]
    pub fn pa(&mut self) -> PaW<MacmiiarSpec> {
        PaW::new(self, 11)
    }
}
#[doc = "Ethernet MAC MII address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macmiiar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macmiiar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacmiiarSpec;
impl crate::RegisterSpec for MacmiiarSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`macmiiar::R`](R) reader structure"]
impl crate::Readable for MacmiiarSpec {}
#[doc = "`write(|w| ..)` method takes [`macmiiar::W`](W) writer structure"]
impl crate::Writable for MacmiiarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACMIIAR to value 0"]
impl crate::Resettable for MacmiiarSpec {
    const RESET_VALUE: u32 = 0;
}
