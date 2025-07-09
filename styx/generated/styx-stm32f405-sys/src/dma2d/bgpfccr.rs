// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BGPFCCR` reader"]
pub type R = crate::R<BgpfccrSpec>;
#[doc = "Register `BGPFCCR` writer"]
pub type W = crate::W<BgpfccrSpec>;
#[doc = "Field `CM` reader - Color mode"]
pub type CmR = crate::FieldReader;
#[doc = "Field `CM` writer - Color mode"]
pub type CmW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `CCM` reader - CLUT Color mode"]
pub type CcmR = crate::BitReader;
#[doc = "Field `CCM` writer - CLUT Color mode"]
pub type CcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `START` reader - Start"]
pub type StartR = crate::BitReader;
#[doc = "Field `START` writer - Start"]
pub type StartW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CS` reader - CLUT size"]
pub type CsR = crate::FieldReader;
#[doc = "Field `CS` writer - CLUT size"]
pub type CsW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `AM` reader - Alpha mode"]
pub type AmR = crate::FieldReader;
#[doc = "Field `AM` writer - Alpha mode"]
pub type AmW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ALPHA` reader - Alpha value"]
pub type AlphaR = crate::FieldReader;
#[doc = "Field `ALPHA` writer - Alpha value"]
pub type AlphaW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:3 - Color mode"]
    #[inline(always)]
    pub fn cm(&self) -> CmR {
        CmR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 4 - CLUT Color mode"]
    #[inline(always)]
    pub fn ccm(&self) -> CcmR {
        CcmR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Start"]
    #[inline(always)]
    pub fn start(&self) -> StartR {
        StartR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 8:15 - CLUT size"]
    #[inline(always)]
    pub fn cs(&self) -> CsR {
        CsR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:17 - Alpha mode"]
    #[inline(always)]
    pub fn am(&self) -> AmR {
        AmR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 24:31 - Alpha value"]
    #[inline(always)]
    pub fn alpha(&self) -> AlphaR {
        AlphaR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Color mode"]
    #[inline(always)]
    #[must_use]
    pub fn cm(&mut self) -> CmW<BgpfccrSpec> {
        CmW::new(self, 0)
    }
    #[doc = "Bit 4 - CLUT Color mode"]
    #[inline(always)]
    #[must_use]
    pub fn ccm(&mut self) -> CcmW<BgpfccrSpec> {
        CcmW::new(self, 4)
    }
    #[doc = "Bit 5 - Start"]
    #[inline(always)]
    #[must_use]
    pub fn start(&mut self) -> StartW<BgpfccrSpec> {
        StartW::new(self, 5)
    }
    #[doc = "Bits 8:15 - CLUT size"]
    #[inline(always)]
    #[must_use]
    pub fn cs(&mut self) -> CsW<BgpfccrSpec> {
        CsW::new(self, 8)
    }
    #[doc = "Bits 16:17 - Alpha mode"]
    #[inline(always)]
    #[must_use]
    pub fn am(&mut self) -> AmW<BgpfccrSpec> {
        AmW::new(self, 16)
    }
    #[doc = "Bits 24:31 - Alpha value"]
    #[inline(always)]
    #[must_use]
    pub fn alpha(&mut self) -> AlphaW<BgpfccrSpec> {
        AlphaW::new(self, 24)
    }
}
#[doc = "background PFC control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgpfccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgpfccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BgpfccrSpec;
impl crate::RegisterSpec for BgpfccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`bgpfccr::R`](R) reader structure"]
impl crate::Readable for BgpfccrSpec {}
#[doc = "`write(|w| ..)` method takes [`bgpfccr::W`](W) writer structure"]
impl crate::Writable for BgpfccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BGPFCCR to value 0"]
impl crate::Resettable for BgpfccrSpec {
    const RESET_VALUE: u32 = 0;
}
