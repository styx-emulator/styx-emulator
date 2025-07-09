// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMAMFBOCR` reader"]
pub type R = crate::R<DmamfbocrSpec>;
#[doc = "Register `DMAMFBOCR` writer"]
pub type W = crate::W<DmamfbocrSpec>;
#[doc = "Field `MFC` reader - MFC"]
pub type MfcR = crate::FieldReader<u16>;
#[doc = "Field `MFC` writer - MFC"]
pub type MfcW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `OMFC` reader - OMFC"]
pub type OmfcR = crate::BitReader;
#[doc = "Field `OMFC` writer - OMFC"]
pub type OmfcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MFA` reader - MFA"]
pub type MfaR = crate::FieldReader<u16>;
#[doc = "Field `MFA` writer - MFA"]
pub type MfaW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `OFOC` reader - OFOC"]
pub type OfocR = crate::BitReader;
#[doc = "Field `OFOC` writer - OFOC"]
pub type OfocW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - MFC"]
    #[inline(always)]
    pub fn mfc(&self) -> MfcR {
        MfcR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 16 - OMFC"]
    #[inline(always)]
    pub fn omfc(&self) -> OmfcR {
        OmfcR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:27 - MFA"]
    #[inline(always)]
    pub fn mfa(&self) -> MfaR {
        MfaR::new(((self.bits >> 17) & 0x07ff) as u16)
    }
    #[doc = "Bit 28 - OFOC"]
    #[inline(always)]
    pub fn ofoc(&self) -> OfocR {
        OfocR::new(((self.bits >> 28) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - MFC"]
    #[inline(always)]
    #[must_use]
    pub fn mfc(&mut self) -> MfcW<DmamfbocrSpec> {
        MfcW::new(self, 0)
    }
    #[doc = "Bit 16 - OMFC"]
    #[inline(always)]
    #[must_use]
    pub fn omfc(&mut self) -> OmfcW<DmamfbocrSpec> {
        OmfcW::new(self, 16)
    }
    #[doc = "Bits 17:27 - MFA"]
    #[inline(always)]
    #[must_use]
    pub fn mfa(&mut self) -> MfaW<DmamfbocrSpec> {
        MfaW::new(self, 17)
    }
    #[doc = "Bit 28 - OFOC"]
    #[inline(always)]
    #[must_use]
    pub fn ofoc(&mut self) -> OfocW<DmamfbocrSpec> {
        OfocW::new(self, 28)
    }
}
#[doc = "Ethernet DMA missed frame and buffer overflow counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmamfbocr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmamfbocr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmamfbocrSpec;
impl crate::RegisterSpec for DmamfbocrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`dmamfbocr::R`](R) reader structure"]
impl crate::Readable for DmamfbocrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmamfbocr::W`](W) writer structure"]
impl crate::Writable for DmamfbocrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMAMFBOCR to value 0"]
impl crate::Resettable for DmamfbocrSpec {
    const RESET_VALUE: u32 = 0;
}
