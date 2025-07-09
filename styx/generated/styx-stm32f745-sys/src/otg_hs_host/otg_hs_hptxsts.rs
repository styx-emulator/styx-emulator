// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_HPTXSTS` reader"]
pub type R = crate::R<OtgHsHptxstsSpec>;
#[doc = "Register `OTG_HS_HPTXSTS` writer"]
pub type W = crate::W<OtgHsHptxstsSpec>;
#[doc = "Field `PTXFSAVL` reader - Periodic transmit data FIFO space available"]
pub type PtxfsavlR = crate::FieldReader<u16>;
#[doc = "Field `PTXFSAVL` writer - Periodic transmit data FIFO space available"]
pub type PtxfsavlW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `PTXQSAV` reader - Periodic transmit request queue space available"]
pub type PtxqsavR = crate::FieldReader;
#[doc = "Field `PTXQSAV` writer - Periodic transmit request queue space available"]
pub type PtxqsavW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `PTXQTOP` reader - Top of the periodic transmit request queue"]
pub type PtxqtopR = crate::FieldReader;
#[doc = "Field `PTXQTOP` writer - Top of the periodic transmit request queue"]
pub type PtxqtopW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:15 - Periodic transmit data FIFO space available"]
    #[inline(always)]
    pub fn ptxfsavl(&self) -> PtxfsavlR {
        PtxfsavlR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:23 - Periodic transmit request queue space available"]
    #[inline(always)]
    pub fn ptxqsav(&self) -> PtxqsavR {
        PtxqsavR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - Top of the periodic transmit request queue"]
    #[inline(always)]
    pub fn ptxqtop(&self) -> PtxqtopR {
        PtxqtopR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:15 - Periodic transmit data FIFO space available"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfsavl(&mut self) -> PtxfsavlW<OtgHsHptxstsSpec> {
        PtxfsavlW::new(self, 0)
    }
    #[doc = "Bits 16:23 - Periodic transmit request queue space available"]
    #[inline(always)]
    #[must_use]
    pub fn ptxqsav(&mut self) -> PtxqsavW<OtgHsHptxstsSpec> {
        PtxqsavW::new(self, 16)
    }
    #[doc = "Bits 24:31 - Top of the periodic transmit request queue"]
    #[inline(always)]
    #[must_use]
    pub fn ptxqtop(&mut self) -> PtxqtopW<OtgHsHptxstsSpec> {
        PtxqtopW::new(self, 24)
    }
}
#[doc = "OTG_HS_Host periodic transmit FIFO/queue status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hptxsts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hptxsts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsHptxstsSpec;
impl crate::RegisterSpec for OtgHsHptxstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`otg_hs_hptxsts::R`](R) reader structure"]
impl crate::Readable for OtgHsHptxstsSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_hptxsts::W`](W) writer structure"]
impl crate::Writable for OtgHsHptxstsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_HPTXSTS to value 0x0008_0100"]
impl crate::Resettable for OtgHsHptxstsSpec {
    const RESET_VALUE: u32 = 0x0008_0100;
}
