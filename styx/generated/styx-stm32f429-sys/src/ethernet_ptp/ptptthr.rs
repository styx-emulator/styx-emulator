// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTTHR` reader"]
pub type R = crate::R<PtptthrSpec>;
#[doc = "Register `PTPTTHR` writer"]
pub type W = crate::W<PtptthrSpec>;
#[doc = "Field `TTSH` reader - 0"]
pub type TtshR = crate::FieldReader<u32>;
#[doc = "Field `TTSH` writer - 0"]
pub type TtshW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - 0"]
    #[inline(always)]
    pub fn ttsh(&self) -> TtshR {
        TtshR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - 0"]
    #[inline(always)]
    #[must_use]
    pub fn ttsh(&mut self) -> TtshW<PtptthrSpec> {
        TtshW::new(self, 0)
    }
}
#[doc = "Ethernet PTP target time high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptthr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptthr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptthrSpec;
impl crate::RegisterSpec for PtptthrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`ptptthr::R`](R) reader structure"]
impl crate::Readable for PtptthrSpec {}
#[doc = "`write(|w| ..)` method takes [`ptptthr::W`](W) writer structure"]
impl crate::Writable for PtptthrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPTTHR to value 0"]
impl crate::Resettable for PtptthrSpec {
    const RESET_VALUE: u32 = 0;
}
