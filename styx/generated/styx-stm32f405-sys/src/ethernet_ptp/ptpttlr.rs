// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTTLR` reader"]
pub type R = crate::R<PtpttlrSpec>;
#[doc = "Register `PTPTTLR` writer"]
pub type W = crate::W<PtpttlrSpec>;
#[doc = "Field `TTSL` reader - TTSL"]
pub type TtslR = crate::FieldReader<u32>;
#[doc = "Field `TTSL` writer - TTSL"]
pub type TtslW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TTSL"]
    #[inline(always)]
    pub fn ttsl(&self) -> TtslR {
        TtslR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TTSL"]
    #[inline(always)]
    #[must_use]
    pub fn ttsl(&mut self) -> TtslW<PtpttlrSpec> {
        TtslW::new(self, 0)
    }
}
#[doc = "Ethernet PTP target time low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptpttlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptpttlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtpttlrSpec;
impl crate::RegisterSpec for PtpttlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`ptpttlr::R`](R) reader structure"]
impl crate::Readable for PtpttlrSpec {}
#[doc = "`write(|w| ..)` method takes [`ptpttlr::W`](W) writer structure"]
impl crate::Writable for PtpttlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPTTLR to value 0"]
impl crate::Resettable for PtpttlrSpec {
    const RESET_VALUE: u32 = 0;
}
