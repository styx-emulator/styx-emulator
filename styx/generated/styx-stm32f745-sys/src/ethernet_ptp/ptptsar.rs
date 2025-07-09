// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTSAR` reader"]
pub type R = crate::R<PtptsarSpec>;
#[doc = "Register `PTPTSAR` writer"]
pub type W = crate::W<PtptsarSpec>;
#[doc = "Field `TSA` reader - TSA"]
pub type TsaR = crate::FieldReader<u32>;
#[doc = "Field `TSA` writer - TSA"]
pub type TsaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TSA"]
    #[inline(always)]
    pub fn tsa(&self) -> TsaR {
        TsaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TSA"]
    #[inline(always)]
    #[must_use]
    pub fn tsa(&mut self) -> TsaW<PtptsarSpec> {
        TsaW::new(self, 0)
    }
}
#[doc = "Ethernet PTP time stamp addend register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptsar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptsar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptsarSpec;
impl crate::RegisterSpec for PtptsarSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ptptsar::R`](R) reader structure"]
impl crate::Readable for PtptsarSpec {}
#[doc = "`write(|w| ..)` method takes [`ptptsar::W`](W) writer structure"]
impl crate::Writable for PtptsarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPTSAR to value 0"]
impl crate::Resettable for PtptsarSpec {
    const RESET_VALUE: u32 = 0;
}
