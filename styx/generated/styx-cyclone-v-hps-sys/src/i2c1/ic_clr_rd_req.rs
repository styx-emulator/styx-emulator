// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_rd_req` reader"]
pub type R = crate::R<IcClrRdReqSpec>;
#[doc = "Register `ic_clr_rd_req` writer"]
pub type W = crate::W<IcClrRdReqSpec>;
#[doc = "Field `clr_rd_req` reader - Read this register to clear the RD_REQ interrupt (bit 5) of the ic_raw_intr_stat register."]
pub type ClrRdReqR = crate::BitReader;
#[doc = "Field `clr_rd_req` writer - Read this register to clear the RD_REQ interrupt (bit 5) of the ic_raw_intr_stat register."]
pub type ClrRdReqW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the RD_REQ interrupt (bit 5) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_rd_req(&self) -> ClrRdReqR {
        ClrRdReqR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the RD_REQ interrupt (bit 5) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_rd_req(&mut self) -> ClrRdReqW<IcClrRdReqSpec> {
        ClrRdReqW::new(self, 0)
    }
}
#[doc = "Clear RD_REQ Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rd_req::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrRdReqSpec;
impl crate::RegisterSpec for IcClrRdReqSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`ic_clr_rd_req::R`](R) reader structure"]
impl crate::Readable for IcClrRdReqSpec {}
#[doc = "`reset()` method sets ic_clr_rd_req to value 0"]
impl crate::Resettable for IcClrRdReqSpec {
    const RESET_VALUE: u32 = 0;
}
