// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTSSR` reader"]
pub type R = crate::R<PtptssrSpec>;
#[doc = "Register `PTPTSSR` writer"]
pub type W = crate::W<PtptssrSpec>;
#[doc = "Field `TSSO` reader - TSSO"]
pub type TssoR = crate::BitReader;
#[doc = "Field `TSSO` writer - TSSO"]
pub type TssoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSTTR` reader - TSTTR"]
pub type TsttrR = crate::BitReader;
#[doc = "Field `TSTTR` writer - TSTTR"]
pub type TsttrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TSSO"]
    #[inline(always)]
    pub fn tsso(&self) -> TssoR {
        TssoR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TSTTR"]
    #[inline(always)]
    pub fn tsttr(&self) -> TsttrR {
        TsttrR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TSSO"]
    #[inline(always)]
    #[must_use]
    pub fn tsso(&mut self) -> TssoW<PtptssrSpec> {
        TssoW::new(self, 0)
    }
    #[doc = "Bit 1 - TSTTR"]
    #[inline(always)]
    #[must_use]
    pub fn tsttr(&mut self) -> TsttrW<PtptssrSpec> {
        TsttrW::new(self, 1)
    }
}
#[doc = "Ethernet PTP time stamp status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptssr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptssrSpec;
impl crate::RegisterSpec for PtptssrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`ptptssr::R`](R) reader structure"]
impl crate::Readable for PtptssrSpec {}
#[doc = "`reset()` method sets PTPTSSR to value 0"]
impl crate::Resettable for PtptssrSpec {
    const RESET_VALUE: u32 = 0;
}
