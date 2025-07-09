// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPPPSCR` reader"]
pub type R = crate::R<PtpppscrSpec>;
#[doc = "Register `PTPPPSCR` writer"]
pub type W = crate::W<PtpppscrSpec>;
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
    pub fn tsso(&mut self) -> TssoW<PtpppscrSpec> {
        TssoW::new(self, 0)
    }
    #[doc = "Bit 1 - TSTTR"]
    #[inline(always)]
    #[must_use]
    pub fn tsttr(&mut self) -> TsttrW<PtpppscrSpec> {
        TsttrW::new(self, 1)
    }
}
#[doc = "Ethernet PTP PPS control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptpppscr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtpppscrSpec;
impl crate::RegisterSpec for PtpppscrSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`ptpppscr::R`](R) reader structure"]
impl crate::Readable for PtpppscrSpec {}
#[doc = "`reset()` method sets PTPPPSCR to value 0"]
impl crate::Resettable for PtpppscrSpec {
    const RESET_VALUE: u32 = 0;
}
