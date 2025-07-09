// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_GRXSTSR_Host` reader"]
pub type R = crate::R<OtgFsGrxstsrHostSpec>;
#[doc = "Register `OTG_FS_GRXSTSR_Host` writer"]
pub type W = crate::W<OtgFsGrxstsrHostSpec>;
#[doc = "Field `CHNUM` reader - Endpoint number"]
pub type ChnumR = crate::FieldReader;
#[doc = "Field `CHNUM` writer - Endpoint number"]
pub type ChnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `BCNT` reader - Byte count"]
pub type BcntR = crate::FieldReader<u16>;
#[doc = "Field `BCNT` writer - Byte count"]
pub type BcntW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `DPID` reader - Data PID"]
pub type DpidR = crate::FieldReader;
#[doc = "Field `DPID` writer - Data PID"]
pub type DpidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PKTSTS` reader - Packet status"]
pub type PktstsR = crate::FieldReader;
#[doc = "Field `PKTSTS` writer - Packet status"]
pub type PktstsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Endpoint number"]
    #[inline(always)]
    pub fn chnum(&self) -> ChnumR {
        ChnumR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:14 - Byte count"]
    #[inline(always)]
    pub fn bcnt(&self) -> BcntR {
        BcntR::new(((self.bits >> 4) & 0x07ff) as u16)
    }
    #[doc = "Bits 15:16 - Data PID"]
    #[inline(always)]
    pub fn dpid(&self) -> DpidR {
        DpidR::new(((self.bits >> 15) & 3) as u8)
    }
    #[doc = "Bits 17:20 - Packet status"]
    #[inline(always)]
    pub fn pktsts(&self) -> PktstsR {
        PktstsR::new(((self.bits >> 17) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Endpoint number"]
    #[inline(always)]
    #[must_use]
    pub fn chnum(&mut self) -> ChnumW<OtgFsGrxstsrHostSpec> {
        ChnumW::new(self, 0)
    }
    #[doc = "Bits 4:14 - Byte count"]
    #[inline(always)]
    #[must_use]
    pub fn bcnt(&mut self) -> BcntW<OtgFsGrxstsrHostSpec> {
        BcntW::new(self, 4)
    }
    #[doc = "Bits 15:16 - Data PID"]
    #[inline(always)]
    #[must_use]
    pub fn dpid(&mut self) -> DpidW<OtgFsGrxstsrHostSpec> {
        DpidW::new(self, 15)
    }
    #[doc = "Bits 17:20 - Packet status"]
    #[inline(always)]
    #[must_use]
    pub fn pktsts(&mut self) -> PktstsW<OtgFsGrxstsrHostSpec> {
        PktstsW::new(self, 17)
    }
}
#[doc = "OTG_FS Receive status debug read(Host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxstsr_host::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGrxstsrHostSpec;
impl crate::RegisterSpec for OtgFsGrxstsrHostSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`otg_fs_grxstsr_host::R`](R) reader structure"]
impl crate::Readable for OtgFsGrxstsrHostSpec {}
#[doc = "`reset()` method sets OTG_FS_GRXSTSR_Host to value 0"]
impl crate::Resettable for OtgFsGrxstsrHostSpec {
    const RESET_VALUE: u32 = 0;
}
