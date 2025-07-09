// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_GRXSTSP_Device` reader"]
pub type R = crate::R<OtgFsGrxstspDeviceSpec>;
#[doc = "Register `OTG_FS_GRXSTSP_Device` writer"]
pub type W = crate::W<OtgFsGrxstspDeviceSpec>;
#[doc = "Field `EPNUM` reader - Endpoint number"]
pub type EpnumR = crate::FieldReader;
#[doc = "Field `EPNUM` writer - Endpoint number"]
pub type EpnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
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
#[doc = "Field `FRMNUM` reader - Frame number"]
pub type FrmnumR = crate::FieldReader;
#[doc = "Field `FRMNUM` writer - Frame number"]
pub type FrmnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Endpoint number"]
    #[inline(always)]
    pub fn epnum(&self) -> EpnumR {
        EpnumR::new((self.bits & 0x0f) as u8)
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
    #[doc = "Bits 21:24 - Frame number"]
    #[inline(always)]
    pub fn frmnum(&self) -> FrmnumR {
        FrmnumR::new(((self.bits >> 21) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Endpoint number"]
    #[inline(always)]
    #[must_use]
    pub fn epnum(&mut self) -> EpnumW<OtgFsGrxstspDeviceSpec> {
        EpnumW::new(self, 0)
    }
    #[doc = "Bits 4:14 - Byte count"]
    #[inline(always)]
    #[must_use]
    pub fn bcnt(&mut self) -> BcntW<OtgFsGrxstspDeviceSpec> {
        BcntW::new(self, 4)
    }
    #[doc = "Bits 15:16 - Data PID"]
    #[inline(always)]
    #[must_use]
    pub fn dpid(&mut self) -> DpidW<OtgFsGrxstspDeviceSpec> {
        DpidW::new(self, 15)
    }
    #[doc = "Bits 17:20 - Packet status"]
    #[inline(always)]
    #[must_use]
    pub fn pktsts(&mut self) -> PktstsW<OtgFsGrxstspDeviceSpec> {
        PktstsW::new(self, 17)
    }
    #[doc = "Bits 21:24 - Frame number"]
    #[inline(always)]
    #[must_use]
    pub fn frmnum(&mut self) -> FrmnumW<OtgFsGrxstspDeviceSpec> {
        FrmnumW::new(self, 21)
    }
}
#[doc = "OTG status read and pop register (Device mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxstsp_device::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGrxstspDeviceSpec;
impl crate::RegisterSpec for OtgFsGrxstspDeviceSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`otg_fs_grxstsp_device::R`](R) reader structure"]
impl crate::Readable for OtgFsGrxstspDeviceSpec {}
#[doc = "`reset()` method sets OTG_FS_GRXSTSP_Device to value 0x0200_0400"]
impl crate::Resettable for OtgFsGrxstspDeviceSpec {
    const RESET_VALUE: u32 = 0x0200_0400;
}
