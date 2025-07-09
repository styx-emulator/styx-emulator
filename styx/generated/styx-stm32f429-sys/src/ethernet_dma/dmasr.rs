// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMASR` reader"]
pub type R = crate::R<DmasrSpec>;
#[doc = "Register `DMASR` writer"]
pub type W = crate::W<DmasrSpec>;
#[doc = "Field `TS` reader - TS"]
pub type TsR = crate::BitReader;
#[doc = "Field `TS` writer - TS"]
pub type TsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TPSS` reader - TPSS"]
pub type TpssR = crate::BitReader;
#[doc = "Field `TPSS` writer - TPSS"]
pub type TpssW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TBUS` reader - TBUS"]
pub type TbusR = crate::BitReader;
#[doc = "Field `TBUS` writer - TBUS"]
pub type TbusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TJTS` reader - TJTS"]
pub type TjtsR = crate::BitReader;
#[doc = "Field `TJTS` writer - TJTS"]
pub type TjtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ROS` reader - ROS"]
pub type RosR = crate::BitReader;
#[doc = "Field `ROS` writer - ROS"]
pub type RosW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TUS` reader - TUS"]
pub type TusR = crate::BitReader;
#[doc = "Field `TUS` writer - TUS"]
pub type TusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RS` reader - RS"]
pub type RsR = crate::BitReader;
#[doc = "Field `RS` writer - RS"]
pub type RsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RBUS` reader - RBUS"]
pub type RbusR = crate::BitReader;
#[doc = "Field `RBUS` writer - RBUS"]
pub type RbusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RPSS` reader - RPSS"]
pub type RpssR = crate::BitReader;
#[doc = "Field `RPSS` writer - RPSS"]
pub type RpssW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PWTS` reader - PWTS"]
pub type PwtsR = crate::BitReader;
#[doc = "Field `PWTS` writer - PWTS"]
pub type PwtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETS` reader - ETS"]
pub type EtsR = crate::BitReader;
#[doc = "Field `ETS` writer - ETS"]
pub type EtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FBES` reader - FBES"]
pub type FbesR = crate::BitReader;
#[doc = "Field `FBES` writer - FBES"]
pub type FbesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERS` reader - ERS"]
pub type ErsR = crate::BitReader;
#[doc = "Field `ERS` writer - ERS"]
pub type ErsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AIS` reader - AIS"]
pub type AisR = crate::BitReader;
#[doc = "Field `AIS` writer - AIS"]
pub type AisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NIS` reader - NIS"]
pub type NisR = crate::BitReader;
#[doc = "Field `NIS` writer - NIS"]
pub type NisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RPS` reader - RPS"]
pub type RpsR = crate::FieldReader;
#[doc = "Field `RPS` writer - RPS"]
pub type RpsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `TPS` reader - TPS"]
pub type TpsR = crate::FieldReader;
#[doc = "Field `TPS` writer - TPS"]
pub type TpsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `EBS` reader - EBS"]
pub type EbsR = crate::FieldReader;
#[doc = "Field `EBS` writer - EBS"]
pub type EbsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `MMCS` reader - MMCS"]
pub type MmcsR = crate::BitReader;
#[doc = "Field `MMCS` writer - MMCS"]
pub type MmcsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PMTS` reader - PMTS"]
pub type PmtsR = crate::BitReader;
#[doc = "Field `PMTS` writer - PMTS"]
pub type PmtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSTS` reader - TSTS"]
pub type TstsR = crate::BitReader;
#[doc = "Field `TSTS` writer - TSTS"]
pub type TstsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TS"]
    #[inline(always)]
    pub fn ts(&self) -> TsR {
        TsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TPSS"]
    #[inline(always)]
    pub fn tpss(&self) -> TpssR {
        TpssR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - TBUS"]
    #[inline(always)]
    pub fn tbus(&self) -> TbusR {
        TbusR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - TJTS"]
    #[inline(always)]
    pub fn tjts(&self) -> TjtsR {
        TjtsR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - ROS"]
    #[inline(always)]
    pub fn ros(&self) -> RosR {
        RosR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - TUS"]
    #[inline(always)]
    pub fn tus(&self) -> TusR {
        TusR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - RS"]
    #[inline(always)]
    pub fn rs(&self) -> RsR {
        RsR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - RBUS"]
    #[inline(always)]
    pub fn rbus(&self) -> RbusR {
        RbusR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - RPSS"]
    #[inline(always)]
    pub fn rpss(&self) -> RpssR {
        RpssR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - PWTS"]
    #[inline(always)]
    pub fn pwts(&self) -> PwtsR {
        PwtsR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - ETS"]
    #[inline(always)]
    pub fn ets(&self) -> EtsR {
        EtsR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 13 - FBES"]
    #[inline(always)]
    pub fn fbes(&self) -> FbesR {
        FbesR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - ERS"]
    #[inline(always)]
    pub fn ers(&self) -> ErsR {
        ErsR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - AIS"]
    #[inline(always)]
    pub fn ais(&self) -> AisR {
        AisR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - NIS"]
    #[inline(always)]
    pub fn nis(&self) -> NisR {
        NisR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:19 - RPS"]
    #[inline(always)]
    pub fn rps(&self) -> RpsR {
        RpsR::new(((self.bits >> 17) & 7) as u8)
    }
    #[doc = "Bits 20:22 - TPS"]
    #[inline(always)]
    pub fn tps(&self) -> TpsR {
        TpsR::new(((self.bits >> 20) & 7) as u8)
    }
    #[doc = "Bits 23:25 - EBS"]
    #[inline(always)]
    pub fn ebs(&self) -> EbsR {
        EbsR::new(((self.bits >> 23) & 7) as u8)
    }
    #[doc = "Bit 27 - MMCS"]
    #[inline(always)]
    pub fn mmcs(&self) -> MmcsR {
        MmcsR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - PMTS"]
    #[inline(always)]
    pub fn pmts(&self) -> PmtsR {
        PmtsR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - TSTS"]
    #[inline(always)]
    pub fn tsts(&self) -> TstsR {
        TstsR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TS"]
    #[inline(always)]
    #[must_use]
    pub fn ts(&mut self) -> TsW<DmasrSpec> {
        TsW::new(self, 0)
    }
    #[doc = "Bit 1 - TPSS"]
    #[inline(always)]
    #[must_use]
    pub fn tpss(&mut self) -> TpssW<DmasrSpec> {
        TpssW::new(self, 1)
    }
    #[doc = "Bit 2 - TBUS"]
    #[inline(always)]
    #[must_use]
    pub fn tbus(&mut self) -> TbusW<DmasrSpec> {
        TbusW::new(self, 2)
    }
    #[doc = "Bit 3 - TJTS"]
    #[inline(always)]
    #[must_use]
    pub fn tjts(&mut self) -> TjtsW<DmasrSpec> {
        TjtsW::new(self, 3)
    }
    #[doc = "Bit 4 - ROS"]
    #[inline(always)]
    #[must_use]
    pub fn ros(&mut self) -> RosW<DmasrSpec> {
        RosW::new(self, 4)
    }
    #[doc = "Bit 5 - TUS"]
    #[inline(always)]
    #[must_use]
    pub fn tus(&mut self) -> TusW<DmasrSpec> {
        TusW::new(self, 5)
    }
    #[doc = "Bit 6 - RS"]
    #[inline(always)]
    #[must_use]
    pub fn rs(&mut self) -> RsW<DmasrSpec> {
        RsW::new(self, 6)
    }
    #[doc = "Bit 7 - RBUS"]
    #[inline(always)]
    #[must_use]
    pub fn rbus(&mut self) -> RbusW<DmasrSpec> {
        RbusW::new(self, 7)
    }
    #[doc = "Bit 8 - RPSS"]
    #[inline(always)]
    #[must_use]
    pub fn rpss(&mut self) -> RpssW<DmasrSpec> {
        RpssW::new(self, 8)
    }
    #[doc = "Bit 9 - PWTS"]
    #[inline(always)]
    #[must_use]
    pub fn pwts(&mut self) -> PwtsW<DmasrSpec> {
        PwtsW::new(self, 9)
    }
    #[doc = "Bit 10 - ETS"]
    #[inline(always)]
    #[must_use]
    pub fn ets(&mut self) -> EtsW<DmasrSpec> {
        EtsW::new(self, 10)
    }
    #[doc = "Bit 13 - FBES"]
    #[inline(always)]
    #[must_use]
    pub fn fbes(&mut self) -> FbesW<DmasrSpec> {
        FbesW::new(self, 13)
    }
    #[doc = "Bit 14 - ERS"]
    #[inline(always)]
    #[must_use]
    pub fn ers(&mut self) -> ErsW<DmasrSpec> {
        ErsW::new(self, 14)
    }
    #[doc = "Bit 15 - AIS"]
    #[inline(always)]
    #[must_use]
    pub fn ais(&mut self) -> AisW<DmasrSpec> {
        AisW::new(self, 15)
    }
    #[doc = "Bit 16 - NIS"]
    #[inline(always)]
    #[must_use]
    pub fn nis(&mut self) -> NisW<DmasrSpec> {
        NisW::new(self, 16)
    }
    #[doc = "Bits 17:19 - RPS"]
    #[inline(always)]
    #[must_use]
    pub fn rps(&mut self) -> RpsW<DmasrSpec> {
        RpsW::new(self, 17)
    }
    #[doc = "Bits 20:22 - TPS"]
    #[inline(always)]
    #[must_use]
    pub fn tps(&mut self) -> TpsW<DmasrSpec> {
        TpsW::new(self, 20)
    }
    #[doc = "Bits 23:25 - EBS"]
    #[inline(always)]
    #[must_use]
    pub fn ebs(&mut self) -> EbsW<DmasrSpec> {
        EbsW::new(self, 23)
    }
    #[doc = "Bit 27 - MMCS"]
    #[inline(always)]
    #[must_use]
    pub fn mmcs(&mut self) -> MmcsW<DmasrSpec> {
        MmcsW::new(self, 27)
    }
    #[doc = "Bit 28 - PMTS"]
    #[inline(always)]
    #[must_use]
    pub fn pmts(&mut self) -> PmtsW<DmasrSpec> {
        PmtsW::new(self, 28)
    }
    #[doc = "Bit 29 - TSTS"]
    #[inline(always)]
    #[must_use]
    pub fn tsts(&mut self) -> TstsW<DmasrSpec> {
        TstsW::new(self, 29)
    }
}
#[doc = "Ethernet DMA status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmasr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmasr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmasrSpec;
impl crate::RegisterSpec for DmasrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`dmasr::R`](R) reader structure"]
impl crate::Readable for DmasrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmasr::W`](W) writer structure"]
impl crate::Writable for DmasrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMASR to value 0"]
impl crate::Resettable for DmasrSpec {
    const RESET_VALUE: u32 = 0;
}
