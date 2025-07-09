// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DIEPCTL1` reader"]
pub type R = crate::R<OtgFsDiepctl1Spec>;
#[doc = "Register `OTG_FS_DIEPCTL1` writer"]
pub type W = crate::W<OtgFsDiepctl1Spec>;
#[doc = "Field `MPSIZ` reader - MPSIZ"]
pub type MpsizR = crate::FieldReader<u16>;
#[doc = "Field `MPSIZ` writer - MPSIZ"]
pub type MpsizW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `USBAEP` reader - USBAEP"]
pub type UsbaepR = crate::BitReader;
#[doc = "Field `USBAEP` writer - USBAEP"]
pub type UsbaepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EONUM_DPID` reader - EONUM/DPID"]
pub type EonumDpidR = crate::BitReader;
#[doc = "Field `EONUM_DPID` writer - EONUM/DPID"]
pub type EonumDpidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NAKSTS` reader - NAKSTS"]
pub type NakstsR = crate::BitReader;
#[doc = "Field `NAKSTS` writer - NAKSTS"]
pub type NakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPTYP` reader - EPTYP"]
pub type EptypR = crate::FieldReader;
#[doc = "Field `EPTYP` writer - EPTYP"]
pub type EptypW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `Stall` reader - Stall"]
pub type StallR = crate::BitReader;
#[doc = "Field `Stall` writer - Stall"]
pub type StallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFNUM` reader - TXFNUM"]
pub type TxfnumR = crate::FieldReader;
#[doc = "Field `TXFNUM` writer - TXFNUM"]
pub type TxfnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `CNAK` reader - CNAK"]
pub type CnakR = crate::BitReader;
#[doc = "Field `CNAK` writer - CNAK"]
pub type CnakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SNAK` reader - SNAK"]
pub type SnakR = crate::BitReader;
#[doc = "Field `SNAK` writer - SNAK"]
pub type SnakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SD0PID_SEVNFRM` reader - SD0PID/SEVNFRM"]
pub type Sd0pidSevnfrmR = crate::BitReader;
#[doc = "Field `SD0PID_SEVNFRM` writer - SD0PID/SEVNFRM"]
pub type Sd0pidSevnfrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SODDFRM_SD1PID` reader - SODDFRM/SD1PID"]
pub type SoddfrmSd1pidR = crate::BitReader;
#[doc = "Field `SODDFRM_SD1PID` writer - SODDFRM/SD1PID"]
pub type SoddfrmSd1pidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDIS` reader - EPDIS"]
pub type EpdisR = crate::BitReader;
#[doc = "Field `EPDIS` writer - EPDIS"]
pub type EpdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPENA` reader - EPENA"]
pub type EpenaR = crate::BitReader;
#[doc = "Field `EPENA` writer - EPENA"]
pub type EpenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:10 - MPSIZ"]
    #[inline(always)]
    pub fn mpsiz(&self) -> MpsizR {
        MpsizR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bit 15 - USBAEP"]
    #[inline(always)]
    pub fn usbaep(&self) -> UsbaepR {
        UsbaepR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - EONUM/DPID"]
    #[inline(always)]
    pub fn eonum_dpid(&self) -> EonumDpidR {
        EonumDpidR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - NAKSTS"]
    #[inline(always)]
    pub fn naksts(&self) -> NakstsR {
        NakstsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - EPTYP"]
    #[inline(always)]
    pub fn eptyp(&self) -> EptypR {
        EptypR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bit 21 - Stall"]
    #[inline(always)]
    pub fn stall(&self) -> StallR {
        StallR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bits 22:25 - TXFNUM"]
    #[inline(always)]
    pub fn txfnum(&self) -> TxfnumR {
        TxfnumR::new(((self.bits >> 22) & 0x0f) as u8)
    }
    #[doc = "Bit 26 - CNAK"]
    #[inline(always)]
    pub fn cnak(&self) -> CnakR {
        CnakR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - SNAK"]
    #[inline(always)]
    pub fn snak(&self) -> SnakR {
        SnakR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - SD0PID/SEVNFRM"]
    #[inline(always)]
    pub fn sd0pid_sevnfrm(&self) -> Sd0pidSevnfrmR {
        Sd0pidSevnfrmR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - SODDFRM/SD1PID"]
    #[inline(always)]
    pub fn soddfrm_sd1pid(&self) -> SoddfrmSd1pidR {
        SoddfrmSd1pidR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - EPDIS"]
    #[inline(always)]
    pub fn epdis(&self) -> EpdisR {
        EpdisR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - EPENA"]
    #[inline(always)]
    pub fn epena(&self) -> EpenaR {
        EpenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:10 - MPSIZ"]
    #[inline(always)]
    #[must_use]
    pub fn mpsiz(&mut self) -> MpsizW<OtgFsDiepctl1Spec> {
        MpsizW::new(self, 0)
    }
    #[doc = "Bit 15 - USBAEP"]
    #[inline(always)]
    #[must_use]
    pub fn usbaep(&mut self) -> UsbaepW<OtgFsDiepctl1Spec> {
        UsbaepW::new(self, 15)
    }
    #[doc = "Bit 16 - EONUM/DPID"]
    #[inline(always)]
    #[must_use]
    pub fn eonum_dpid(&mut self) -> EonumDpidW<OtgFsDiepctl1Spec> {
        EonumDpidW::new(self, 16)
    }
    #[doc = "Bit 17 - NAKSTS"]
    #[inline(always)]
    #[must_use]
    pub fn naksts(&mut self) -> NakstsW<OtgFsDiepctl1Spec> {
        NakstsW::new(self, 17)
    }
    #[doc = "Bits 18:19 - EPTYP"]
    #[inline(always)]
    #[must_use]
    pub fn eptyp(&mut self) -> EptypW<OtgFsDiepctl1Spec> {
        EptypW::new(self, 18)
    }
    #[doc = "Bit 21 - Stall"]
    #[inline(always)]
    #[must_use]
    pub fn stall(&mut self) -> StallW<OtgFsDiepctl1Spec> {
        StallW::new(self, 21)
    }
    #[doc = "Bits 22:25 - TXFNUM"]
    #[inline(always)]
    #[must_use]
    pub fn txfnum(&mut self) -> TxfnumW<OtgFsDiepctl1Spec> {
        TxfnumW::new(self, 22)
    }
    #[doc = "Bit 26 - CNAK"]
    #[inline(always)]
    #[must_use]
    pub fn cnak(&mut self) -> CnakW<OtgFsDiepctl1Spec> {
        CnakW::new(self, 26)
    }
    #[doc = "Bit 27 - SNAK"]
    #[inline(always)]
    #[must_use]
    pub fn snak(&mut self) -> SnakW<OtgFsDiepctl1Spec> {
        SnakW::new(self, 27)
    }
    #[doc = "Bit 28 - SD0PID/SEVNFRM"]
    #[inline(always)]
    #[must_use]
    pub fn sd0pid_sevnfrm(&mut self) -> Sd0pidSevnfrmW<OtgFsDiepctl1Spec> {
        Sd0pidSevnfrmW::new(self, 28)
    }
    #[doc = "Bit 29 - SODDFRM/SD1PID"]
    #[inline(always)]
    #[must_use]
    pub fn soddfrm_sd1pid(&mut self) -> SoddfrmSd1pidW<OtgFsDiepctl1Spec> {
        SoddfrmSd1pidW::new(self, 29)
    }
    #[doc = "Bit 30 - EPDIS"]
    #[inline(always)]
    #[must_use]
    pub fn epdis(&mut self) -> EpdisW<OtgFsDiepctl1Spec> {
        EpdisW::new(self, 30)
    }
    #[doc = "Bit 31 - EPENA"]
    #[inline(always)]
    #[must_use]
    pub fn epena(&mut self) -> EpenaW<OtgFsDiepctl1Spec> {
        EpenaW::new(self, 31)
    }
}
#[doc = "OTG device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDiepctl1Spec;
impl crate::RegisterSpec for OtgFsDiepctl1Spec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`otg_fs_diepctl1::R`](R) reader structure"]
impl crate::Readable for OtgFsDiepctl1Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_diepctl1::W`](W) writer structure"]
impl crate::Writable for OtgFsDiepctl1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DIEPCTL1 to value 0"]
impl crate::Resettable for OtgFsDiepctl1Spec {
    const RESET_VALUE: u32 = 0;
}
