// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DOEPCTL1` reader"]
pub type R = crate::R<OtgHsDoepctl1Spec>;
#[doc = "Register `OTG_HS_DOEPCTL1` writer"]
pub type W = crate::W<OtgHsDoepctl1Spec>;
#[doc = "Field `MPSIZ` reader - Maximum packet size"]
pub type MpsizR = crate::FieldReader<u16>;
#[doc = "Field `MPSIZ` writer - Maximum packet size"]
pub type MpsizW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `USBAEP` reader - USB active endpoint"]
pub type UsbaepR = crate::BitReader;
#[doc = "Field `USBAEP` writer - USB active endpoint"]
pub type UsbaepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EONUM_DPID` reader - Even odd frame/Endpoint data PID"]
pub type EonumDpidR = crate::BitReader;
#[doc = "Field `EONUM_DPID` writer - Even odd frame/Endpoint data PID"]
pub type EonumDpidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NAKSTS` reader - NAK status"]
pub type NakstsR = crate::BitReader;
#[doc = "Field `NAKSTS` writer - NAK status"]
pub type NakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPTYP` reader - Endpoint type"]
pub type EptypR = crate::FieldReader;
#[doc = "Field `EPTYP` writer - Endpoint type"]
pub type EptypW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SNPM` reader - Snoop mode"]
pub type SnpmR = crate::BitReader;
#[doc = "Field `SNPM` writer - Snoop mode"]
pub type SnpmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `Stall` reader - STALL handshake"]
pub type StallR = crate::BitReader;
#[doc = "Field `Stall` writer - STALL handshake"]
pub type StallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CNAK` reader - Clear NAK"]
pub type CnakR = crate::BitReader;
#[doc = "Field `CNAK` writer - Clear NAK"]
pub type CnakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SNAK` reader - Set NAK"]
pub type SnakR = crate::BitReader;
#[doc = "Field `SNAK` writer - Set NAK"]
pub type SnakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SD0PID_SEVNFRM` reader - Set DATA0 PID/Set even frame"]
pub type Sd0pidSevnfrmR = crate::BitReader;
#[doc = "Field `SD0PID_SEVNFRM` writer - Set DATA0 PID/Set even frame"]
pub type Sd0pidSevnfrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SODDFRM` reader - Set odd frame"]
pub type SoddfrmR = crate::BitReader;
#[doc = "Field `SODDFRM` writer - Set odd frame"]
pub type SoddfrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDIS` reader - Endpoint disable"]
pub type EpdisR = crate::BitReader;
#[doc = "Field `EPDIS` writer - Endpoint disable"]
pub type EpdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPENA` reader - Endpoint enable"]
pub type EpenaR = crate::BitReader;
#[doc = "Field `EPENA` writer - Endpoint enable"]
pub type EpenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:10 - Maximum packet size"]
    #[inline(always)]
    pub fn mpsiz(&self) -> MpsizR {
        MpsizR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bit 15 - USB active endpoint"]
    #[inline(always)]
    pub fn usbaep(&self) -> UsbaepR {
        UsbaepR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Even odd frame/Endpoint data PID"]
    #[inline(always)]
    pub fn eonum_dpid(&self) -> EonumDpidR {
        EonumDpidR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - NAK status"]
    #[inline(always)]
    pub fn naksts(&self) -> NakstsR {
        NakstsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - Endpoint type"]
    #[inline(always)]
    pub fn eptyp(&self) -> EptypR {
        EptypR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bit 20 - Snoop mode"]
    #[inline(always)]
    pub fn snpm(&self) -> SnpmR {
        SnpmR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - STALL handshake"]
    #[inline(always)]
    pub fn stall(&self) -> StallR {
        StallR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 26 - Clear NAK"]
    #[inline(always)]
    pub fn cnak(&self) -> CnakR {
        CnakR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Set NAK"]
    #[inline(always)]
    pub fn snak(&self) -> SnakR {
        SnakR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Set DATA0 PID/Set even frame"]
    #[inline(always)]
    pub fn sd0pid_sevnfrm(&self) -> Sd0pidSevnfrmR {
        Sd0pidSevnfrmR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Set odd frame"]
    #[inline(always)]
    pub fn soddfrm(&self) -> SoddfrmR {
        SoddfrmR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Endpoint disable"]
    #[inline(always)]
    pub fn epdis(&self) -> EpdisR {
        EpdisR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Endpoint enable"]
    #[inline(always)]
    pub fn epena(&self) -> EpenaR {
        EpenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:10 - Maximum packet size"]
    #[inline(always)]
    #[must_use]
    pub fn mpsiz(&mut self) -> MpsizW<OtgHsDoepctl1Spec> {
        MpsizW::new(self, 0)
    }
    #[doc = "Bit 15 - USB active endpoint"]
    #[inline(always)]
    #[must_use]
    pub fn usbaep(&mut self) -> UsbaepW<OtgHsDoepctl1Spec> {
        UsbaepW::new(self, 15)
    }
    #[doc = "Bit 16 - Even odd frame/Endpoint data PID"]
    #[inline(always)]
    #[must_use]
    pub fn eonum_dpid(&mut self) -> EonumDpidW<OtgHsDoepctl1Spec> {
        EonumDpidW::new(self, 16)
    }
    #[doc = "Bit 17 - NAK status"]
    #[inline(always)]
    #[must_use]
    pub fn naksts(&mut self) -> NakstsW<OtgHsDoepctl1Spec> {
        NakstsW::new(self, 17)
    }
    #[doc = "Bits 18:19 - Endpoint type"]
    #[inline(always)]
    #[must_use]
    pub fn eptyp(&mut self) -> EptypW<OtgHsDoepctl1Spec> {
        EptypW::new(self, 18)
    }
    #[doc = "Bit 20 - Snoop mode"]
    #[inline(always)]
    #[must_use]
    pub fn snpm(&mut self) -> SnpmW<OtgHsDoepctl1Spec> {
        SnpmW::new(self, 20)
    }
    #[doc = "Bit 21 - STALL handshake"]
    #[inline(always)]
    #[must_use]
    pub fn stall(&mut self) -> StallW<OtgHsDoepctl1Spec> {
        StallW::new(self, 21)
    }
    #[doc = "Bit 26 - Clear NAK"]
    #[inline(always)]
    #[must_use]
    pub fn cnak(&mut self) -> CnakW<OtgHsDoepctl1Spec> {
        CnakW::new(self, 26)
    }
    #[doc = "Bit 27 - Set NAK"]
    #[inline(always)]
    #[must_use]
    pub fn snak(&mut self) -> SnakW<OtgHsDoepctl1Spec> {
        SnakW::new(self, 27)
    }
    #[doc = "Bit 28 - Set DATA0 PID/Set even frame"]
    #[inline(always)]
    #[must_use]
    pub fn sd0pid_sevnfrm(&mut self) -> Sd0pidSevnfrmW<OtgHsDoepctl1Spec> {
        Sd0pidSevnfrmW::new(self, 28)
    }
    #[doc = "Bit 29 - Set odd frame"]
    #[inline(always)]
    #[must_use]
    pub fn soddfrm(&mut self) -> SoddfrmW<OtgHsDoepctl1Spec> {
        SoddfrmW::new(self, 29)
    }
    #[doc = "Bit 30 - Endpoint disable"]
    #[inline(always)]
    #[must_use]
    pub fn epdis(&mut self) -> EpdisW<OtgHsDoepctl1Spec> {
        EpdisW::new(self, 30)
    }
    #[doc = "Bit 31 - Endpoint enable"]
    #[inline(always)]
    #[must_use]
    pub fn epena(&mut self) -> EpenaW<OtgHsDoepctl1Spec> {
        EpenaW::new(self, 31)
    }
}
#[doc = "OTG device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDoepctl1Spec;
impl crate::RegisterSpec for OtgHsDoepctl1Spec {
    type Ux = u32;
    const OFFSET: u64 = 800u64;
}
#[doc = "`read()` method returns [`otg_hs_doepctl1::R`](R) reader structure"]
impl crate::Readable for OtgHsDoepctl1Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_doepctl1::W`](W) writer structure"]
impl crate::Writable for OtgHsDoepctl1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DOEPCTL1 to value 0"]
impl crate::Resettable for OtgHsDoepctl1Spec {
    const RESET_VALUE: u32 = 0;
}
