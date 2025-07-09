// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_GUSBCFG` reader"]
pub type R = crate::R<OtgHsGusbcfgSpec>;
#[doc = "Register `OTG_HS_GUSBCFG` writer"]
pub type W = crate::W<OtgHsGusbcfgSpec>;
#[doc = "Field `TOCAL` reader - FS timeout calibration"]
pub type TocalR = crate::FieldReader;
#[doc = "Field `TOCAL` writer - FS timeout calibration"]
pub type TocalW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `PHYSEL` reader - USB 2.0 high-speed ULPI PHY or USB 1.1 full-speed serial transceiver select"]
pub type PhyselR = crate::BitReader;
#[doc = "Field `PHYSEL` writer - USB 2.0 high-speed ULPI PHY or USB 1.1 full-speed serial transceiver select"]
pub type PhyselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRPCAP` reader - SRP-capable"]
pub type SrpcapR = crate::BitReader;
#[doc = "Field `SRPCAP` writer - SRP-capable"]
pub type SrpcapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNPCAP` reader - HNP-capable"]
pub type HnpcapR = crate::BitReader;
#[doc = "Field `HNPCAP` writer - HNP-capable"]
pub type HnpcapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TRDT` reader - USB turnaround time"]
pub type TrdtR = crate::FieldReader;
#[doc = "Field `TRDT` writer - USB turnaround time"]
pub type TrdtW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PHYLPCS` reader - PHY Low-power clock select"]
pub type PhylpcsR = crate::BitReader;
#[doc = "Field `PHYLPCS` writer - PHY Low-power clock select"]
pub type PhylpcsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ULPIFSLS` reader - ULPI FS/LS select"]
pub type UlpifslsR = crate::BitReader;
#[doc = "Field `ULPIFSLS` writer - ULPI FS/LS select"]
pub type UlpifslsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ULPIAR` reader - ULPI Auto-resume"]
pub type UlpiarR = crate::BitReader;
#[doc = "Field `ULPIAR` writer - ULPI Auto-resume"]
pub type UlpiarW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ULPICSM` reader - ULPI Clock SuspendM"]
pub type UlpicsmR = crate::BitReader;
#[doc = "Field `ULPICSM` writer - ULPI Clock SuspendM"]
pub type UlpicsmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ULPIEVBUSD` reader - ULPI External VBUS Drive"]
pub type UlpievbusdR = crate::BitReader;
#[doc = "Field `ULPIEVBUSD` writer - ULPI External VBUS Drive"]
pub type UlpievbusdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ULPIEVBUSI` reader - ULPI external VBUS indicator"]
pub type UlpievbusiR = crate::BitReader;
#[doc = "Field `ULPIEVBUSI` writer - ULPI external VBUS indicator"]
pub type UlpievbusiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSDPS` reader - TermSel DLine pulsing selection"]
pub type TsdpsR = crate::BitReader;
#[doc = "Field `TSDPS` writer - TermSel DLine pulsing selection"]
pub type TsdpsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PCCI` reader - Indicator complement"]
pub type PcciR = crate::BitReader;
#[doc = "Field `PCCI` writer - Indicator complement"]
pub type PcciW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTCI` reader - Indicator pass through"]
pub type PtciR = crate::BitReader;
#[doc = "Field `PTCI` writer - Indicator pass through"]
pub type PtciW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ULPIIPD` reader - ULPI interface protect disable"]
pub type UlpiipdR = crate::BitReader;
#[doc = "Field `ULPIIPD` writer - ULPI interface protect disable"]
pub type UlpiipdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FHMOD` reader - Forced host mode"]
pub type FhmodR = crate::BitReader;
#[doc = "Field `FHMOD` writer - Forced host mode"]
pub type FhmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FDMOD` reader - Forced peripheral mode"]
pub type FdmodR = crate::BitReader;
#[doc = "Field `FDMOD` writer - Forced peripheral mode"]
pub type FdmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTXPKT` reader - Corrupt Tx packet"]
pub type CtxpktR = crate::BitReader;
#[doc = "Field `CTXPKT` writer - Corrupt Tx packet"]
pub type CtxpktW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - FS timeout calibration"]
    #[inline(always)]
    pub fn tocal(&self) -> TocalR {
        TocalR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 6 - USB 2.0 high-speed ULPI PHY or USB 1.1 full-speed serial transceiver select"]
    #[inline(always)]
    pub fn physel(&self) -> PhyselR {
        PhyselR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - SRP-capable"]
    #[inline(always)]
    pub fn srpcap(&self) -> SrpcapR {
        SrpcapR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - HNP-capable"]
    #[inline(always)]
    pub fn hnpcap(&self) -> HnpcapR {
        HnpcapR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:13 - USB turnaround time"]
    #[inline(always)]
    pub fn trdt(&self) -> TrdtR {
        TrdtR::new(((self.bits >> 10) & 0x0f) as u8)
    }
    #[doc = "Bit 15 - PHY Low-power clock select"]
    #[inline(always)]
    pub fn phylpcs(&self) -> PhylpcsR {
        PhylpcsR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - ULPI FS/LS select"]
    #[inline(always)]
    pub fn ulpifsls(&self) -> UlpifslsR {
        UlpifslsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - ULPI Auto-resume"]
    #[inline(always)]
    pub fn ulpiar(&self) -> UlpiarR {
        UlpiarR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - ULPI Clock SuspendM"]
    #[inline(always)]
    pub fn ulpicsm(&self) -> UlpicsmR {
        UlpicsmR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - ULPI External VBUS Drive"]
    #[inline(always)]
    pub fn ulpievbusd(&self) -> UlpievbusdR {
        UlpievbusdR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - ULPI external VBUS indicator"]
    #[inline(always)]
    pub fn ulpievbusi(&self) -> UlpievbusiR {
        UlpievbusiR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - TermSel DLine pulsing selection"]
    #[inline(always)]
    pub fn tsdps(&self) -> TsdpsR {
        TsdpsR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Indicator complement"]
    #[inline(always)]
    pub fn pcci(&self) -> PcciR {
        PcciR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Indicator pass through"]
    #[inline(always)]
    pub fn ptci(&self) -> PtciR {
        PtciR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - ULPI interface protect disable"]
    #[inline(always)]
    pub fn ulpiipd(&self) -> UlpiipdR {
        UlpiipdR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 29 - Forced host mode"]
    #[inline(always)]
    pub fn fhmod(&self) -> FhmodR {
        FhmodR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Forced peripheral mode"]
    #[inline(always)]
    pub fn fdmod(&self) -> FdmodR {
        FdmodR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Corrupt Tx packet"]
    #[inline(always)]
    pub fn ctxpkt(&self) -> CtxpktR {
        CtxpktR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - FS timeout calibration"]
    #[inline(always)]
    #[must_use]
    pub fn tocal(&mut self) -> TocalW<OtgHsGusbcfgSpec> {
        TocalW::new(self, 0)
    }
    #[doc = "Bit 6 - USB 2.0 high-speed ULPI PHY or USB 1.1 full-speed serial transceiver select"]
    #[inline(always)]
    #[must_use]
    pub fn physel(&mut self) -> PhyselW<OtgHsGusbcfgSpec> {
        PhyselW::new(self, 6)
    }
    #[doc = "Bit 8 - SRP-capable"]
    #[inline(always)]
    #[must_use]
    pub fn srpcap(&mut self) -> SrpcapW<OtgHsGusbcfgSpec> {
        SrpcapW::new(self, 8)
    }
    #[doc = "Bit 9 - HNP-capable"]
    #[inline(always)]
    #[must_use]
    pub fn hnpcap(&mut self) -> HnpcapW<OtgHsGusbcfgSpec> {
        HnpcapW::new(self, 9)
    }
    #[doc = "Bits 10:13 - USB turnaround time"]
    #[inline(always)]
    #[must_use]
    pub fn trdt(&mut self) -> TrdtW<OtgHsGusbcfgSpec> {
        TrdtW::new(self, 10)
    }
    #[doc = "Bit 15 - PHY Low-power clock select"]
    #[inline(always)]
    #[must_use]
    pub fn phylpcs(&mut self) -> PhylpcsW<OtgHsGusbcfgSpec> {
        PhylpcsW::new(self, 15)
    }
    #[doc = "Bit 17 - ULPI FS/LS select"]
    #[inline(always)]
    #[must_use]
    pub fn ulpifsls(&mut self) -> UlpifslsW<OtgHsGusbcfgSpec> {
        UlpifslsW::new(self, 17)
    }
    #[doc = "Bit 18 - ULPI Auto-resume"]
    #[inline(always)]
    #[must_use]
    pub fn ulpiar(&mut self) -> UlpiarW<OtgHsGusbcfgSpec> {
        UlpiarW::new(self, 18)
    }
    #[doc = "Bit 19 - ULPI Clock SuspendM"]
    #[inline(always)]
    #[must_use]
    pub fn ulpicsm(&mut self) -> UlpicsmW<OtgHsGusbcfgSpec> {
        UlpicsmW::new(self, 19)
    }
    #[doc = "Bit 20 - ULPI External VBUS Drive"]
    #[inline(always)]
    #[must_use]
    pub fn ulpievbusd(&mut self) -> UlpievbusdW<OtgHsGusbcfgSpec> {
        UlpievbusdW::new(self, 20)
    }
    #[doc = "Bit 21 - ULPI external VBUS indicator"]
    #[inline(always)]
    #[must_use]
    pub fn ulpievbusi(&mut self) -> UlpievbusiW<OtgHsGusbcfgSpec> {
        UlpievbusiW::new(self, 21)
    }
    #[doc = "Bit 22 - TermSel DLine pulsing selection"]
    #[inline(always)]
    #[must_use]
    pub fn tsdps(&mut self) -> TsdpsW<OtgHsGusbcfgSpec> {
        TsdpsW::new(self, 22)
    }
    #[doc = "Bit 23 - Indicator complement"]
    #[inline(always)]
    #[must_use]
    pub fn pcci(&mut self) -> PcciW<OtgHsGusbcfgSpec> {
        PcciW::new(self, 23)
    }
    #[doc = "Bit 24 - Indicator pass through"]
    #[inline(always)]
    #[must_use]
    pub fn ptci(&mut self) -> PtciW<OtgHsGusbcfgSpec> {
        PtciW::new(self, 24)
    }
    #[doc = "Bit 25 - ULPI interface protect disable"]
    #[inline(always)]
    #[must_use]
    pub fn ulpiipd(&mut self) -> UlpiipdW<OtgHsGusbcfgSpec> {
        UlpiipdW::new(self, 25)
    }
    #[doc = "Bit 29 - Forced host mode"]
    #[inline(always)]
    #[must_use]
    pub fn fhmod(&mut self) -> FhmodW<OtgHsGusbcfgSpec> {
        FhmodW::new(self, 29)
    }
    #[doc = "Bit 30 - Forced peripheral mode"]
    #[inline(always)]
    #[must_use]
    pub fn fdmod(&mut self) -> FdmodW<OtgHsGusbcfgSpec> {
        FdmodW::new(self, 30)
    }
    #[doc = "Bit 31 - Corrupt Tx packet"]
    #[inline(always)]
    #[must_use]
    pub fn ctxpkt(&mut self) -> CtxpktW<OtgHsGusbcfgSpec> {
        CtxpktW::new(self, 31)
    }
}
#[doc = "OTG_HS USB configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gusbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gusbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsGusbcfgSpec;
impl crate::RegisterSpec for OtgHsGusbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`otg_hs_gusbcfg::R`](R) reader structure"]
impl crate::Readable for OtgHsGusbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_gusbcfg::W`](W) writer structure"]
impl crate::Writable for OtgHsGusbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_GUSBCFG to value 0x0a00"]
impl crate::Resettable for OtgHsGusbcfgSpec {
    const RESET_VALUE: u32 = 0x0a00;
}
