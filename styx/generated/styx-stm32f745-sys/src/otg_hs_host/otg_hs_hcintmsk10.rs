// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_HCINTMSK10` reader"]
pub type R = crate::R<OtgHsHcintmsk10Spec>;
#[doc = "Register `OTG_HS_HCINTMSK10` writer"]
pub type W = crate::W<OtgHsHcintmsk10Spec>;
#[doc = "Field `XFRCM` reader - Transfer completed mask"]
pub type XfrcmR = crate::BitReader;
#[doc = "Field `XFRCM` writer - Transfer completed mask"]
pub type XfrcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHHM` reader - Channel halted mask"]
pub type ChhmR = crate::BitReader;
#[doc = "Field `CHHM` writer - Channel halted mask"]
pub type ChhmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AHBERR` reader - AHB error"]
pub type AhberrR = crate::BitReader;
#[doc = "Field `AHBERR` writer - AHB error"]
pub type AhberrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STALLM` reader - STALL response received interrupt mask"]
pub type StallmR = crate::BitReader;
#[doc = "Field `STALLM` writer - STALL response received interrupt mask"]
pub type StallmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NAKM` reader - NAK response received interrupt mask"]
pub type NakmR = crate::BitReader;
#[doc = "Field `NAKM` writer - NAK response received interrupt mask"]
pub type NakmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ACKM` reader - ACK response received/transmitted interrupt mask"]
pub type AckmR = crate::BitReader;
#[doc = "Field `ACKM` writer - ACK response received/transmitted interrupt mask"]
pub type AckmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NYET` reader - response received interrupt mask"]
pub type NyetR = crate::BitReader;
#[doc = "Field `NYET` writer - response received interrupt mask"]
pub type NyetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXERRM` reader - Transaction error mask"]
pub type TxerrmR = crate::BitReader;
#[doc = "Field `TXERRM` writer - Transaction error mask"]
pub type TxerrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BBERRM` reader - Babble error mask"]
pub type BberrmR = crate::BitReader;
#[doc = "Field `BBERRM` writer - Babble error mask"]
pub type BberrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FRMORM` reader - Frame overrun mask"]
pub type FrmormR = crate::BitReader;
#[doc = "Field `FRMORM` writer - Frame overrun mask"]
pub type FrmormW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DTERRM` reader - Data toggle error mask"]
pub type DterrmR = crate::BitReader;
#[doc = "Field `DTERRM` writer - Data toggle error mask"]
pub type DterrmW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Transfer completed mask"]
    #[inline(always)]
    pub fn xfrcm(&self) -> XfrcmR {
        XfrcmR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Channel halted mask"]
    #[inline(always)]
    pub fn chhm(&self) -> ChhmR {
        ChhmR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - AHB error"]
    #[inline(always)]
    pub fn ahberr(&self) -> AhberrR {
        AhberrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - STALL response received interrupt mask"]
    #[inline(always)]
    pub fn stallm(&self) -> StallmR {
        StallmR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - NAK response received interrupt mask"]
    #[inline(always)]
    pub fn nakm(&self) -> NakmR {
        NakmR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - ACK response received/transmitted interrupt mask"]
    #[inline(always)]
    pub fn ackm(&self) -> AckmR {
        AckmR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - response received interrupt mask"]
    #[inline(always)]
    pub fn nyet(&self) -> NyetR {
        NyetR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Transaction error mask"]
    #[inline(always)]
    pub fn txerrm(&self) -> TxerrmR {
        TxerrmR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Babble error mask"]
    #[inline(always)]
    pub fn bberrm(&self) -> BberrmR {
        BberrmR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Frame overrun mask"]
    #[inline(always)]
    pub fn frmorm(&self) -> FrmormR {
        FrmormR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Data toggle error mask"]
    #[inline(always)]
    pub fn dterrm(&self) -> DterrmR {
        DterrmR::new(((self.bits >> 10) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer completed mask"]
    #[inline(always)]
    #[must_use]
    pub fn xfrcm(&mut self) -> XfrcmW<OtgHsHcintmsk10Spec> {
        XfrcmW::new(self, 0)
    }
    #[doc = "Bit 1 - Channel halted mask"]
    #[inline(always)]
    #[must_use]
    pub fn chhm(&mut self) -> ChhmW<OtgHsHcintmsk10Spec> {
        ChhmW::new(self, 1)
    }
    #[doc = "Bit 2 - AHB error"]
    #[inline(always)]
    #[must_use]
    pub fn ahberr(&mut self) -> AhberrW<OtgHsHcintmsk10Spec> {
        AhberrW::new(self, 2)
    }
    #[doc = "Bit 3 - STALL response received interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn stallm(&mut self) -> StallmW<OtgHsHcintmsk10Spec> {
        StallmW::new(self, 3)
    }
    #[doc = "Bit 4 - NAK response received interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn nakm(&mut self) -> NakmW<OtgHsHcintmsk10Spec> {
        NakmW::new(self, 4)
    }
    #[doc = "Bit 5 - ACK response received/transmitted interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn ackm(&mut self) -> AckmW<OtgHsHcintmsk10Spec> {
        AckmW::new(self, 5)
    }
    #[doc = "Bit 6 - response received interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn nyet(&mut self) -> NyetW<OtgHsHcintmsk10Spec> {
        NyetW::new(self, 6)
    }
    #[doc = "Bit 7 - Transaction error mask"]
    #[inline(always)]
    #[must_use]
    pub fn txerrm(&mut self) -> TxerrmW<OtgHsHcintmsk10Spec> {
        TxerrmW::new(self, 7)
    }
    #[doc = "Bit 8 - Babble error mask"]
    #[inline(always)]
    #[must_use]
    pub fn bberrm(&mut self) -> BberrmW<OtgHsHcintmsk10Spec> {
        BberrmW::new(self, 8)
    }
    #[doc = "Bit 9 - Frame overrun mask"]
    #[inline(always)]
    #[must_use]
    pub fn frmorm(&mut self) -> FrmormW<OtgHsHcintmsk10Spec> {
        FrmormW::new(self, 9)
    }
    #[doc = "Bit 10 - Data toggle error mask"]
    #[inline(always)]
    #[must_use]
    pub fn dterrm(&mut self) -> DterrmW<OtgHsHcintmsk10Spec> {
        DterrmW::new(self, 10)
    }
}
#[doc = "OTG_HS host channel-10 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk10::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk10::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsHcintmsk10Spec;
impl crate::RegisterSpec for OtgHsHcintmsk10Spec {
    type Ux = u32;
    const OFFSET: u64 = 588u64;
}
#[doc = "`read()` method returns [`otg_hs_hcintmsk10::R`](R) reader structure"]
impl crate::Readable for OtgHsHcintmsk10Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_hcintmsk10::W`](W) writer structure"]
impl crate::Writable for OtgHsHcintmsk10Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_HCINTMSK10 to value 0"]
impl crate::Resettable for OtgHsHcintmsk10Spec {
    const RESET_VALUE: u32 = 0;
}
