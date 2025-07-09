// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DIEPINT5` reader"]
pub type R = crate::R<OtgHsDiepint5Spec>;
#[doc = "Register `OTG_HS_DIEPINT5` writer"]
pub type W = crate::W<OtgHsDiepint5Spec>;
#[doc = "Field `XFRC` reader - Transfer completed interrupt"]
pub type XfrcR = crate::BitReader;
#[doc = "Field `XFRC` writer - Transfer completed interrupt"]
pub type XfrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDISD` reader - Endpoint disabled interrupt"]
pub type EpdisdR = crate::BitReader;
#[doc = "Field `EPDISD` writer - Endpoint disabled interrupt"]
pub type EpdisdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TOC` reader - Timeout condition"]
pub type TocR = crate::BitReader;
#[doc = "Field `TOC` writer - Timeout condition"]
pub type TocW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ITTXFE` reader - IN token received when TxFIFO is empty"]
pub type IttxfeR = crate::BitReader;
#[doc = "Field `ITTXFE` writer - IN token received when TxFIFO is empty"]
pub type IttxfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `INEPNE` reader - IN endpoint NAK effective"]
pub type InepneR = crate::BitReader;
#[doc = "Field `INEPNE` writer - IN endpoint NAK effective"]
pub type InepneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFE` reader - Transmit FIFO empty"]
pub type TxfeR = crate::BitReader;
#[doc = "Field `TXFE` writer - Transmit FIFO empty"]
pub type TxfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFIFOUDRN` reader - Transmit Fifo Underrun"]
pub type TxfifoudrnR = crate::BitReader;
#[doc = "Field `TXFIFOUDRN` writer - Transmit Fifo Underrun"]
pub type TxfifoudrnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BNA` reader - Buffer not available interrupt"]
pub type BnaR = crate::BitReader;
#[doc = "Field `BNA` writer - Buffer not available interrupt"]
pub type BnaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PKTDRPSTS` reader - Packet dropped status"]
pub type PktdrpstsR = crate::BitReader;
#[doc = "Field `PKTDRPSTS` writer - Packet dropped status"]
pub type PktdrpstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BERR` reader - Babble error interrupt"]
pub type BerrR = crate::BitReader;
#[doc = "Field `BERR` writer - Babble error interrupt"]
pub type BerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NAK` reader - NAK interrupt"]
pub type NakR = crate::BitReader;
#[doc = "Field `NAK` writer - NAK interrupt"]
pub type NakW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Transfer completed interrupt"]
    #[inline(always)]
    pub fn xfrc(&self) -> XfrcR {
        XfrcR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Endpoint disabled interrupt"]
    #[inline(always)]
    pub fn epdisd(&self) -> EpdisdR {
        EpdisdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Timeout condition"]
    #[inline(always)]
    pub fn toc(&self) -> TocR {
        TocR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - IN token received when TxFIFO is empty"]
    #[inline(always)]
    pub fn ittxfe(&self) -> IttxfeR {
        IttxfeR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - IN endpoint NAK effective"]
    #[inline(always)]
    pub fn inepne(&self) -> InepneR {
        InepneR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Transmit FIFO empty"]
    #[inline(always)]
    pub fn txfe(&self) -> TxfeR {
        TxfeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Transmit Fifo Underrun"]
    #[inline(always)]
    pub fn txfifoudrn(&self) -> TxfifoudrnR {
        TxfifoudrnR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Buffer not available interrupt"]
    #[inline(always)]
    pub fn bna(&self) -> BnaR {
        BnaR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 11 - Packet dropped status"]
    #[inline(always)]
    pub fn pktdrpsts(&self) -> PktdrpstsR {
        PktdrpstsR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Babble error interrupt"]
    #[inline(always)]
    pub fn berr(&self) -> BerrR {
        BerrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - NAK interrupt"]
    #[inline(always)]
    pub fn nak(&self) -> NakR {
        NakR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer completed interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn xfrc(&mut self) -> XfrcW<OtgHsDiepint5Spec> {
        XfrcW::new(self, 0)
    }
    #[doc = "Bit 1 - Endpoint disabled interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn epdisd(&mut self) -> EpdisdW<OtgHsDiepint5Spec> {
        EpdisdW::new(self, 1)
    }
    #[doc = "Bit 3 - Timeout condition"]
    #[inline(always)]
    #[must_use]
    pub fn toc(&mut self) -> TocW<OtgHsDiepint5Spec> {
        TocW::new(self, 3)
    }
    #[doc = "Bit 4 - IN token received when TxFIFO is empty"]
    #[inline(always)]
    #[must_use]
    pub fn ittxfe(&mut self) -> IttxfeW<OtgHsDiepint5Spec> {
        IttxfeW::new(self, 4)
    }
    #[doc = "Bit 6 - IN endpoint NAK effective"]
    #[inline(always)]
    #[must_use]
    pub fn inepne(&mut self) -> InepneW<OtgHsDiepint5Spec> {
        InepneW::new(self, 6)
    }
    #[doc = "Bit 7 - Transmit FIFO empty"]
    #[inline(always)]
    #[must_use]
    pub fn txfe(&mut self) -> TxfeW<OtgHsDiepint5Spec> {
        TxfeW::new(self, 7)
    }
    #[doc = "Bit 8 - Transmit Fifo Underrun"]
    #[inline(always)]
    #[must_use]
    pub fn txfifoudrn(&mut self) -> TxfifoudrnW<OtgHsDiepint5Spec> {
        TxfifoudrnW::new(self, 8)
    }
    #[doc = "Bit 9 - Buffer not available interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn bna(&mut self) -> BnaW<OtgHsDiepint5Spec> {
        BnaW::new(self, 9)
    }
    #[doc = "Bit 11 - Packet dropped status"]
    #[inline(always)]
    #[must_use]
    pub fn pktdrpsts(&mut self) -> PktdrpstsW<OtgHsDiepint5Spec> {
        PktdrpstsW::new(self, 11)
    }
    #[doc = "Bit 12 - Babble error interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn berr(&mut self) -> BerrW<OtgHsDiepint5Spec> {
        BerrW::new(self, 12)
    }
    #[doc = "Bit 13 - NAK interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn nak(&mut self) -> NakW<OtgHsDiepint5Spec> {
        NakW::new(self, 13)
    }
}
#[doc = "OTG device endpoint-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDiepint5Spec;
impl crate::RegisterSpec for OtgHsDiepint5Spec {
    type Ux = u32;
    const OFFSET: u64 = 424u64;
}
#[doc = "`read()` method returns [`otg_hs_diepint5::R`](R) reader structure"]
impl crate::Readable for OtgHsDiepint5Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_diepint5::W`](W) writer structure"]
impl crate::Writable for OtgHsDiepint5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DIEPINT5 to value 0"]
impl crate::Resettable for OtgHsDiepint5Spec {
    const RESET_VALUE: u32 = 0;
}
