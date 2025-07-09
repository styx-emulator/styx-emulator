// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR2` reader"]
pub type R = crate::R<Cr2Spec>;
#[doc = "Register `CR2` writer"]
pub type W = crate::W<Cr2Spec>;
#[doc = "Field `RXDMAEN` reader - Rx buffer DMA enable"]
pub type RxdmaenR = crate::BitReader;
#[doc = "Field `RXDMAEN` writer - Rx buffer DMA enable"]
pub type RxdmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXDMAEN` reader - Tx buffer DMA enable"]
pub type TxdmaenR = crate::BitReader;
#[doc = "Field `TXDMAEN` writer - Tx buffer DMA enable"]
pub type TxdmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SSOE` reader - SS output enable"]
pub type SsoeR = crate::BitReader;
#[doc = "Field `SSOE` writer - SS output enable"]
pub type SsoeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NSSP` reader - NSS pulse management"]
pub type NsspR = crate::BitReader;
#[doc = "Field `NSSP` writer - NSS pulse management"]
pub type NsspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FRF` reader - Frame format"]
pub type FrfR = crate::BitReader;
#[doc = "Field `FRF` writer - Frame format"]
pub type FrfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERRIE` reader - Error interrupt enable"]
pub type ErrieR = crate::BitReader;
#[doc = "Field `ERRIE` writer - Error interrupt enable"]
pub type ErrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXNEIE` reader - RX buffer not empty interrupt enable"]
pub type RxneieR = crate::BitReader;
#[doc = "Field `RXNEIE` writer - RX buffer not empty interrupt enable"]
pub type RxneieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXEIE` reader - Tx buffer empty interrupt enable"]
pub type TxeieR = crate::BitReader;
#[doc = "Field `TXEIE` writer - Tx buffer empty interrupt enable"]
pub type TxeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DS` reader - Data size"]
pub type DsR = crate::FieldReader;
#[doc = "Field `DS` writer - Data size"]
pub type DsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `FRXTH` reader - FIFO reception threshold"]
pub type FrxthR = crate::BitReader;
#[doc = "Field `FRXTH` writer - FIFO reception threshold"]
pub type FrxthW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LDMA_RX` reader - Last DMA transfer for reception"]
pub type LdmaRxR = crate::BitReader;
#[doc = "Field `LDMA_RX` writer - Last DMA transfer for reception"]
pub type LdmaRxW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LDMA_TX` reader - Last DMA transfer for transmission"]
pub type LdmaTxR = crate::BitReader;
#[doc = "Field `LDMA_TX` writer - Last DMA transfer for transmission"]
pub type LdmaTxW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Rx buffer DMA enable"]
    #[inline(always)]
    pub fn rxdmaen(&self) -> RxdmaenR {
        RxdmaenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Tx buffer DMA enable"]
    #[inline(always)]
    pub fn txdmaen(&self) -> TxdmaenR {
        TxdmaenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - SS output enable"]
    #[inline(always)]
    pub fn ssoe(&self) -> SsoeR {
        SsoeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - NSS pulse management"]
    #[inline(always)]
    pub fn nssp(&self) -> NsspR {
        NsspR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Frame format"]
    #[inline(always)]
    pub fn frf(&self) -> FrfR {
        FrfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Error interrupt enable"]
    #[inline(always)]
    pub fn errie(&self) -> ErrieR {
        ErrieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - RX buffer not empty interrupt enable"]
    #[inline(always)]
    pub fn rxneie(&self) -> RxneieR {
        RxneieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Tx buffer empty interrupt enable"]
    #[inline(always)]
    pub fn txeie(&self) -> TxeieR {
        TxeieR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:11 - Data size"]
    #[inline(always)]
    pub fn ds(&self) -> DsR {
        DsR::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bit 12 - FIFO reception threshold"]
    #[inline(always)]
    pub fn frxth(&self) -> FrxthR {
        FrxthR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Last DMA transfer for reception"]
    #[inline(always)]
    pub fn ldma_rx(&self) -> LdmaRxR {
        LdmaRxR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Last DMA transfer for transmission"]
    #[inline(always)]
    pub fn ldma_tx(&self) -> LdmaTxR {
        LdmaTxR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Rx buffer DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxdmaen(&mut self) -> RxdmaenW<Cr2Spec> {
        RxdmaenW::new(self, 0)
    }
    #[doc = "Bit 1 - Tx buffer DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn txdmaen(&mut self) -> TxdmaenW<Cr2Spec> {
        TxdmaenW::new(self, 1)
    }
    #[doc = "Bit 2 - SS output enable"]
    #[inline(always)]
    #[must_use]
    pub fn ssoe(&mut self) -> SsoeW<Cr2Spec> {
        SsoeW::new(self, 2)
    }
    #[doc = "Bit 3 - NSS pulse management"]
    #[inline(always)]
    #[must_use]
    pub fn nssp(&mut self) -> NsspW<Cr2Spec> {
        NsspW::new(self, 3)
    }
    #[doc = "Bit 4 - Frame format"]
    #[inline(always)]
    #[must_use]
    pub fn frf(&mut self) -> FrfW<Cr2Spec> {
        FrfW::new(self, 4)
    }
    #[doc = "Bit 5 - Error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn errie(&mut self) -> ErrieW<Cr2Spec> {
        ErrieW::new(self, 5)
    }
    #[doc = "Bit 6 - RX buffer not empty interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxneie(&mut self) -> RxneieW<Cr2Spec> {
        RxneieW::new(self, 6)
    }
    #[doc = "Bit 7 - Tx buffer empty interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txeie(&mut self) -> TxeieW<Cr2Spec> {
        TxeieW::new(self, 7)
    }
    #[doc = "Bits 8:11 - Data size"]
    #[inline(always)]
    #[must_use]
    pub fn ds(&mut self) -> DsW<Cr2Spec> {
        DsW::new(self, 8)
    }
    #[doc = "Bit 12 - FIFO reception threshold"]
    #[inline(always)]
    #[must_use]
    pub fn frxth(&mut self) -> FrxthW<Cr2Spec> {
        FrxthW::new(self, 12)
    }
    #[doc = "Bit 13 - Last DMA transfer for reception"]
    #[inline(always)]
    #[must_use]
    pub fn ldma_rx(&mut self) -> LdmaRxW<Cr2Spec> {
        LdmaRxW::new(self, 13)
    }
    #[doc = "Bit 14 - Last DMA transfer for transmission"]
    #[inline(always)]
    #[must_use]
    pub fn ldma_tx(&mut self) -> LdmaTxW<Cr2Spec> {
        LdmaTxW::new(self, 14)
    }
}
#[doc = "control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr2Spec;
impl crate::RegisterSpec for Cr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`cr2::R`](R) reader structure"]
impl crate::Readable for Cr2Spec {}
#[doc = "`write(|w| ..)` method takes [`cr2::W`](W) writer structure"]
impl crate::Writable for Cr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR2 to value 0x0700"]
impl crate::Resettable for Cr2Spec {
    const RESET_VALUE: u32 = 0x0700;
}
