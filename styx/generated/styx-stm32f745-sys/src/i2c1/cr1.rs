// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR1` reader"]
pub type R = crate::R<Cr1Spec>;
#[doc = "Register `CR1` writer"]
pub type W = crate::W<Cr1Spec>;
#[doc = "Field `PE` reader - Peripheral enable"]
pub type PeR = crate::BitReader;
#[doc = "Field `PE` writer - Peripheral enable"]
pub type PeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXIE` reader - TX Interrupt enable"]
pub type TxieR = crate::BitReader;
#[doc = "Field `TXIE` writer - TX Interrupt enable"]
pub type TxieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXIE` reader - RX Interrupt enable"]
pub type RxieR = crate::BitReader;
#[doc = "Field `RXIE` writer - RX Interrupt enable"]
pub type RxieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADDRIE` reader - Address match interrupt enable (slave only)"]
pub type AddrieR = crate::BitReader;
#[doc = "Field `ADDRIE` writer - Address match interrupt enable (slave only)"]
pub type AddrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NACKIE` reader - Not acknowledge received interrupt enable"]
pub type NackieR = crate::BitReader;
#[doc = "Field `NACKIE` writer - Not acknowledge received interrupt enable"]
pub type NackieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STOPIE` reader - STOP detection Interrupt enable"]
pub type StopieR = crate::BitReader;
#[doc = "Field `STOPIE` writer - STOP detection Interrupt enable"]
pub type StopieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIE` reader - Transfer Complete interrupt enable"]
pub type TcieR = crate::BitReader;
#[doc = "Field `TCIE` writer - Transfer Complete interrupt enable"]
pub type TcieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERRIE` reader - Error interrupts enable"]
pub type ErrieR = crate::BitReader;
#[doc = "Field `ERRIE` writer - Error interrupts enable"]
pub type ErrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DNF` reader - Digital noise filter"]
pub type DnfR = crate::FieldReader;
#[doc = "Field `DNF` writer - Digital noise filter"]
pub type DnfW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `ANFOFF` reader - Analog noise filter OFF"]
pub type AnfoffR = crate::BitReader;
#[doc = "Field `ANFOFF` writer - Analog noise filter OFF"]
pub type AnfoffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXDMAEN` reader - DMA transmission requests enable"]
pub type TxdmaenR = crate::BitReader;
#[doc = "Field `TXDMAEN` writer - DMA transmission requests enable"]
pub type TxdmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXDMAEN` reader - DMA reception requests enable"]
pub type RxdmaenR = crate::BitReader;
#[doc = "Field `RXDMAEN` writer - DMA reception requests enable"]
pub type RxdmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBC` reader - Slave byte control"]
pub type SbcR = crate::BitReader;
#[doc = "Field `SBC` writer - Slave byte control"]
pub type SbcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NOSTRETCH` reader - Clock stretching disable"]
pub type NostretchR = crate::BitReader;
#[doc = "Field `NOSTRETCH` writer - Clock stretching disable"]
pub type NostretchW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPEN` reader - Wakeup from STOP enable"]
pub type WupenR = crate::BitReader;
#[doc = "Field `WUPEN` writer - Wakeup from STOP enable"]
pub type WupenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GCEN` reader - General call enable"]
pub type GcenR = crate::BitReader;
#[doc = "Field `GCEN` writer - General call enable"]
pub type GcenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMBHEN` reader - SMBus Host address enable"]
pub type SmbhenR = crate::BitReader;
#[doc = "Field `SMBHEN` writer - SMBus Host address enable"]
pub type SmbhenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMBDEN` reader - SMBus Device Default address enable"]
pub type SmbdenR = crate::BitReader;
#[doc = "Field `SMBDEN` writer - SMBus Device Default address enable"]
pub type SmbdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ALERTEN` reader - SMBUS alert enable"]
pub type AlertenR = crate::BitReader;
#[doc = "Field `ALERTEN` writer - SMBUS alert enable"]
pub type AlertenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PECEN` reader - PEC enable"]
pub type PecenR = crate::BitReader;
#[doc = "Field `PECEN` writer - PEC enable"]
pub type PecenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Peripheral enable"]
    #[inline(always)]
    pub fn pe(&self) -> PeR {
        PeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TX Interrupt enable"]
    #[inline(always)]
    pub fn txie(&self) -> TxieR {
        TxieR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - RX Interrupt enable"]
    #[inline(always)]
    pub fn rxie(&self) -> RxieR {
        RxieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Address match interrupt enable (slave only)"]
    #[inline(always)]
    pub fn addrie(&self) -> AddrieR {
        AddrieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Not acknowledge received interrupt enable"]
    #[inline(always)]
    pub fn nackie(&self) -> NackieR {
        NackieR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - STOP detection Interrupt enable"]
    #[inline(always)]
    pub fn stopie(&self) -> StopieR {
        StopieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Transfer Complete interrupt enable"]
    #[inline(always)]
    pub fn tcie(&self) -> TcieR {
        TcieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Error interrupts enable"]
    #[inline(always)]
    pub fn errie(&self) -> ErrieR {
        ErrieR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:11 - Digital noise filter"]
    #[inline(always)]
    pub fn dnf(&self) -> DnfR {
        DnfR::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bit 12 - Analog noise filter OFF"]
    #[inline(always)]
    pub fn anfoff(&self) -> AnfoffR {
        AnfoffR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 14 - DMA transmission requests enable"]
    #[inline(always)]
    pub fn txdmaen(&self) -> TxdmaenR {
        TxdmaenR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - DMA reception requests enable"]
    #[inline(always)]
    pub fn rxdmaen(&self) -> RxdmaenR {
        RxdmaenR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Slave byte control"]
    #[inline(always)]
    pub fn sbc(&self) -> SbcR {
        SbcR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Clock stretching disable"]
    #[inline(always)]
    pub fn nostretch(&self) -> NostretchR {
        NostretchR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Wakeup from STOP enable"]
    #[inline(always)]
    pub fn wupen(&self) -> WupenR {
        WupenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - General call enable"]
    #[inline(always)]
    pub fn gcen(&self) -> GcenR {
        GcenR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - SMBus Host address enable"]
    #[inline(always)]
    pub fn smbhen(&self) -> SmbhenR {
        SmbhenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - SMBus Device Default address enable"]
    #[inline(always)]
    pub fn smbden(&self) -> SmbdenR {
        SmbdenR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - SMBUS alert enable"]
    #[inline(always)]
    pub fn alerten(&self) -> AlertenR {
        AlertenR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - PEC enable"]
    #[inline(always)]
    pub fn pecen(&self) -> PecenR {
        PecenR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Peripheral enable"]
    #[inline(always)]
    #[must_use]
    pub fn pe(&mut self) -> PeW<Cr1Spec> {
        PeW::new(self, 0)
    }
    #[doc = "Bit 1 - TX Interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txie(&mut self) -> TxieW<Cr1Spec> {
        TxieW::new(self, 1)
    }
    #[doc = "Bit 2 - RX Interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxie(&mut self) -> RxieW<Cr1Spec> {
        RxieW::new(self, 2)
    }
    #[doc = "Bit 3 - Address match interrupt enable (slave only)"]
    #[inline(always)]
    #[must_use]
    pub fn addrie(&mut self) -> AddrieW<Cr1Spec> {
        AddrieW::new(self, 3)
    }
    #[doc = "Bit 4 - Not acknowledge received interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn nackie(&mut self) -> NackieW<Cr1Spec> {
        NackieW::new(self, 4)
    }
    #[doc = "Bit 5 - STOP detection Interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn stopie(&mut self) -> StopieW<Cr1Spec> {
        StopieW::new(self, 5)
    }
    #[doc = "Bit 6 - Transfer Complete interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tcie(&mut self) -> TcieW<Cr1Spec> {
        TcieW::new(self, 6)
    }
    #[doc = "Bit 7 - Error interrupts enable"]
    #[inline(always)]
    #[must_use]
    pub fn errie(&mut self) -> ErrieW<Cr1Spec> {
        ErrieW::new(self, 7)
    }
    #[doc = "Bits 8:11 - Digital noise filter"]
    #[inline(always)]
    #[must_use]
    pub fn dnf(&mut self) -> DnfW<Cr1Spec> {
        DnfW::new(self, 8)
    }
    #[doc = "Bit 12 - Analog noise filter OFF"]
    #[inline(always)]
    #[must_use]
    pub fn anfoff(&mut self) -> AnfoffW<Cr1Spec> {
        AnfoffW::new(self, 12)
    }
    #[doc = "Bit 14 - DMA transmission requests enable"]
    #[inline(always)]
    #[must_use]
    pub fn txdmaen(&mut self) -> TxdmaenW<Cr1Spec> {
        TxdmaenW::new(self, 14)
    }
    #[doc = "Bit 15 - DMA reception requests enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxdmaen(&mut self) -> RxdmaenW<Cr1Spec> {
        RxdmaenW::new(self, 15)
    }
    #[doc = "Bit 16 - Slave byte control"]
    #[inline(always)]
    #[must_use]
    pub fn sbc(&mut self) -> SbcW<Cr1Spec> {
        SbcW::new(self, 16)
    }
    #[doc = "Bit 17 - Clock stretching disable"]
    #[inline(always)]
    #[must_use]
    pub fn nostretch(&mut self) -> NostretchW<Cr1Spec> {
        NostretchW::new(self, 17)
    }
    #[doc = "Bit 18 - Wakeup from STOP enable"]
    #[inline(always)]
    #[must_use]
    pub fn wupen(&mut self) -> WupenW<Cr1Spec> {
        WupenW::new(self, 18)
    }
    #[doc = "Bit 19 - General call enable"]
    #[inline(always)]
    #[must_use]
    pub fn gcen(&mut self) -> GcenW<Cr1Spec> {
        GcenW::new(self, 19)
    }
    #[doc = "Bit 20 - SMBus Host address enable"]
    #[inline(always)]
    #[must_use]
    pub fn smbhen(&mut self) -> SmbhenW<Cr1Spec> {
        SmbhenW::new(self, 20)
    }
    #[doc = "Bit 21 - SMBus Device Default address enable"]
    #[inline(always)]
    #[must_use]
    pub fn smbden(&mut self) -> SmbdenW<Cr1Spec> {
        SmbdenW::new(self, 21)
    }
    #[doc = "Bit 22 - SMBUS alert enable"]
    #[inline(always)]
    #[must_use]
    pub fn alerten(&mut self) -> AlertenW<Cr1Spec> {
        AlertenW::new(self, 22)
    }
    #[doc = "Bit 23 - PEC enable"]
    #[inline(always)]
    #[must_use]
    pub fn pecen(&mut self) -> PecenW<Cr1Spec> {
        PecenW::new(self, 23)
    }
}
#[doc = "Control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr1Spec;
impl crate::RegisterSpec for Cr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr1::R`](R) reader structure"]
impl crate::Readable for Cr1Spec {}
#[doc = "`write(|w| ..)` method takes [`cr1::W`](W) writer structure"]
impl crate::Writable for Cr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR1 to value 0"]
impl crate::Resettable for Cr1Spec {
    const RESET_VALUE: u32 = 0;
}
