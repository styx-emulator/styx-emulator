// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB1ENR` reader"]
pub type R = crate::R<Ahb1enrSpec>;
#[doc = "Register `AHB1ENR` writer"]
pub type W = crate::W<Ahb1enrSpec>;
#[doc = "Field `GPIOAEN` reader - IO port A clock enable"]
pub type GpioaenR = crate::BitReader;
#[doc = "Field `GPIOAEN` writer - IO port A clock enable"]
pub type GpioaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOBEN` reader - IO port B clock enable"]
pub type GpiobenR = crate::BitReader;
#[doc = "Field `GPIOBEN` writer - IO port B clock enable"]
pub type GpiobenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOCEN` reader - IO port C clock enable"]
pub type GpiocenR = crate::BitReader;
#[doc = "Field `GPIOCEN` writer - IO port C clock enable"]
pub type GpiocenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIODEN` reader - IO port D clock enable"]
pub type GpiodenR = crate::BitReader;
#[doc = "Field `GPIODEN` writer - IO port D clock enable"]
pub type GpiodenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOEEN` reader - IO port E clock enable"]
pub type GpioeenR = crate::BitReader;
#[doc = "Field `GPIOEEN` writer - IO port E clock enable"]
pub type GpioeenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOFEN` reader - IO port F clock enable"]
pub type GpiofenR = crate::BitReader;
#[doc = "Field `GPIOFEN` writer - IO port F clock enable"]
pub type GpiofenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOGEN` reader - IO port G clock enable"]
pub type GpiogenR = crate::BitReader;
#[doc = "Field `GPIOGEN` writer - IO port G clock enable"]
pub type GpiogenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOHEN` reader - IO port H clock enable"]
pub type GpiohenR = crate::BitReader;
#[doc = "Field `GPIOHEN` writer - IO port H clock enable"]
pub type GpiohenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GPIOIEN` reader - IO port I clock enable"]
pub type GpioienR = crate::BitReader;
#[doc = "Field `GPIOIEN` writer - IO port I clock enable"]
pub type GpioienW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CRCEN` reader - CRC clock enable"]
pub type CrcenR = crate::BitReader;
#[doc = "Field `CRCEN` writer - CRC clock enable"]
pub type CrcenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BKPSRAMEN` reader - Backup SRAM interface clock enable"]
pub type BkpsramenR = crate::BitReader;
#[doc = "Field `BKPSRAMEN` writer - Backup SRAM interface clock enable"]
pub type BkpsramenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CCMDATARAMEN` reader - CCM data RAM clock enable"]
pub type CcmdataramenR = crate::BitReader;
#[doc = "Field `CCMDATARAMEN` writer - CCM data RAM clock enable"]
pub type CcmdataramenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMA1EN` reader - DMA1 clock enable"]
pub type Dma1enR = crate::BitReader;
#[doc = "Field `DMA1EN` writer - DMA1 clock enable"]
pub type Dma1enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMA2EN` reader - DMA2 clock enable"]
pub type Dma2enR = crate::BitReader;
#[doc = "Field `DMA2EN` writer - DMA2 clock enable"]
pub type Dma2enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETHMACEN` reader - Ethernet MAC clock enable"]
pub type EthmacenR = crate::BitReader;
#[doc = "Field `ETHMACEN` writer - Ethernet MAC clock enable"]
pub type EthmacenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETHMACTXEN` reader - Ethernet Transmission clock enable"]
pub type EthmactxenR = crate::BitReader;
#[doc = "Field `ETHMACTXEN` writer - Ethernet Transmission clock enable"]
pub type EthmactxenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETHMACRXEN` reader - Ethernet Reception clock enable"]
pub type EthmacrxenR = crate::BitReader;
#[doc = "Field `ETHMACRXEN` writer - Ethernet Reception clock enable"]
pub type EthmacrxenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETHMACPTPEN` reader - Ethernet PTP clock enable"]
pub type EthmacptpenR = crate::BitReader;
#[doc = "Field `ETHMACPTPEN` writer - Ethernet PTP clock enable"]
pub type EthmacptpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGHSEN` reader - USB OTG HS clock enable"]
pub type OtghsenR = crate::BitReader;
#[doc = "Field `OTGHSEN` writer - USB OTG HS clock enable"]
pub type OtghsenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGHSULPIEN` reader - USB OTG HSULPI clock enable"]
pub type OtghsulpienR = crate::BitReader;
#[doc = "Field `OTGHSULPIEN` writer - USB OTG HSULPI clock enable"]
pub type OtghsulpienW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - IO port A clock enable"]
    #[inline(always)]
    pub fn gpioaen(&self) -> GpioaenR {
        GpioaenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - IO port B clock enable"]
    #[inline(always)]
    pub fn gpioben(&self) -> GpiobenR {
        GpiobenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - IO port C clock enable"]
    #[inline(always)]
    pub fn gpiocen(&self) -> GpiocenR {
        GpiocenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - IO port D clock enable"]
    #[inline(always)]
    pub fn gpioden(&self) -> GpiodenR {
        GpiodenR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - IO port E clock enable"]
    #[inline(always)]
    pub fn gpioeen(&self) -> GpioeenR {
        GpioeenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - IO port F clock enable"]
    #[inline(always)]
    pub fn gpiofen(&self) -> GpiofenR {
        GpiofenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - IO port G clock enable"]
    #[inline(always)]
    pub fn gpiogen(&self) -> GpiogenR {
        GpiogenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - IO port H clock enable"]
    #[inline(always)]
    pub fn gpiohen(&self) -> GpiohenR {
        GpiohenR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - IO port I clock enable"]
    #[inline(always)]
    pub fn gpioien(&self) -> GpioienR {
        GpioienR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 12 - CRC clock enable"]
    #[inline(always)]
    pub fn crcen(&self) -> CrcenR {
        CrcenR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 18 - Backup SRAM interface clock enable"]
    #[inline(always)]
    pub fn bkpsramen(&self) -> BkpsramenR {
        BkpsramenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 20 - CCM data RAM clock enable"]
    #[inline(always)]
    pub fn ccmdataramen(&self) -> CcmdataramenR {
        CcmdataramenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - DMA1 clock enable"]
    #[inline(always)]
    pub fn dma1en(&self) -> Dma1enR {
        Dma1enR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - DMA2 clock enable"]
    #[inline(always)]
    pub fn dma2en(&self) -> Dma2enR {
        Dma2enR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 25 - Ethernet MAC clock enable"]
    #[inline(always)]
    pub fn ethmacen(&self) -> EthmacenR {
        EthmacenR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Ethernet Transmission clock enable"]
    #[inline(always)]
    pub fn ethmactxen(&self) -> EthmactxenR {
        EthmactxenR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Ethernet Reception clock enable"]
    #[inline(always)]
    pub fn ethmacrxen(&self) -> EthmacrxenR {
        EthmacrxenR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Ethernet PTP clock enable"]
    #[inline(always)]
    pub fn ethmacptpen(&self) -> EthmacptpenR {
        EthmacptpenR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - USB OTG HS clock enable"]
    #[inline(always)]
    pub fn otghsen(&self) -> OtghsenR {
        OtghsenR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - USB OTG HSULPI clock enable"]
    #[inline(always)]
    pub fn otghsulpien(&self) -> OtghsulpienR {
        OtghsulpienR::new(((self.bits >> 30) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - IO port A clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpioaen(&mut self) -> GpioaenW<Ahb1enrSpec> {
        GpioaenW::new(self, 0)
    }
    #[doc = "Bit 1 - IO port B clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpioben(&mut self) -> GpiobenW<Ahb1enrSpec> {
        GpiobenW::new(self, 1)
    }
    #[doc = "Bit 2 - IO port C clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpiocen(&mut self) -> GpiocenW<Ahb1enrSpec> {
        GpiocenW::new(self, 2)
    }
    #[doc = "Bit 3 - IO port D clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpioden(&mut self) -> GpiodenW<Ahb1enrSpec> {
        GpiodenW::new(self, 3)
    }
    #[doc = "Bit 4 - IO port E clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpioeen(&mut self) -> GpioeenW<Ahb1enrSpec> {
        GpioeenW::new(self, 4)
    }
    #[doc = "Bit 5 - IO port F clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpiofen(&mut self) -> GpiofenW<Ahb1enrSpec> {
        GpiofenW::new(self, 5)
    }
    #[doc = "Bit 6 - IO port G clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpiogen(&mut self) -> GpiogenW<Ahb1enrSpec> {
        GpiogenW::new(self, 6)
    }
    #[doc = "Bit 7 - IO port H clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpiohen(&mut self) -> GpiohenW<Ahb1enrSpec> {
        GpiohenW::new(self, 7)
    }
    #[doc = "Bit 8 - IO port I clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn gpioien(&mut self) -> GpioienW<Ahb1enrSpec> {
        GpioienW::new(self, 8)
    }
    #[doc = "Bit 12 - CRC clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn crcen(&mut self) -> CrcenW<Ahb1enrSpec> {
        CrcenW::new(self, 12)
    }
    #[doc = "Bit 18 - Backup SRAM interface clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn bkpsramen(&mut self) -> BkpsramenW<Ahb1enrSpec> {
        BkpsramenW::new(self, 18)
    }
    #[doc = "Bit 20 - CCM data RAM clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn ccmdataramen(&mut self) -> CcmdataramenW<Ahb1enrSpec> {
        CcmdataramenW::new(self, 20)
    }
    #[doc = "Bit 21 - DMA1 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn dma1en(&mut self) -> Dma1enW<Ahb1enrSpec> {
        Dma1enW::new(self, 21)
    }
    #[doc = "Bit 22 - DMA2 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn dma2en(&mut self) -> Dma2enW<Ahb1enrSpec> {
        Dma2enW::new(self, 22)
    }
    #[doc = "Bit 25 - Ethernet MAC clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn ethmacen(&mut self) -> EthmacenW<Ahb1enrSpec> {
        EthmacenW::new(self, 25)
    }
    #[doc = "Bit 26 - Ethernet Transmission clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn ethmactxen(&mut self) -> EthmactxenW<Ahb1enrSpec> {
        EthmactxenW::new(self, 26)
    }
    #[doc = "Bit 27 - Ethernet Reception clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn ethmacrxen(&mut self) -> EthmacrxenW<Ahb1enrSpec> {
        EthmacrxenW::new(self, 27)
    }
    #[doc = "Bit 28 - Ethernet PTP clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn ethmacptpen(&mut self) -> EthmacptpenW<Ahb1enrSpec> {
        EthmacptpenW::new(self, 28)
    }
    #[doc = "Bit 29 - USB OTG HS clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn otghsen(&mut self) -> OtghsenW<Ahb1enrSpec> {
        OtghsenW::new(self, 29)
    }
    #[doc = "Bit 30 - USB OTG HSULPI clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn otghsulpien(&mut self) -> OtghsulpienW<Ahb1enrSpec> {
        OtghsulpienW::new(self, 30)
    }
}
#[doc = "AHB1 peripheral clock register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb1enr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb1enr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb1enrSpec;
impl crate::RegisterSpec for Ahb1enrSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`ahb1enr::R`](R) reader structure"]
impl crate::Readable for Ahb1enrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb1enr::W`](W) writer structure"]
impl crate::Writable for Ahb1enrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB1ENR to value 0x0010_0000"]
impl crate::Resettable for Ahb1enrSpec {
    const RESET_VALUE: u32 = 0x0010_0000;
}
