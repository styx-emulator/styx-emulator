// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_GRSTCTL` reader"]
pub type R = crate::R<OtgFsGrstctlSpec>;
#[doc = "Register `OTG_FS_GRSTCTL` writer"]
pub type W = crate::W<OtgFsGrstctlSpec>;
#[doc = "Field `CSRST` reader - Core soft reset"]
pub type CsrstR = crate::BitReader;
#[doc = "Field `CSRST` writer - Core soft reset"]
pub type CsrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSRST` reader - HCLK soft reset"]
pub type HsrstR = crate::BitReader;
#[doc = "Field `HSRST` writer - HCLK soft reset"]
pub type HsrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FCRST` reader - Host frame counter reset"]
pub type FcrstR = crate::BitReader;
#[doc = "Field `FCRST` writer - Host frame counter reset"]
pub type FcrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFFLSH` reader - RxFIFO flush"]
pub type RxfflshR = crate::BitReader;
#[doc = "Field `RXFFLSH` writer - RxFIFO flush"]
pub type RxfflshW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFFLSH` reader - TxFIFO flush"]
pub type TxfflshR = crate::BitReader;
#[doc = "Field `TXFFLSH` writer - TxFIFO flush"]
pub type TxfflshW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFNUM` reader - TxFIFO number"]
pub type TxfnumR = crate::FieldReader;
#[doc = "Field `TXFNUM` writer - TxFIFO number"]
pub type TxfnumW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `AHBIDL` reader - AHB master idle"]
pub type AhbidlR = crate::BitReader;
#[doc = "Field `AHBIDL` writer - AHB master idle"]
pub type AhbidlW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Core soft reset"]
    #[inline(always)]
    pub fn csrst(&self) -> CsrstR {
        CsrstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - HCLK soft reset"]
    #[inline(always)]
    pub fn hsrst(&self) -> HsrstR {
        HsrstR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Host frame counter reset"]
    #[inline(always)]
    pub fn fcrst(&self) -> FcrstR {
        FcrstR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - RxFIFO flush"]
    #[inline(always)]
    pub fn rxfflsh(&self) -> RxfflshR {
        RxfflshR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - TxFIFO flush"]
    #[inline(always)]
    pub fn txfflsh(&self) -> TxfflshR {
        TxfflshR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:10 - TxFIFO number"]
    #[inline(always)]
    pub fn txfnum(&self) -> TxfnumR {
        TxfnumR::new(((self.bits >> 6) & 0x1f) as u8)
    }
    #[doc = "Bit 31 - AHB master idle"]
    #[inline(always)]
    pub fn ahbidl(&self) -> AhbidlR {
        AhbidlR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Core soft reset"]
    #[inline(always)]
    #[must_use]
    pub fn csrst(&mut self) -> CsrstW<OtgFsGrstctlSpec> {
        CsrstW::new(self, 0)
    }
    #[doc = "Bit 1 - HCLK soft reset"]
    #[inline(always)]
    #[must_use]
    pub fn hsrst(&mut self) -> HsrstW<OtgFsGrstctlSpec> {
        HsrstW::new(self, 1)
    }
    #[doc = "Bit 2 - Host frame counter reset"]
    #[inline(always)]
    #[must_use]
    pub fn fcrst(&mut self) -> FcrstW<OtgFsGrstctlSpec> {
        FcrstW::new(self, 2)
    }
    #[doc = "Bit 4 - RxFIFO flush"]
    #[inline(always)]
    #[must_use]
    pub fn rxfflsh(&mut self) -> RxfflshW<OtgFsGrstctlSpec> {
        RxfflshW::new(self, 4)
    }
    #[doc = "Bit 5 - TxFIFO flush"]
    #[inline(always)]
    #[must_use]
    pub fn txfflsh(&mut self) -> TxfflshW<OtgFsGrstctlSpec> {
        TxfflshW::new(self, 5)
    }
    #[doc = "Bits 6:10 - TxFIFO number"]
    #[inline(always)]
    #[must_use]
    pub fn txfnum(&mut self) -> TxfnumW<OtgFsGrstctlSpec> {
        TxfnumW::new(self, 6)
    }
    #[doc = "Bit 31 - AHB master idle"]
    #[inline(always)]
    #[must_use]
    pub fn ahbidl(&mut self) -> AhbidlW<OtgFsGrstctlSpec> {
        AhbidlW::new(self, 31)
    }
}
#[doc = "OTG_FS reset register (OTG_FS_GRSTCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grstctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_grstctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGrstctlSpec;
impl crate::RegisterSpec for OtgFsGrstctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`otg_fs_grstctl::R`](R) reader structure"]
impl crate::Readable for OtgFsGrstctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_grstctl::W`](W) writer structure"]
impl crate::Writable for OtgFsGrstctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GRSTCTL to value 0x2000_0000"]
impl crate::Resettable for OtgFsGrstctlSpec {
    const RESET_VALUE: u32 = 0x2000_0000;
}
