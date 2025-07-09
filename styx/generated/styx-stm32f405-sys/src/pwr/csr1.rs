// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR1` reader"]
pub type R = crate::R<Csr1Spec>;
#[doc = "Register `CSR1` writer"]
pub type W = crate::W<Csr1Spec>;
#[doc = "Field `WUIF` reader - Wakeup internal flag"]
pub type WuifR = crate::BitReader;
#[doc = "Field `WUIF` writer - Wakeup internal flag"]
pub type WuifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBF` reader - Standby flag"]
pub type SbfR = crate::BitReader;
#[doc = "Field `SBF` writer - Standby flag"]
pub type SbfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PVDO` reader - PVD output"]
pub type PvdoR = crate::BitReader;
#[doc = "Field `PVDO` writer - PVD output"]
pub type PvdoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BRR` reader - Backup regulator ready"]
pub type BrrR = crate::BitReader;
#[doc = "Field `BRR` writer - Backup regulator ready"]
pub type BrrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BRE` reader - Backup regulator enable"]
pub type BreR = crate::BitReader;
#[doc = "Field `BRE` writer - Backup regulator enable"]
pub type BreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VOSRDY` reader - Regulator voltage scaling output selection ready bit"]
pub type VosrdyR = crate::BitReader;
#[doc = "Field `VOSRDY` writer - Regulator voltage scaling output selection ready bit"]
pub type VosrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODRDY` reader - Over-drive mode ready"]
pub type OdrdyR = crate::BitReader;
#[doc = "Field `ODRDY` writer - Over-drive mode ready"]
pub type OdrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODSWRDY` reader - Over-drive mode switching ready"]
pub type OdswrdyR = crate::BitReader;
#[doc = "Field `ODSWRDY` writer - Over-drive mode switching ready"]
pub type OdswrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UDRDY` reader - Under-drive ready flag"]
pub type UdrdyR = crate::FieldReader;
#[doc = "Field `UDRDY` writer - Under-drive ready flag"]
pub type UdrdyW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Wakeup internal flag"]
    #[inline(always)]
    pub fn wuif(&self) -> WuifR {
        WuifR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Standby flag"]
    #[inline(always)]
    pub fn sbf(&self) -> SbfR {
        SbfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - PVD output"]
    #[inline(always)]
    pub fn pvdo(&self) -> PvdoR {
        PvdoR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Backup regulator ready"]
    #[inline(always)]
    pub fn brr(&self) -> BrrR {
        BrrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 9 - Backup regulator enable"]
    #[inline(always)]
    pub fn bre(&self) -> BreR {
        BreR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 14 - Regulator voltage scaling output selection ready bit"]
    #[inline(always)]
    pub fn vosrdy(&self) -> VosrdyR {
        VosrdyR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - Over-drive mode ready"]
    #[inline(always)]
    pub fn odrdy(&self) -> OdrdyR {
        OdrdyR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Over-drive mode switching ready"]
    #[inline(always)]
    pub fn odswrdy(&self) -> OdswrdyR {
        OdswrdyR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - Under-drive ready flag"]
    #[inline(always)]
    pub fn udrdy(&self) -> UdrdyR {
        UdrdyR::new(((self.bits >> 18) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Wakeup internal flag"]
    #[inline(always)]
    #[must_use]
    pub fn wuif(&mut self) -> WuifW<Csr1Spec> {
        WuifW::new(self, 0)
    }
    #[doc = "Bit 1 - Standby flag"]
    #[inline(always)]
    #[must_use]
    pub fn sbf(&mut self) -> SbfW<Csr1Spec> {
        SbfW::new(self, 1)
    }
    #[doc = "Bit 2 - PVD output"]
    #[inline(always)]
    #[must_use]
    pub fn pvdo(&mut self) -> PvdoW<Csr1Spec> {
        PvdoW::new(self, 2)
    }
    #[doc = "Bit 3 - Backup regulator ready"]
    #[inline(always)]
    #[must_use]
    pub fn brr(&mut self) -> BrrW<Csr1Spec> {
        BrrW::new(self, 3)
    }
    #[doc = "Bit 9 - Backup regulator enable"]
    #[inline(always)]
    #[must_use]
    pub fn bre(&mut self) -> BreW<Csr1Spec> {
        BreW::new(self, 9)
    }
    #[doc = "Bit 14 - Regulator voltage scaling output selection ready bit"]
    #[inline(always)]
    #[must_use]
    pub fn vosrdy(&mut self) -> VosrdyW<Csr1Spec> {
        VosrdyW::new(self, 14)
    }
    #[doc = "Bit 16 - Over-drive mode ready"]
    #[inline(always)]
    #[must_use]
    pub fn odrdy(&mut self) -> OdrdyW<Csr1Spec> {
        OdrdyW::new(self, 16)
    }
    #[doc = "Bit 17 - Over-drive mode switching ready"]
    #[inline(always)]
    #[must_use]
    pub fn odswrdy(&mut self) -> OdswrdyW<Csr1Spec> {
        OdswrdyW::new(self, 17)
    }
    #[doc = "Bits 18:19 - Under-drive ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn udrdy(&mut self) -> UdrdyW<Csr1Spec> {
        UdrdyW::new(self, 18)
    }
}
#[doc = "power control/status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr1Spec;
impl crate::RegisterSpec for Csr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`csr1::R`](R) reader structure"]
impl crate::Readable for Csr1Spec {}
#[doc = "`write(|w| ..)` method takes [`csr1::W`](W) writer structure"]
impl crate::Writable for Csr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR1 to value 0"]
impl crate::Resettable for Csr1Spec {
    const RESET_VALUE: u32 = 0;
}
