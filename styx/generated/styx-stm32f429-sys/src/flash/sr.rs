// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `EOP` reader - End of operation"]
pub type EopR = crate::BitReader;
#[doc = "Field `EOP` writer - End of operation"]
pub type EopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OPERR` reader - Operation error"]
pub type OperrR = crate::BitReader;
#[doc = "Field `OPERR` writer - Operation error"]
pub type OperrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WRPERR` reader - Write protection error"]
pub type WrperrR = crate::BitReader;
#[doc = "Field `WRPERR` writer - Write protection error"]
pub type WrperrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PGAERR` reader - Programming alignment error"]
pub type PgaerrR = crate::BitReader;
#[doc = "Field `PGAERR` writer - Programming alignment error"]
pub type PgaerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PGPERR` reader - Programming parallelism error"]
pub type PgperrR = crate::BitReader;
#[doc = "Field `PGPERR` writer - Programming parallelism error"]
pub type PgperrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PGSERR` reader - Programming sequence error"]
pub type PgserrR = crate::BitReader;
#[doc = "Field `PGSERR` writer - Programming sequence error"]
pub type PgserrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BSY` reader - Busy"]
pub type BsyR = crate::BitReader;
#[doc = "Field `BSY` writer - Busy"]
pub type BsyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - End of operation"]
    #[inline(always)]
    pub fn eop(&self) -> EopR {
        EopR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Operation error"]
    #[inline(always)]
    pub fn operr(&self) -> OperrR {
        OperrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 4 - Write protection error"]
    #[inline(always)]
    pub fn wrperr(&self) -> WrperrR {
        WrperrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Programming alignment error"]
    #[inline(always)]
    pub fn pgaerr(&self) -> PgaerrR {
        PgaerrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Programming parallelism error"]
    #[inline(always)]
    pub fn pgperr(&self) -> PgperrR {
        PgperrR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Programming sequence error"]
    #[inline(always)]
    pub fn pgserr(&self) -> PgserrR {
        PgserrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 16 - Busy"]
    #[inline(always)]
    pub fn bsy(&self) -> BsyR {
        BsyR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - End of operation"]
    #[inline(always)]
    #[must_use]
    pub fn eop(&mut self) -> EopW<SrSpec> {
        EopW::new(self, 0)
    }
    #[doc = "Bit 1 - Operation error"]
    #[inline(always)]
    #[must_use]
    pub fn operr(&mut self) -> OperrW<SrSpec> {
        OperrW::new(self, 1)
    }
    #[doc = "Bit 4 - Write protection error"]
    #[inline(always)]
    #[must_use]
    pub fn wrperr(&mut self) -> WrperrW<SrSpec> {
        WrperrW::new(self, 4)
    }
    #[doc = "Bit 5 - Programming alignment error"]
    #[inline(always)]
    #[must_use]
    pub fn pgaerr(&mut self) -> PgaerrW<SrSpec> {
        PgaerrW::new(self, 5)
    }
    #[doc = "Bit 6 - Programming parallelism error"]
    #[inline(always)]
    #[must_use]
    pub fn pgperr(&mut self) -> PgperrW<SrSpec> {
        PgperrW::new(self, 6)
    }
    #[doc = "Bit 7 - Programming sequence error"]
    #[inline(always)]
    #[must_use]
    pub fn pgserr(&mut self) -> PgserrW<SrSpec> {
        PgserrW::new(self, 7)
    }
    #[doc = "Bit 16 - Busy"]
    #[inline(always)]
    #[must_use]
    pub fn bsy(&mut self) -> BsyW<SrSpec> {
        BsyW::new(self, 16)
    }
}
#[doc = "Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`write(|w| ..)` method takes [`sr::W`](W) writer structure"]
impl crate::Writable for SrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
