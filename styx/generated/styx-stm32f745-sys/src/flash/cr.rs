// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `PG` reader - Programming"]
pub type PgR = crate::BitReader;
#[doc = "Field `PG` writer - Programming"]
pub type PgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SER` reader - Sector Erase"]
pub type SerR = crate::BitReader;
#[doc = "Field `SER` writer - Sector Erase"]
pub type SerW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MER` reader - Mass Erase of sectors 0 to 11"]
pub type MerR = crate::BitReader;
#[doc = "Field `MER` writer - Mass Erase of sectors 0 to 11"]
pub type MerW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SNB` reader - Sector number"]
pub type SnbR = crate::FieldReader;
#[doc = "Field `SNB` writer - Sector number"]
pub type SnbW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PSIZE` reader - Program size"]
pub type PsizeR = crate::FieldReader;
#[doc = "Field `PSIZE` writer - Program size"]
pub type PsizeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `STRT` reader - Start"]
pub type StrtR = crate::BitReader;
#[doc = "Field `STRT` writer - Start"]
pub type StrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOPIE` reader - End of operation interrupt enable"]
pub type EopieR = crate::BitReader;
#[doc = "Field `EOPIE` writer - End of operation interrupt enable"]
pub type EopieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERRIE` reader - Error interrupt enable"]
pub type ErrieR = crate::BitReader;
#[doc = "Field `ERRIE` writer - Error interrupt enable"]
pub type ErrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LOCK` reader - Lock"]
pub type LockR = crate::BitReader;
#[doc = "Field `LOCK` writer - Lock"]
pub type LockW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Programming"]
    #[inline(always)]
    pub fn pg(&self) -> PgR {
        PgR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Sector Erase"]
    #[inline(always)]
    pub fn ser(&self) -> SerR {
        SerR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Mass Erase of sectors 0 to 11"]
    #[inline(always)]
    pub fn mer(&self) -> MerR {
        MerR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:6 - Sector number"]
    #[inline(always)]
    pub fn snb(&self) -> SnbR {
        SnbR::new(((self.bits >> 3) & 0x0f) as u8)
    }
    #[doc = "Bits 8:9 - Program size"]
    #[inline(always)]
    pub fn psize(&self) -> PsizeR {
        PsizeR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bit 16 - Start"]
    #[inline(always)]
    pub fn strt(&self) -> StrtR {
        StrtR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 24 - End of operation interrupt enable"]
    #[inline(always)]
    pub fn eopie(&self) -> EopieR {
        EopieR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Error interrupt enable"]
    #[inline(always)]
    pub fn errie(&self) -> ErrieR {
        ErrieR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 31 - Lock"]
    #[inline(always)]
    pub fn lock(&self) -> LockR {
        LockR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Programming"]
    #[inline(always)]
    #[must_use]
    pub fn pg(&mut self) -> PgW<CrSpec> {
        PgW::new(self, 0)
    }
    #[doc = "Bit 1 - Sector Erase"]
    #[inline(always)]
    #[must_use]
    pub fn ser(&mut self) -> SerW<CrSpec> {
        SerW::new(self, 1)
    }
    #[doc = "Bit 2 - Mass Erase of sectors 0 to 11"]
    #[inline(always)]
    #[must_use]
    pub fn mer(&mut self) -> MerW<CrSpec> {
        MerW::new(self, 2)
    }
    #[doc = "Bits 3:6 - Sector number"]
    #[inline(always)]
    #[must_use]
    pub fn snb(&mut self) -> SnbW<CrSpec> {
        SnbW::new(self, 3)
    }
    #[doc = "Bits 8:9 - Program size"]
    #[inline(always)]
    #[must_use]
    pub fn psize(&mut self) -> PsizeW<CrSpec> {
        PsizeW::new(self, 8)
    }
    #[doc = "Bit 16 - Start"]
    #[inline(always)]
    #[must_use]
    pub fn strt(&mut self) -> StrtW<CrSpec> {
        StrtW::new(self, 16)
    }
    #[doc = "Bit 24 - End of operation interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn eopie(&mut self) -> EopieW<CrSpec> {
        EopieW::new(self, 24)
    }
    #[doc = "Bit 25 - Error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn errie(&mut self) -> ErrieW<CrSpec> {
        ErrieW::new(self, 25)
    }
    #[doc = "Bit 31 - Lock"]
    #[inline(always)]
    #[must_use]
    pub fn lock(&mut self) -> LockW<CrSpec> {
        LockW::new(self, 31)
    }
}
#[doc = "Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0x8000_0000"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0x8000_0000;
}
