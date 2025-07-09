// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TAMPCR` reader"]
pub type R = crate::R<TampcrSpec>;
#[doc = "Register `TAMPCR` writer"]
pub type W = crate::W<TampcrSpec>;
#[doc = "Field `TAMP1E` reader - Tamper 1 detection enable"]
pub type Tamp1eR = crate::BitReader;
#[doc = "Field `TAMP1E` writer - Tamper 1 detection enable"]
pub type Tamp1eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1TRG` reader - Active level for tamper 1"]
pub type Tamp1trgR = crate::BitReader;
#[doc = "Field `TAMP1TRG` writer - Active level for tamper 1"]
pub type Tamp1trgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPIE` reader - Tamper interrupt enable"]
pub type TampieR = crate::BitReader;
#[doc = "Field `TAMPIE` writer - Tamper interrupt enable"]
pub type TampieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2E` reader - Tamper 2 detection enable"]
pub type Tamp2eR = crate::BitReader;
#[doc = "Field `TAMP2E` writer - Tamper 2 detection enable"]
pub type Tamp2eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2TRG` reader - Active level for tamper 2"]
pub type Tamp2trgR = crate::BitReader;
#[doc = "Field `TAMP2TRG` writer - Active level for tamper 2"]
pub type Tamp2trgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP3E` reader - Tamper 3 detection enable"]
pub type Tamp3eR = crate::BitReader;
#[doc = "Field `TAMP3E` writer - Tamper 3 detection enable"]
pub type Tamp3eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP3TRG` reader - Active level for tamper 3"]
pub type Tamp3trgR = crate::BitReader;
#[doc = "Field `TAMP3TRG` writer - Active level for tamper 3"]
pub type Tamp3trgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPTS` reader - Activate timestamp on tamper detection event"]
pub type TamptsR = crate::BitReader;
#[doc = "Field `TAMPTS` writer - Activate timestamp on tamper detection event"]
pub type TamptsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPFREQ` reader - Tamper sampling frequency"]
pub type TampfreqR = crate::FieldReader;
#[doc = "Field `TAMPFREQ` writer - Tamper sampling frequency"]
pub type TampfreqW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `TAMPFLT` reader - Tamper filter count"]
pub type TampfltR = crate::FieldReader;
#[doc = "Field `TAMPFLT` writer - Tamper filter count"]
pub type TampfltW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TAMPPRCH` reader - Tamper precharge duration"]
pub type TampprchR = crate::FieldReader;
#[doc = "Field `TAMPPRCH` writer - Tamper precharge duration"]
pub type TampprchW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TAMPPUDIS` reader - TAMPER pull-up disable"]
pub type TamppudisR = crate::BitReader;
#[doc = "Field `TAMPPUDIS` writer - TAMPER pull-up disable"]
pub type TamppudisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1IE` reader - Tamper 1 interrupt enable"]
pub type Tamp1ieR = crate::BitReader;
#[doc = "Field `TAMP1IE` writer - Tamper 1 interrupt enable"]
pub type Tamp1ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1NOERASE` reader - Tamper 1 no erase"]
pub type Tamp1noeraseR = crate::BitReader;
#[doc = "Field `TAMP1NOERASE` writer - Tamper 1 no erase"]
pub type Tamp1noeraseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1MF` reader - Tamper 1 mask flag"]
pub type Tamp1mfR = crate::BitReader;
#[doc = "Field `TAMP1MF` writer - Tamper 1 mask flag"]
pub type Tamp1mfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2IE` reader - Tamper 2 interrupt enable"]
pub type Tamp2ieR = crate::BitReader;
#[doc = "Field `TAMP2IE` writer - Tamper 2 interrupt enable"]
pub type Tamp2ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2NOERASE` reader - Tamper 2 no erase"]
pub type Tamp2noeraseR = crate::BitReader;
#[doc = "Field `TAMP2NOERASE` writer - Tamper 2 no erase"]
pub type Tamp2noeraseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2MF` reader - Tamper 2 mask flag"]
pub type Tamp2mfR = crate::BitReader;
#[doc = "Field `TAMP2MF` writer - Tamper 2 mask flag"]
pub type Tamp2mfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP3IE` reader - Tamper 3 interrupt enable"]
pub type Tamp3ieR = crate::BitReader;
#[doc = "Field `TAMP3IE` writer - Tamper 3 interrupt enable"]
pub type Tamp3ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP3NOERASE` reader - Tamper 3 no erase"]
pub type Tamp3noeraseR = crate::BitReader;
#[doc = "Field `TAMP3NOERASE` writer - Tamper 3 no erase"]
pub type Tamp3noeraseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP3MF` reader - Tamper 3 mask flag"]
pub type Tamp3mfR = crate::BitReader;
#[doc = "Field `TAMP3MF` writer - Tamper 3 mask flag"]
pub type Tamp3mfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Tamper 1 detection enable"]
    #[inline(always)]
    pub fn tamp1e(&self) -> Tamp1eR {
        Tamp1eR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Active level for tamper 1"]
    #[inline(always)]
    pub fn tamp1trg(&self) -> Tamp1trgR {
        Tamp1trgR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Tamper interrupt enable"]
    #[inline(always)]
    pub fn tampie(&self) -> TampieR {
        TampieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Tamper 2 detection enable"]
    #[inline(always)]
    pub fn tamp2e(&self) -> Tamp2eR {
        Tamp2eR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Active level for tamper 2"]
    #[inline(always)]
    pub fn tamp2trg(&self) -> Tamp2trgR {
        Tamp2trgR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Tamper 3 detection enable"]
    #[inline(always)]
    pub fn tamp3e(&self) -> Tamp3eR {
        Tamp3eR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Active level for tamper 3"]
    #[inline(always)]
    pub fn tamp3trg(&self) -> Tamp3trgR {
        Tamp3trgR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Activate timestamp on tamper detection event"]
    #[inline(always)]
    pub fn tampts(&self) -> TamptsR {
        TamptsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:10 - Tamper sampling frequency"]
    #[inline(always)]
    pub fn tampfreq(&self) -> TampfreqR {
        TampfreqR::new(((self.bits >> 8) & 7) as u8)
    }
    #[doc = "Bits 11:12 - Tamper filter count"]
    #[inline(always)]
    pub fn tampflt(&self) -> TampfltR {
        TampfltR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bits 13:14 - Tamper precharge duration"]
    #[inline(always)]
    pub fn tampprch(&self) -> TampprchR {
        TampprchR::new(((self.bits >> 13) & 3) as u8)
    }
    #[doc = "Bit 15 - TAMPER pull-up disable"]
    #[inline(always)]
    pub fn tamppudis(&self) -> TamppudisR {
        TamppudisR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Tamper 1 interrupt enable"]
    #[inline(always)]
    pub fn tamp1ie(&self) -> Tamp1ieR {
        Tamp1ieR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Tamper 1 no erase"]
    #[inline(always)]
    pub fn tamp1noerase(&self) -> Tamp1noeraseR {
        Tamp1noeraseR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Tamper 1 mask flag"]
    #[inline(always)]
    pub fn tamp1mf(&self) -> Tamp1mfR {
        Tamp1mfR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Tamper 2 interrupt enable"]
    #[inline(always)]
    pub fn tamp2ie(&self) -> Tamp2ieR {
        Tamp2ieR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Tamper 2 no erase"]
    #[inline(always)]
    pub fn tamp2noerase(&self) -> Tamp2noeraseR {
        Tamp2noeraseR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Tamper 2 mask flag"]
    #[inline(always)]
    pub fn tamp2mf(&self) -> Tamp2mfR {
        Tamp2mfR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Tamper 3 interrupt enable"]
    #[inline(always)]
    pub fn tamp3ie(&self) -> Tamp3ieR {
        Tamp3ieR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Tamper 3 no erase"]
    #[inline(always)]
    pub fn tamp3noerase(&self) -> Tamp3noeraseR {
        Tamp3noeraseR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Tamper 3 mask flag"]
    #[inline(always)]
    pub fn tamp3mf(&self) -> Tamp3mfR {
        Tamp3mfR::new(((self.bits >> 24) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Tamper 1 detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1e(&mut self) -> Tamp1eW<TampcrSpec> {
        Tamp1eW::new(self, 0)
    }
    #[doc = "Bit 1 - Active level for tamper 1"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1trg(&mut self) -> Tamp1trgW<TampcrSpec> {
        Tamp1trgW::new(self, 1)
    }
    #[doc = "Bit 2 - Tamper interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tampie(&mut self) -> TampieW<TampcrSpec> {
        TampieW::new(self, 2)
    }
    #[doc = "Bit 3 - Tamper 2 detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2e(&mut self) -> Tamp2eW<TampcrSpec> {
        Tamp2eW::new(self, 3)
    }
    #[doc = "Bit 4 - Active level for tamper 2"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2trg(&mut self) -> Tamp2trgW<TampcrSpec> {
        Tamp2trgW::new(self, 4)
    }
    #[doc = "Bit 5 - Tamper 3 detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp3e(&mut self) -> Tamp3eW<TampcrSpec> {
        Tamp3eW::new(self, 5)
    }
    #[doc = "Bit 6 - Active level for tamper 3"]
    #[inline(always)]
    #[must_use]
    pub fn tamp3trg(&mut self) -> Tamp3trgW<TampcrSpec> {
        Tamp3trgW::new(self, 6)
    }
    #[doc = "Bit 7 - Activate timestamp on tamper detection event"]
    #[inline(always)]
    #[must_use]
    pub fn tampts(&mut self) -> TamptsW<TampcrSpec> {
        TamptsW::new(self, 7)
    }
    #[doc = "Bits 8:10 - Tamper sampling frequency"]
    #[inline(always)]
    #[must_use]
    pub fn tampfreq(&mut self) -> TampfreqW<TampcrSpec> {
        TampfreqW::new(self, 8)
    }
    #[doc = "Bits 11:12 - Tamper filter count"]
    #[inline(always)]
    #[must_use]
    pub fn tampflt(&mut self) -> TampfltW<TampcrSpec> {
        TampfltW::new(self, 11)
    }
    #[doc = "Bits 13:14 - Tamper precharge duration"]
    #[inline(always)]
    #[must_use]
    pub fn tampprch(&mut self) -> TampprchW<TampcrSpec> {
        TampprchW::new(self, 13)
    }
    #[doc = "Bit 15 - TAMPER pull-up disable"]
    #[inline(always)]
    #[must_use]
    pub fn tamppudis(&mut self) -> TamppudisW<TampcrSpec> {
        TamppudisW::new(self, 15)
    }
    #[doc = "Bit 16 - Tamper 1 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1ie(&mut self) -> Tamp1ieW<TampcrSpec> {
        Tamp1ieW::new(self, 16)
    }
    #[doc = "Bit 17 - Tamper 1 no erase"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1noerase(&mut self) -> Tamp1noeraseW<TampcrSpec> {
        Tamp1noeraseW::new(self, 17)
    }
    #[doc = "Bit 18 - Tamper 1 mask flag"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1mf(&mut self) -> Tamp1mfW<TampcrSpec> {
        Tamp1mfW::new(self, 18)
    }
    #[doc = "Bit 19 - Tamper 2 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2ie(&mut self) -> Tamp2ieW<TampcrSpec> {
        Tamp2ieW::new(self, 19)
    }
    #[doc = "Bit 20 - Tamper 2 no erase"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2noerase(&mut self) -> Tamp2noeraseW<TampcrSpec> {
        Tamp2noeraseW::new(self, 20)
    }
    #[doc = "Bit 21 - Tamper 2 mask flag"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2mf(&mut self) -> Tamp2mfW<TampcrSpec> {
        Tamp2mfW::new(self, 21)
    }
    #[doc = "Bit 22 - Tamper 3 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp3ie(&mut self) -> Tamp3ieW<TampcrSpec> {
        Tamp3ieW::new(self, 22)
    }
    #[doc = "Bit 23 - Tamper 3 no erase"]
    #[inline(always)]
    #[must_use]
    pub fn tamp3noerase(&mut self) -> Tamp3noeraseW<TampcrSpec> {
        Tamp3noeraseW::new(self, 23)
    }
    #[doc = "Bit 24 - Tamper 3 mask flag"]
    #[inline(always)]
    #[must_use]
    pub fn tamp3mf(&mut self) -> Tamp3mfW<TampcrSpec> {
        Tamp3mfW::new(self, 24)
    }
}
#[doc = "tamper configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tampcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tampcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TampcrSpec;
impl crate::RegisterSpec for TampcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`tampcr::R`](R) reader structure"]
impl crate::Readable for TampcrSpec {}
#[doc = "`write(|w| ..)` method takes [`tampcr::W`](W) writer structure"]
impl crate::Writable for TampcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TAMPCR to value 0"]
impl crate::Resettable for TampcrSpec {
    const RESET_VALUE: u32 = 0;
}
