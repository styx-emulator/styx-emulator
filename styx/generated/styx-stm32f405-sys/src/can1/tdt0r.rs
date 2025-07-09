// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TDT0R` reader"]
pub type R = crate::R<Tdt0rSpec>;
#[doc = "Register `TDT0R` writer"]
pub type W = crate::W<Tdt0rSpec>;
#[doc = "Field `DLC` reader - DLC"]
pub type DlcR = crate::FieldReader;
#[doc = "Field `DLC` writer - DLC"]
pub type DlcW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TGT` reader - TGT"]
pub type TgtR = crate::BitReader;
#[doc = "Field `TGT` writer - TGT"]
pub type TgtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIME` reader - TIME"]
pub type TimeR = crate::FieldReader<u16>;
#[doc = "Field `TIME` writer - TIME"]
pub type TimeW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:3 - DLC"]
    #[inline(always)]
    pub fn dlc(&self) -> DlcR {
        DlcR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 8 - TGT"]
    #[inline(always)]
    pub fn tgt(&self) -> TgtR {
        TgtR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bits 16:31 - TIME"]
    #[inline(always)]
    pub fn time(&self) -> TimeR {
        TimeR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:3 - DLC"]
    #[inline(always)]
    #[must_use]
    pub fn dlc(&mut self) -> DlcW<Tdt0rSpec> {
        DlcW::new(self, 0)
    }
    #[doc = "Bit 8 - TGT"]
    #[inline(always)]
    #[must_use]
    pub fn tgt(&mut self) -> TgtW<Tdt0rSpec> {
        TgtW::new(self, 8)
    }
    #[doc = "Bits 16:31 - TIME"]
    #[inline(always)]
    #[must_use]
    pub fn time(&mut self) -> TimeW<Tdt0rSpec> {
        TimeW::new(self, 16)
    }
}
#[doc = "mailbox data length control and time stamp register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdt0r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdt0r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Tdt0rSpec;
impl crate::RegisterSpec for Tdt0rSpec {
    type Ux = u32;
    const OFFSET: u64 = 388u64;
}
#[doc = "`read()` method returns [`tdt0r::R`](R) reader structure"]
impl crate::Readable for Tdt0rSpec {}
#[doc = "`write(|w| ..)` method takes [`tdt0r::W`](W) writer structure"]
impl crate::Writable for Tdt0rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TDT0R to value 0"]
impl crate::Resettable for Tdt0rSpec {
    const RESET_VALUE: u32 = 0;
}
