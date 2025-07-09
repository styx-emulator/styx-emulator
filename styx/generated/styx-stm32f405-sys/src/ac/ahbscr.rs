// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHBSCR` reader"]
pub type R = crate::R<AhbscrSpec>;
#[doc = "Register `AHBSCR` writer"]
pub type W = crate::W<AhbscrSpec>;
#[doc = "Field `CTL` reader - CTL"]
pub type CtlR = crate::FieldReader;
#[doc = "Field `CTL` writer - CTL"]
pub type CtlW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TPRI` reader - TPRI"]
pub type TpriR = crate::FieldReader<u16>;
#[doc = "Field `TPRI` writer - TPRI"]
pub type TpriW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `INITCOUNT` reader - INITCOUNT"]
pub type InitcountR = crate::FieldReader;
#[doc = "Field `INITCOUNT` writer - INITCOUNT"]
pub type InitcountW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:1 - CTL"]
    #[inline(always)]
    pub fn ctl(&self) -> CtlR {
        CtlR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:10 - TPRI"]
    #[inline(always)]
    pub fn tpri(&self) -> TpriR {
        TpriR::new(((self.bits >> 2) & 0x01ff) as u16)
    }
    #[doc = "Bits 11:15 - INITCOUNT"]
    #[inline(always)]
    pub fn initcount(&self) -> InitcountR {
        InitcountR::new(((self.bits >> 11) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - CTL"]
    #[inline(always)]
    #[must_use]
    pub fn ctl(&mut self) -> CtlW<AhbscrSpec> {
        CtlW::new(self, 0)
    }
    #[doc = "Bits 2:10 - TPRI"]
    #[inline(always)]
    #[must_use]
    pub fn tpri(&mut self) -> TpriW<AhbscrSpec> {
        TpriW::new(self, 2)
    }
    #[doc = "Bits 11:15 - INITCOUNT"]
    #[inline(always)]
    #[must_use]
    pub fn initcount(&mut self) -> InitcountW<AhbscrSpec> {
        InitcountW::new(self, 11)
    }
}
#[doc = "AHB Slave Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahbscr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahbscr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AhbscrSpec;
impl crate::RegisterSpec for AhbscrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`ahbscr::R`](R) reader structure"]
impl crate::Readable for AhbscrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahbscr::W`](W) writer structure"]
impl crate::Writable for AhbscrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHBSCR to value 0"]
impl crate::Resettable for AhbscrSpec {
    const RESET_VALUE: u32 = 0;
}
