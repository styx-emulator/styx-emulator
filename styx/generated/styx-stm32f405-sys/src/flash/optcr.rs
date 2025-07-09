// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OPTCR` reader"]
pub type R = crate::R<OptcrSpec>;
#[doc = "Register `OPTCR` writer"]
pub type W = crate::W<OptcrSpec>;
#[doc = "Field `OPTLOCK` reader - Option lock"]
pub type OptlockR = crate::BitReader;
#[doc = "Field `OPTLOCK` writer - Option lock"]
pub type OptlockW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OPTSTRT` reader - Option start"]
pub type OptstrtR = crate::BitReader;
#[doc = "Field `OPTSTRT` writer - Option start"]
pub type OptstrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BOR_LEV` reader - BOR reset Level"]
pub type BorLevR = crate::FieldReader;
#[doc = "Field `BOR_LEV` writer - BOR reset Level"]
pub type BorLevW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `WDG_SW` reader - WDG_SW User option bytes"]
pub type WdgSwR = crate::BitReader;
#[doc = "Field `WDG_SW` writer - WDG_SW User option bytes"]
pub type WdgSwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nRST_STOP` reader - nRST_STOP User option bytes"]
pub type NRstStopR = crate::BitReader;
#[doc = "Field `nRST_STOP` writer - nRST_STOP User option bytes"]
pub type NRstStopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nRST_STDBY` reader - nRST_STDBY User option bytes"]
pub type NRstStdbyR = crate::BitReader;
#[doc = "Field `nRST_STDBY` writer - nRST_STDBY User option bytes"]
pub type NRstStdbyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RDP` reader - Read protect"]
pub type RdpR = crate::FieldReader;
#[doc = "Field `RDP` writer - Read protect"]
pub type RdpW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `nWRP` reader - Not write protect"]
pub type NWrpR = crate::FieldReader<u16>;
#[doc = "Field `nWRP` writer - Not write protect"]
pub type NWrpW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bit 0 - Option lock"]
    #[inline(always)]
    pub fn optlock(&self) -> OptlockR {
        OptlockR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Option start"]
    #[inline(always)]
    pub fn optstrt(&self) -> OptstrtR {
        OptstrtR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:3 - BOR reset Level"]
    #[inline(always)]
    pub fn bor_lev(&self) -> BorLevR {
        BorLevR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bit 5 - WDG_SW User option bytes"]
    #[inline(always)]
    pub fn wdg_sw(&self) -> WdgSwR {
        WdgSwR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - nRST_STOP User option bytes"]
    #[inline(always)]
    pub fn n_rst_stop(&self) -> NRstStopR {
        NRstStopR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - nRST_STDBY User option bytes"]
    #[inline(always)]
    pub fn n_rst_stdby(&self) -> NRstStdbyR {
        NRstStdbyR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:15 - Read protect"]
    #[inline(always)]
    pub fn rdp(&self) -> RdpR {
        RdpR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:27 - Not write protect"]
    #[inline(always)]
    pub fn n_wrp(&self) -> NWrpR {
        NWrpR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - Option lock"]
    #[inline(always)]
    #[must_use]
    pub fn optlock(&mut self) -> OptlockW<OptcrSpec> {
        OptlockW::new(self, 0)
    }
    #[doc = "Bit 1 - Option start"]
    #[inline(always)]
    #[must_use]
    pub fn optstrt(&mut self) -> OptstrtW<OptcrSpec> {
        OptstrtW::new(self, 1)
    }
    #[doc = "Bits 2:3 - BOR reset Level"]
    #[inline(always)]
    #[must_use]
    pub fn bor_lev(&mut self) -> BorLevW<OptcrSpec> {
        BorLevW::new(self, 2)
    }
    #[doc = "Bit 5 - WDG_SW User option bytes"]
    #[inline(always)]
    #[must_use]
    pub fn wdg_sw(&mut self) -> WdgSwW<OptcrSpec> {
        WdgSwW::new(self, 5)
    }
    #[doc = "Bit 6 - nRST_STOP User option bytes"]
    #[inline(always)]
    #[must_use]
    pub fn n_rst_stop(&mut self) -> NRstStopW<OptcrSpec> {
        NRstStopW::new(self, 6)
    }
    #[doc = "Bit 7 - nRST_STDBY User option bytes"]
    #[inline(always)]
    #[must_use]
    pub fn n_rst_stdby(&mut self) -> NRstStdbyW<OptcrSpec> {
        NRstStdbyW::new(self, 7)
    }
    #[doc = "Bits 8:15 - Read protect"]
    #[inline(always)]
    #[must_use]
    pub fn rdp(&mut self) -> RdpW<OptcrSpec> {
        RdpW::new(self, 8)
    }
    #[doc = "Bits 16:27 - Not write protect"]
    #[inline(always)]
    #[must_use]
    pub fn n_wrp(&mut self) -> NWrpW<OptcrSpec> {
        NWrpW::new(self, 16)
    }
}
#[doc = "Flash option control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`optcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`optcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OptcrSpec;
impl crate::RegisterSpec for OptcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`optcr::R`](R) reader structure"]
impl crate::Readable for OptcrSpec {}
#[doc = "`write(|w| ..)` method takes [`optcr::W`](W) writer structure"]
impl crate::Writable for OptcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OPTCR to value 0x14"]
impl crate::Resettable for OptcrSpec {
    const RESET_VALUE: u32 = 0x14;
}
