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
#[doc = "Field `WWDG_SW` reader - User option bytes"]
pub type WwdgSwR = crate::BitReader;
#[doc = "Field `WWDG_SW` writer - User option bytes"]
pub type WwdgSwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IWDG_SW` reader - User option bytes"]
pub type IwdgSwR = crate::BitReader;
#[doc = "Field `IWDG_SW` writer - User option bytes"]
pub type IwdgSwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nRST_STOP` reader - User option bytes"]
pub type NRstStopR = crate::BitReader;
#[doc = "Field `nRST_STOP` writer - User option bytes"]
pub type NRstStopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nRST_STDBY` reader - User option bytes"]
pub type NRstStdbyR = crate::BitReader;
#[doc = "Field `nRST_STDBY` writer - User option bytes"]
pub type NRstStdbyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RDP` reader - Read protect"]
pub type RdpR = crate::FieldReader;
#[doc = "Field `RDP` writer - Read protect"]
pub type RdpW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `nWRP` reader - Not write protect"]
pub type NWrpR = crate::FieldReader;
#[doc = "Field `nWRP` writer - Not write protect"]
pub type NWrpW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IWDG_STDBY` reader - Independent watchdog counter freeze in standby mode"]
pub type IwdgStdbyR = crate::BitReader;
#[doc = "Field `IWDG_STDBY` writer - Independent watchdog counter freeze in standby mode"]
pub type IwdgStdbyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IWDG_STOP` reader - Independent watchdog counter freeze in Stop mode"]
pub type IwdgStopR = crate::BitReader;
#[doc = "Field `IWDG_STOP` writer - Independent watchdog counter freeze in Stop mode"]
pub type IwdgStopW<'a, REG> = crate::BitWriter<'a, REG>;
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
    #[doc = "Bit 4 - User option bytes"]
    #[inline(always)]
    pub fn wwdg_sw(&self) -> WwdgSwR {
        WwdgSwR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - User option bytes"]
    #[inline(always)]
    pub fn iwdg_sw(&self) -> IwdgSwR {
        IwdgSwR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - User option bytes"]
    #[inline(always)]
    pub fn n_rst_stop(&self) -> NRstStopR {
        NRstStopR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - User option bytes"]
    #[inline(always)]
    pub fn n_rst_stdby(&self) -> NRstStdbyR {
        NRstStdbyR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:15 - Read protect"]
    #[inline(always)]
    pub fn rdp(&self) -> RdpR {
        RdpR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Not write protect"]
    #[inline(always)]
    pub fn n_wrp(&self) -> NWrpR {
        NWrpR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bit 30 - Independent watchdog counter freeze in standby mode"]
    #[inline(always)]
    pub fn iwdg_stdby(&self) -> IwdgStdbyR {
        IwdgStdbyR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Independent watchdog counter freeze in Stop mode"]
    #[inline(always)]
    pub fn iwdg_stop(&self) -> IwdgStopR {
        IwdgStopR::new(((self.bits >> 31) & 1) != 0)
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
    #[doc = "Bit 4 - User option bytes"]
    #[inline(always)]
    #[must_use]
    pub fn wwdg_sw(&mut self) -> WwdgSwW<OptcrSpec> {
        WwdgSwW::new(self, 4)
    }
    #[doc = "Bit 5 - User option bytes"]
    #[inline(always)]
    #[must_use]
    pub fn iwdg_sw(&mut self) -> IwdgSwW<OptcrSpec> {
        IwdgSwW::new(self, 5)
    }
    #[doc = "Bit 6 - User option bytes"]
    #[inline(always)]
    #[must_use]
    pub fn n_rst_stop(&mut self) -> NRstStopW<OptcrSpec> {
        NRstStopW::new(self, 6)
    }
    #[doc = "Bit 7 - User option bytes"]
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
    #[doc = "Bits 16:23 - Not write protect"]
    #[inline(always)]
    #[must_use]
    pub fn n_wrp(&mut self) -> NWrpW<OptcrSpec> {
        NWrpW::new(self, 16)
    }
    #[doc = "Bit 30 - Independent watchdog counter freeze in standby mode"]
    #[inline(always)]
    #[must_use]
    pub fn iwdg_stdby(&mut self) -> IwdgStdbyW<OptcrSpec> {
        IwdgStdbyW::new(self, 30)
    }
    #[doc = "Bit 31 - Independent watchdog counter freeze in Stop mode"]
    #[inline(always)]
    #[must_use]
    pub fn iwdg_stop(&mut self) -> IwdgStopW<OptcrSpec> {
        IwdgStopW::new(self, 31)
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
#[doc = "`reset()` method sets OPTCR to value 0x0fff_aaed"]
impl crate::Resettable for OptcrSpec {
    const RESET_VALUE: u32 = 0x0fff_aaed;
}
