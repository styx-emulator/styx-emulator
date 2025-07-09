// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_HPRT` reader"]
pub type R = crate::R<OtgHsHprtSpec>;
#[doc = "Register `OTG_HS_HPRT` writer"]
pub type W = crate::W<OtgHsHprtSpec>;
#[doc = "Field `PCSTS` reader - Port connect status"]
pub type PcstsR = crate::BitReader;
#[doc = "Field `PCSTS` writer - Port connect status"]
pub type PcstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PCDET` reader - Port connect detected"]
pub type PcdetR = crate::BitReader;
#[doc = "Field `PCDET` writer - Port connect detected"]
pub type PcdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENA` reader - Port enable"]
pub type PenaR = crate::BitReader;
#[doc = "Field `PENA` writer - Port enable"]
pub type PenaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENCHNG` reader - Port enable/disable change"]
pub type PenchngR = crate::BitReader;
#[doc = "Field `PENCHNG` writer - Port enable/disable change"]
pub type PenchngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `POCA` reader - Port overcurrent active"]
pub type PocaR = crate::BitReader;
#[doc = "Field `POCA` writer - Port overcurrent active"]
pub type PocaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `POCCHNG` reader - Port overcurrent change"]
pub type PocchngR = crate::BitReader;
#[doc = "Field `POCCHNG` writer - Port overcurrent change"]
pub type PocchngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRES` reader - Port resume"]
pub type PresR = crate::BitReader;
#[doc = "Field `PRES` writer - Port resume"]
pub type PresW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PSUSP` reader - Port suspend"]
pub type PsuspR = crate::BitReader;
#[doc = "Field `PSUSP` writer - Port suspend"]
pub type PsuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRST` reader - Port reset"]
pub type PrstR = crate::BitReader;
#[doc = "Field `PRST` writer - Port reset"]
pub type PrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLSTS` reader - Port line status"]
pub type PlstsR = crate::FieldReader;
#[doc = "Field `PLSTS` writer - Port line status"]
pub type PlstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PPWR` reader - Port power"]
pub type PpwrR = crate::BitReader;
#[doc = "Field `PPWR` writer - Port power"]
pub type PpwrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTCTL` reader - Port test control"]
pub type PtctlR = crate::FieldReader;
#[doc = "Field `PTCTL` writer - Port test control"]
pub type PtctlW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PSPD` reader - Port speed"]
pub type PspdR = crate::FieldReader;
#[doc = "Field `PSPD` writer - Port speed"]
pub type PspdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Port connect status"]
    #[inline(always)]
    pub fn pcsts(&self) -> PcstsR {
        PcstsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Port connect detected"]
    #[inline(always)]
    pub fn pcdet(&self) -> PcdetR {
        PcdetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Port enable"]
    #[inline(always)]
    pub fn pena(&self) -> PenaR {
        PenaR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Port enable/disable change"]
    #[inline(always)]
    pub fn penchng(&self) -> PenchngR {
        PenchngR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Port overcurrent active"]
    #[inline(always)]
    pub fn poca(&self) -> PocaR {
        PocaR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Port overcurrent change"]
    #[inline(always)]
    pub fn pocchng(&self) -> PocchngR {
        PocchngR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Port resume"]
    #[inline(always)]
    pub fn pres(&self) -> PresR {
        PresR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Port suspend"]
    #[inline(always)]
    pub fn psusp(&self) -> PsuspR {
        PsuspR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Port reset"]
    #[inline(always)]
    pub fn prst(&self) -> PrstR {
        PrstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bits 10:11 - Port line status"]
    #[inline(always)]
    pub fn plsts(&self) -> PlstsR {
        PlstsR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bit 12 - Port power"]
    #[inline(always)]
    pub fn ppwr(&self) -> PpwrR {
        PpwrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bits 13:16 - Port test control"]
    #[inline(always)]
    pub fn ptctl(&self) -> PtctlR {
        PtctlR::new(((self.bits >> 13) & 0x0f) as u8)
    }
    #[doc = "Bits 17:18 - Port speed"]
    #[inline(always)]
    pub fn pspd(&self) -> PspdR {
        PspdR::new(((self.bits >> 17) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Port connect status"]
    #[inline(always)]
    #[must_use]
    pub fn pcsts(&mut self) -> PcstsW<OtgHsHprtSpec> {
        PcstsW::new(self, 0)
    }
    #[doc = "Bit 1 - Port connect detected"]
    #[inline(always)]
    #[must_use]
    pub fn pcdet(&mut self) -> PcdetW<OtgHsHprtSpec> {
        PcdetW::new(self, 1)
    }
    #[doc = "Bit 2 - Port enable"]
    #[inline(always)]
    #[must_use]
    pub fn pena(&mut self) -> PenaW<OtgHsHprtSpec> {
        PenaW::new(self, 2)
    }
    #[doc = "Bit 3 - Port enable/disable change"]
    #[inline(always)]
    #[must_use]
    pub fn penchng(&mut self) -> PenchngW<OtgHsHprtSpec> {
        PenchngW::new(self, 3)
    }
    #[doc = "Bit 4 - Port overcurrent active"]
    #[inline(always)]
    #[must_use]
    pub fn poca(&mut self) -> PocaW<OtgHsHprtSpec> {
        PocaW::new(self, 4)
    }
    #[doc = "Bit 5 - Port overcurrent change"]
    #[inline(always)]
    #[must_use]
    pub fn pocchng(&mut self) -> PocchngW<OtgHsHprtSpec> {
        PocchngW::new(self, 5)
    }
    #[doc = "Bit 6 - Port resume"]
    #[inline(always)]
    #[must_use]
    pub fn pres(&mut self) -> PresW<OtgHsHprtSpec> {
        PresW::new(self, 6)
    }
    #[doc = "Bit 7 - Port suspend"]
    #[inline(always)]
    #[must_use]
    pub fn psusp(&mut self) -> PsuspW<OtgHsHprtSpec> {
        PsuspW::new(self, 7)
    }
    #[doc = "Bit 8 - Port reset"]
    #[inline(always)]
    #[must_use]
    pub fn prst(&mut self) -> PrstW<OtgHsHprtSpec> {
        PrstW::new(self, 8)
    }
    #[doc = "Bits 10:11 - Port line status"]
    #[inline(always)]
    #[must_use]
    pub fn plsts(&mut self) -> PlstsW<OtgHsHprtSpec> {
        PlstsW::new(self, 10)
    }
    #[doc = "Bit 12 - Port power"]
    #[inline(always)]
    #[must_use]
    pub fn ppwr(&mut self) -> PpwrW<OtgHsHprtSpec> {
        PpwrW::new(self, 12)
    }
    #[doc = "Bits 13:16 - Port test control"]
    #[inline(always)]
    #[must_use]
    pub fn ptctl(&mut self) -> PtctlW<OtgHsHprtSpec> {
        PtctlW::new(self, 13)
    }
    #[doc = "Bits 17:18 - Port speed"]
    #[inline(always)]
    #[must_use]
    pub fn pspd(&mut self) -> PspdW<OtgHsHprtSpec> {
        PspdW::new(self, 17)
    }
}
#[doc = "OTG_HS host port control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hprt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hprt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsHprtSpec;
impl crate::RegisterSpec for OtgHsHprtSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`otg_hs_hprt::R`](R) reader structure"]
impl crate::Readable for OtgHsHprtSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_hprt::W`](W) writer structure"]
impl crate::Writable for OtgHsHprtSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_HPRT to value 0"]
impl crate::Resettable for OtgHsHprtSpec {
    const RESET_VALUE: u32 = 0;
}
