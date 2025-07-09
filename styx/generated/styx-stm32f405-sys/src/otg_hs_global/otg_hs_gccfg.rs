// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `OTG_HS_GCCFG` reader"]
pub type R = crate::R<OtgHsGccfgSpec>;
#[doc = "Register `OTG_HS_GCCFG` writer"]
pub type W = crate::W<OtgHsGccfgSpec>;
#[doc = "Field `PWRDWN` reader - Power down"]
pub type PwrdwnR = crate::BitReader;
#[doc = "Field `PWRDWN` writer - Power down"]
pub type PwrdwnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2CPADEN` reader - Enable I2C bus connection for the external I2C PHY interface"]
pub type I2cpadenR = crate::BitReader;
#[doc = "Field `I2CPADEN` writer - Enable I2C bus connection for the external I2C PHY interface"]
pub type I2cpadenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBUSASEN` reader - Enable the VBUS sensing device"]
pub type VbusasenR = crate::BitReader;
#[doc = "Field `VBUSASEN` writer - Enable the VBUS sensing device"]
pub type VbusasenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBUSBSEN` reader - Enable the VBUS sensing device"]
pub type VbusbsenR = crate::BitReader;
#[doc = "Field `VBUSBSEN` writer - Enable the VBUS sensing device"]
pub type VbusbsenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SOFOUTEN` reader - SOF output enable"]
pub type SofoutenR = crate::BitReader;
#[doc = "Field `SOFOUTEN` writer - SOF output enable"]
pub type SofoutenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NOVBUSSENS` reader - VBUS sensing disable option"]
pub type NovbussensR = crate::BitReader;
#[doc = "Field `NOVBUSSENS` writer - VBUS sensing disable option"]
pub type NovbussensW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 16 - Power down"]
    #[inline(always)]
    pub fn pwrdwn(&self) -> PwrdwnR {
        PwrdwnR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Enable I2C bus connection for the external I2C PHY interface"]
    #[inline(always)]
    pub fn i2cpaden(&self) -> I2cpadenR {
        I2cpadenR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Enable the VBUS sensing device"]
    #[inline(always)]
    pub fn vbusasen(&self) -> VbusasenR {
        VbusasenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Enable the VBUS sensing device"]
    #[inline(always)]
    pub fn vbusbsen(&self) -> VbusbsenR {
        VbusbsenR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - SOF output enable"]
    #[inline(always)]
    pub fn sofouten(&self) -> SofoutenR {
        SofoutenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - VBUS sensing disable option"]
    #[inline(always)]
    pub fn novbussens(&self) -> NovbussensR {
        NovbussensR::new(((self.bits >> 21) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 16 - Power down"]
    #[inline(always)]
    #[must_use]
    pub fn pwrdwn(&mut self) -> PwrdwnW<OtgHsGccfgSpec> {
        PwrdwnW::new(self, 16)
    }
    #[doc = "Bit 17 - Enable I2C bus connection for the external I2C PHY interface"]
    #[inline(always)]
    #[must_use]
    pub fn i2cpaden(&mut self) -> I2cpadenW<OtgHsGccfgSpec> {
        I2cpadenW::new(self, 17)
    }
    #[doc = "Bit 18 - Enable the VBUS sensing device"]
    #[inline(always)]
    #[must_use]
    pub fn vbusasen(&mut self) -> VbusasenW<OtgHsGccfgSpec> {
        VbusasenW::new(self, 18)
    }
    #[doc = "Bit 19 - Enable the VBUS sensing device"]
    #[inline(always)]
    #[must_use]
    pub fn vbusbsen(&mut self) -> VbusbsenW<OtgHsGccfgSpec> {
        VbusbsenW::new(self, 19)
    }
    #[doc = "Bit 20 - SOF output enable"]
    #[inline(always)]
    #[must_use]
    pub fn sofouten(&mut self) -> SofoutenW<OtgHsGccfgSpec> {
        SofoutenW::new(self, 20)
    }
    #[doc = "Bit 21 - VBUS sensing disable option"]
    #[inline(always)]
    #[must_use]
    pub fn novbussens(&mut self) -> NovbussensW<OtgHsGccfgSpec> {
        NovbussensW::new(self, 21)
    }
}
#[doc = "OTG_HS general core configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gccfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gccfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsGccfgSpec;
impl crate::RegisterSpec for OtgHsGccfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`otg_hs_gccfg::R`](R) reader structure"]
impl crate::Readable for OtgHsGccfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_gccfg::W`](W) writer structure"]
impl crate::Writable for OtgHsGccfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_GCCFG to value 0"]
impl crate::Resettable for OtgHsGccfgSpec {
    const RESET_VALUE: u32 = 0;
}
