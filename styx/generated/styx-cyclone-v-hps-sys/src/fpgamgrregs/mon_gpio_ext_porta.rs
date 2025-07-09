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
#[doc = "Register `mon_gpio_ext_porta` reader"]
pub type R = crate::R<MonGpioExtPortaSpec>;
#[doc = "Register `mon_gpio_ext_porta` writer"]
pub type W = crate::W<MonGpioExtPortaSpec>;
#[doc = "Field `ns` reader - Reading this provides the value of nSTATUS"]
pub type NsR = crate::BitReader;
#[doc = "Field `ns` writer - Reading this provides the value of nSTATUS"]
pub type NsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cd` reader - Reading this provides the value of CONF_DONE"]
pub type CdR = crate::BitReader;
#[doc = "Field `cd` writer - Reading this provides the value of CONF_DONE"]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `id` reader - Reading this provides the value of INIT_DONE"]
pub type IdR = crate::BitReader;
#[doc = "Field `id` writer - Reading this provides the value of INIT_DONE"]
pub type IdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `crc` reader - Reading this provides the value of CRC_ERROR"]
pub type CrcR = crate::BitReader;
#[doc = "Field `crc` writer - Reading this provides the value of CRC_ERROR"]
pub type CrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ccd` reader - Reading this provides the value of CVP_CONF_DONE"]
pub type CcdR = crate::BitReader;
#[doc = "Field `ccd` writer - Reading this provides the value of CVP_CONF_DONE"]
pub type CcdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `prr` reader - Reading this provides the value of PR_READY"]
pub type PrrR = crate::BitReader;
#[doc = "Field `prr` writer - Reading this provides the value of PR_READY"]
pub type PrrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `pre` reader - Reading this provides the value of PR_ERROR"]
pub type PreR = crate::BitReader;
#[doc = "Field `pre` writer - Reading this provides the value of PR_ERROR"]
pub type PreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `prd` reader - Reading this provides the value of PR_DONE"]
pub type PrdR = crate::BitReader;
#[doc = "Field `prd` writer - Reading this provides the value of PR_DONE"]
pub type PrdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ncp` reader - Reading this provides the value of nCONFIG Pin"]
pub type NcpR = crate::BitReader;
#[doc = "Field `ncp` writer - Reading this provides the value of nCONFIG Pin"]
pub type NcpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nsp` reader - Reading this provides the value of nSTATUS Pin"]
pub type NspR = crate::BitReader;
#[doc = "Field `nsp` writer - Reading this provides the value of nSTATUS Pin"]
pub type NspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cdp` reader - Reading this provides the value of CONF_DONE Pin"]
pub type CdpR = crate::BitReader;
#[doc = "Field `cdp` writer - Reading this provides the value of CONF_DONE Pin"]
pub type CdpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpo` reader - Reading this provides the value of FPGA_POWER_ON"]
pub type FpoR = crate::BitReader;
#[doc = "Field `fpo` writer - Reading this provides the value of FPGA_POWER_ON"]
pub type FpoW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Reading this provides the value of nSTATUS"]
    #[inline(always)]
    pub fn ns(&self) -> NsR {
        NsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Reading this provides the value of CONF_DONE"]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Reading this provides the value of INIT_DONE"]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Reading this provides the value of CRC_ERROR"]
    #[inline(always)]
    pub fn crc(&self) -> CrcR {
        CrcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Reading this provides the value of CVP_CONF_DONE"]
    #[inline(always)]
    pub fn ccd(&self) -> CcdR {
        CcdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Reading this provides the value of PR_READY"]
    #[inline(always)]
    pub fn prr(&self) -> PrrR {
        PrrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Reading this provides the value of PR_ERROR"]
    #[inline(always)]
    pub fn pre(&self) -> PreR {
        PreR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Reading this provides the value of PR_DONE"]
    #[inline(always)]
    pub fn prd(&self) -> PrdR {
        PrdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Reading this provides the value of nCONFIG Pin"]
    #[inline(always)]
    pub fn ncp(&self) -> NcpR {
        NcpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Reading this provides the value of nSTATUS Pin"]
    #[inline(always)]
    pub fn nsp(&self) -> NspR {
        NspR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Reading this provides the value of CONF_DONE Pin"]
    #[inline(always)]
    pub fn cdp(&self) -> CdpR {
        CdpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Reading this provides the value of FPGA_POWER_ON"]
    #[inline(always)]
    pub fn fpo(&self) -> FpoR {
        FpoR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Reading this provides the value of nSTATUS"]
    #[inline(always)]
    #[must_use]
    pub fn ns(&mut self) -> NsW<MonGpioExtPortaSpec> {
        NsW::new(self, 0)
    }
    #[doc = "Bit 1 - Reading this provides the value of CONF_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MonGpioExtPortaSpec> {
        CdW::new(self, 1)
    }
    #[doc = "Bit 2 - Reading this provides the value of INIT_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MonGpioExtPortaSpec> {
        IdW::new(self, 2)
    }
    #[doc = "Bit 3 - Reading this provides the value of CRC_ERROR"]
    #[inline(always)]
    #[must_use]
    pub fn crc(&mut self) -> CrcW<MonGpioExtPortaSpec> {
        CrcW::new(self, 3)
    }
    #[doc = "Bit 4 - Reading this provides the value of CVP_CONF_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn ccd(&mut self) -> CcdW<MonGpioExtPortaSpec> {
        CcdW::new(self, 4)
    }
    #[doc = "Bit 5 - Reading this provides the value of PR_READY"]
    #[inline(always)]
    #[must_use]
    pub fn prr(&mut self) -> PrrW<MonGpioExtPortaSpec> {
        PrrW::new(self, 5)
    }
    #[doc = "Bit 6 - Reading this provides the value of PR_ERROR"]
    #[inline(always)]
    #[must_use]
    pub fn pre(&mut self) -> PreW<MonGpioExtPortaSpec> {
        PreW::new(self, 6)
    }
    #[doc = "Bit 7 - Reading this provides the value of PR_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn prd(&mut self) -> PrdW<MonGpioExtPortaSpec> {
        PrdW::new(self, 7)
    }
    #[doc = "Bit 8 - Reading this provides the value of nCONFIG Pin"]
    #[inline(always)]
    #[must_use]
    pub fn ncp(&mut self) -> NcpW<MonGpioExtPortaSpec> {
        NcpW::new(self, 8)
    }
    #[doc = "Bit 9 - Reading this provides the value of nSTATUS Pin"]
    #[inline(always)]
    #[must_use]
    pub fn nsp(&mut self) -> NspW<MonGpioExtPortaSpec> {
        NspW::new(self, 9)
    }
    #[doc = "Bit 10 - Reading this provides the value of CONF_DONE Pin"]
    #[inline(always)]
    #[must_use]
    pub fn cdp(&mut self) -> CdpW<MonGpioExtPortaSpec> {
        CdpW::new(self, 10)
    }
    #[doc = "Bit 11 - Reading this provides the value of FPGA_POWER_ON"]
    #[inline(always)]
    #[must_use]
    pub fn fpo(&mut self) -> FpoW<MonGpioExtPortaSpec> {
        FpoW::new(self, 11)
    }
}
#[doc = "Reading this register reads the values of the GPIO inputs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_ext_porta::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioExtPortaSpec;
impl crate::RegisterSpec for MonGpioExtPortaSpec {
    type Ux = u32;
    const OFFSET: u64 = 2128u64;
}
#[doc = "`read()` method returns [`mon_gpio_ext_porta::R`](R) reader structure"]
impl crate::Readable for MonGpioExtPortaSpec {}
#[doc = "`reset()` method sets mon_gpio_ext_porta to value 0"]
impl crate::Resettable for MonGpioExtPortaSpec {
    const RESET_VALUE: u32 = 0;
}
