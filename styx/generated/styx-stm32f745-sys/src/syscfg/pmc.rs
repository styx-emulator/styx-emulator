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
#[doc = "Register `PMC` reader"]
pub type R = crate::R<PmcSpec>;
#[doc = "Register `PMC` writer"]
pub type W = crate::W<PmcSpec>;
#[doc = "Field `ADC1DC2` reader - ADC1DC2"]
pub type Adc1dc2R = crate::BitReader;
#[doc = "Field `ADC1DC2` writer - ADC1DC2"]
pub type Adc1dc2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC2DC2` reader - ADC2DC2"]
pub type Adc2dc2R = crate::BitReader;
#[doc = "Field `ADC2DC2` writer - ADC2DC2"]
pub type Adc2dc2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC3DC2` reader - ADC3DC2"]
pub type Adc3dc2R = crate::BitReader;
#[doc = "Field `ADC3DC2` writer - ADC3DC2"]
pub type Adc3dc2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MII_RMII_SEL` reader - Ethernet PHY interface selection"]
pub type MiiRmiiSelR = crate::BitReader;
#[doc = "Field `MII_RMII_SEL` writer - Ethernet PHY interface selection"]
pub type MiiRmiiSelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 16 - ADC1DC2"]
    #[inline(always)]
    pub fn adc1dc2(&self) -> Adc1dc2R {
        Adc1dc2R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - ADC2DC2"]
    #[inline(always)]
    pub fn adc2dc2(&self) -> Adc2dc2R {
        Adc2dc2R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - ADC3DC2"]
    #[inline(always)]
    pub fn adc3dc2(&self) -> Adc3dc2R {
        Adc3dc2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 23 - Ethernet PHY interface selection"]
    #[inline(always)]
    pub fn mii_rmii_sel(&self) -> MiiRmiiSelR {
        MiiRmiiSelR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 16 - ADC1DC2"]
    #[inline(always)]
    #[must_use]
    pub fn adc1dc2(&mut self) -> Adc1dc2W<PmcSpec> {
        Adc1dc2W::new(self, 16)
    }
    #[doc = "Bit 17 - ADC2DC2"]
    #[inline(always)]
    #[must_use]
    pub fn adc2dc2(&mut self) -> Adc2dc2W<PmcSpec> {
        Adc2dc2W::new(self, 17)
    }
    #[doc = "Bit 18 - ADC3DC2"]
    #[inline(always)]
    #[must_use]
    pub fn adc3dc2(&mut self) -> Adc3dc2W<PmcSpec> {
        Adc3dc2W::new(self, 18)
    }
    #[doc = "Bit 23 - Ethernet PHY interface selection"]
    #[inline(always)]
    #[must_use]
    pub fn mii_rmii_sel(&mut self) -> MiiRmiiSelW<PmcSpec> {
        MiiRmiiSelW::new(self, 23)
    }
}
#[doc = "peripheral mode configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pmc::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pmc::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PmcSpec;
impl crate::RegisterSpec for PmcSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`pmc::R`](R) reader structure"]
impl crate::Readable for PmcSpec {}
#[doc = "`write(|w| ..)` method takes [`pmc::W`](W) writer structure"]
impl crate::Writable for PmcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PMC to value 0"]
impl crate::Resettable for PmcSpec {
    const RESET_VALUE: u32 = 0;
}
