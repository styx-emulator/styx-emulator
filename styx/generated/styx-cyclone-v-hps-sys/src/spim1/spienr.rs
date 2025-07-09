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
#[doc = "Register `spienr` reader"]
pub type R = crate::R<SpienrSpec>;
#[doc = "Register `spienr` writer"]
pub type W = crate::W<SpienrSpec>;
#[doc = "Enables and disables all SPI Master operations. When disabled, all serial transfers are halted immediately. Transmit and receive FIFO buffers are cleared when the device is disabled. It is impossible to program some of the SPI Master control registers when enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpiEn {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<SpiEn> for bool {
    #[inline(always)]
    fn from(variant: SpiEn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `spi_en` reader - Enables and disables all SPI Master operations. When disabled, all serial transfers are halted immediately. Transmit and receive FIFO buffers are cleared when the device is disabled. It is impossible to program some of the SPI Master control registers when enabled."]
pub type SpiEnR = crate::BitReader<SpiEn>;
impl SpiEnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SpiEn {
        match self.bits {
            false => SpiEn::Disabled,
            true => SpiEn::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == SpiEn::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == SpiEn::Enabled
    }
}
#[doc = "Field `spi_en` writer - Enables and disables all SPI Master operations. When disabled, all serial transfers are halted immediately. Transmit and receive FIFO buffers are cleared when the device is disabled. It is impossible to program some of the SPI Master control registers when enabled."]
pub type SpiEnW<'a, REG> = crate::BitWriter<'a, REG, SpiEn>;
impl<'a, REG> SpiEnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(SpiEn::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(SpiEn::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Enables and disables all SPI Master operations. When disabled, all serial transfers are halted immediately. Transmit and receive FIFO buffers are cleared when the device is disabled. It is impossible to program some of the SPI Master control registers when enabled."]
    #[inline(always)]
    pub fn spi_en(&self) -> SpiEnR {
        SpiEnR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables and disables all SPI Master operations. When disabled, all serial transfers are halted immediately. Transmit and receive FIFO buffers are cleared when the device is disabled. It is impossible to program some of the SPI Master control registers when enabled."]
    #[inline(always)]
    #[must_use]
    pub fn spi_en(&mut self) -> SpiEnW<SpienrSpec> {
        SpiEnW::new(self, 0)
    }
}
#[doc = "Enables and Disables all SPI operations.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`spienr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`spienr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SpienrSpec;
impl crate::RegisterSpec for SpienrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`spienr::R`](R) reader structure"]
impl crate::Readable for SpienrSpec {}
#[doc = "`write(|w| ..)` method takes [`spienr::W`](W) writer structure"]
impl crate::Writable for SpienrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets spienr to value 0"]
impl crate::Resettable for SpienrSpec {
    const RESET_VALUE: u32 = 0;
}
