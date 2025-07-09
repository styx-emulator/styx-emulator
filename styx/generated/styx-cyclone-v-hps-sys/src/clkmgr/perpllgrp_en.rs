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
#[doc = "Register `perpllgrp_en` reader"]
pub type R = crate::R<PerpllgrpEnSpec>;
#[doc = "Register `perpllgrp_en` writer"]
pub type W = crate::W<PerpllgrpEnSpec>;
#[doc = "Field `emac0clk` reader - Enables clock emac0_clk output"]
pub type Emac0clkR = crate::BitReader;
#[doc = "Field `emac0clk` writer - Enables clock emac0_clk output"]
pub type Emac0clkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `emac1clk` reader - Enables clock emac1_clk output"]
pub type Emac1clkR = crate::BitReader;
#[doc = "Field `emac1clk` writer - Enables clock emac1_clk output"]
pub type Emac1clkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `usbclk` reader - Enables clock usb_mp_clk output"]
pub type UsbclkR = crate::BitReader;
#[doc = "Field `usbclk` writer - Enables clock usb_mp_clk output"]
pub type UsbclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `spimclk` reader - Enables clock spi_m_clk output"]
pub type SpimclkR = crate::BitReader;
#[doc = "Field `spimclk` writer - Enables clock spi_m_clk output"]
pub type SpimclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `can0clk` reader - Enables clock can0_clk output"]
pub type Can0clkR = crate::BitReader;
#[doc = "Field `can0clk` writer - Enables clock can0_clk output"]
pub type Can0clkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `can1clk` reader - Enables clock can1_clk output"]
pub type Can1clkR = crate::BitReader;
#[doc = "Field `can1clk` writer - Enables clock can1_clk output"]
pub type Can1clkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gpioclk` reader - Enables clock gpio_clk output"]
pub type GpioclkR = crate::BitReader;
#[doc = "Field `gpioclk` writer - Enables clock gpio_clk output"]
pub type GpioclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `s2fuser1clk` reader - Enables clock s2f_user1_clk output. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk."]
pub type S2fuser1clkR = crate::BitReader;
#[doc = "Field `s2fuser1clk` writer - Enables clock s2f_user1_clk output. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk."]
pub type S2fuser1clkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdmmcclk` reader - Enables clock sdmmc_clk output"]
pub type SdmmcclkR = crate::BitReader;
#[doc = "Field `sdmmcclk` writer - Enables clock sdmmc_clk output"]
pub type SdmmcclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nandxclk` reader - Enables clock nand_x_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
pub type NandxclkR = crate::BitReader;
#[doc = "Field `nandxclk` writer - Enables clock nand_x_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
pub type NandxclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nandclk` reader - Enables clock nand_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
pub type NandclkR = crate::BitReader;
#[doc = "Field `nandclk` writer - Enables clock nand_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
pub type NandclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `qspiclk` reader - Enables clock qspi_clk output"]
pub type QspiclkR = crate::BitReader;
#[doc = "Field `qspiclk` writer - Enables clock qspi_clk output"]
pub type QspiclkW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enables clock emac0_clk output"]
    #[inline(always)]
    pub fn emac0clk(&self) -> Emac0clkR {
        Emac0clkR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Enables clock emac1_clk output"]
    #[inline(always)]
    pub fn emac1clk(&self) -> Emac1clkR {
        Emac1clkR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Enables clock usb_mp_clk output"]
    #[inline(always)]
    pub fn usbclk(&self) -> UsbclkR {
        UsbclkR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Enables clock spi_m_clk output"]
    #[inline(always)]
    pub fn spimclk(&self) -> SpimclkR {
        SpimclkR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Enables clock can0_clk output"]
    #[inline(always)]
    pub fn can0clk(&self) -> Can0clkR {
        Can0clkR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Enables clock can1_clk output"]
    #[inline(always)]
    pub fn can1clk(&self) -> Can1clkR {
        Can1clkR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Enables clock gpio_clk output"]
    #[inline(always)]
    pub fn gpioclk(&self) -> GpioclkR {
        GpioclkR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Enables clock s2f_user1_clk output. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk."]
    #[inline(always)]
    pub fn s2fuser1clk(&self) -> S2fuser1clkR {
        S2fuser1clkR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Enables clock sdmmc_clk output"]
    #[inline(always)]
    pub fn sdmmcclk(&self) -> SdmmcclkR {
        SdmmcclkR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Enables clock nand_x_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
    #[inline(always)]
    pub fn nandxclk(&self) -> NandxclkR {
        NandxclkR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Enables clock nand_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
    #[inline(always)]
    pub fn nandclk(&self) -> NandclkR {
        NandclkR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Enables clock qspi_clk output"]
    #[inline(always)]
    pub fn qspiclk(&self) -> QspiclkR {
        QspiclkR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables clock emac0_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn emac0clk(&mut self) -> Emac0clkW<PerpllgrpEnSpec> {
        Emac0clkW::new(self, 0)
    }
    #[doc = "Bit 1 - Enables clock emac1_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn emac1clk(&mut self) -> Emac1clkW<PerpllgrpEnSpec> {
        Emac1clkW::new(self, 1)
    }
    #[doc = "Bit 2 - Enables clock usb_mp_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn usbclk(&mut self) -> UsbclkW<PerpllgrpEnSpec> {
        UsbclkW::new(self, 2)
    }
    #[doc = "Bit 3 - Enables clock spi_m_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn spimclk(&mut self) -> SpimclkW<PerpllgrpEnSpec> {
        SpimclkW::new(self, 3)
    }
    #[doc = "Bit 4 - Enables clock can0_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn can0clk(&mut self) -> Can0clkW<PerpllgrpEnSpec> {
        Can0clkW::new(self, 4)
    }
    #[doc = "Bit 5 - Enables clock can1_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn can1clk(&mut self) -> Can1clkW<PerpllgrpEnSpec> {
        Can1clkW::new(self, 5)
    }
    #[doc = "Bit 6 - Enables clock gpio_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn gpioclk(&mut self) -> GpioclkW<PerpllgrpEnSpec> {
        GpioclkW::new(self, 6)
    }
    #[doc = "Bit 7 - Enables clock s2f_user1_clk output. Qsys and user documenation refer to s2f_user1_clk as h2f_user1_clk."]
    #[inline(always)]
    #[must_use]
    pub fn s2fuser1clk(&mut self) -> S2fuser1clkW<PerpllgrpEnSpec> {
        S2fuser1clkW::new(self, 7)
    }
    #[doc = "Bit 8 - Enables clock sdmmc_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn sdmmcclk(&mut self) -> SdmmcclkW<PerpllgrpEnSpec> {
        SdmmcclkW::new(self, 8)
    }
    #[doc = "Bit 9 - Enables clock nand_x_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
    #[inline(always)]
    #[must_use]
    pub fn nandxclk(&mut self) -> NandxclkW<PerpllgrpEnSpec> {
        NandxclkW::new(self, 9)
    }
    #[doc = "Bit 10 - Enables clock nand_clk output nand_clk Enable should always be de-asserted before the nand_x_clk Enable, and the nand_x_clk Enable should always be asserted before the nand_clk Enable is asserted. A brief delay is also required between switching the enables (8 * nand_clk period)."]
    #[inline(always)]
    #[must_use]
    pub fn nandclk(&mut self) -> NandclkW<PerpllgrpEnSpec> {
        NandclkW::new(self, 10)
    }
    #[doc = "Bit 11 - Enables clock qspi_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn qspiclk(&mut self) -> QspiclkW<PerpllgrpEnSpec> {
        QspiclkW::new(self, 11)
    }
}
#[doc = "Contains fields that control clock enables for clocks derived from the Peripheral PLL 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_en::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_en::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpEnSpec;
impl crate::RegisterSpec for PerpllgrpEnSpec {
    type Ux = u32;
    const OFFSET: u64 = 160u64;
}
#[doc = "`read()` method returns [`perpllgrp_en::R`](R) reader structure"]
impl crate::Readable for PerpllgrpEnSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_en::W`](W) writer structure"]
impl crate::Writable for PerpllgrpEnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_en to value 0x0fff"]
impl crate::Resettable for PerpllgrpEnSpec {
    const RESET_VALUE: u32 = 0x0fff;
}
