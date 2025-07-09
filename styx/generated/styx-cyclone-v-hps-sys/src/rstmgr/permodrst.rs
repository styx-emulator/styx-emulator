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
#[doc = "Register `permodrst` reader"]
pub type R = crate::R<PermodrstSpec>;
#[doc = "Register `permodrst` writer"]
pub type W = crate::W<PermodrstSpec>;
#[doc = "Field `emac0` reader - Resets EMAC0"]
pub type Emac0R = crate::BitReader;
#[doc = "Field `emac0` writer - Resets EMAC0"]
pub type Emac0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `emac1` reader - Resets EMAC1"]
pub type Emac1R = crate::BitReader;
#[doc = "Field `emac1` writer - Resets EMAC1"]
pub type Emac1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `usb0` reader - Resets USB0"]
pub type Usb0R = crate::BitReader;
#[doc = "Field `usb0` writer - Resets USB0"]
pub type Usb0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `usb1` reader - Resets USB1"]
pub type Usb1R = crate::BitReader;
#[doc = "Field `usb1` writer - Resets USB1"]
pub type Usb1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nand` reader - Resets NAND flash controller"]
pub type NandR = crate::BitReader;
#[doc = "Field `nand` writer - Resets NAND flash controller"]
pub type NandW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `qspi` reader - Resets QSPI flash controller"]
pub type QspiR = crate::BitReader;
#[doc = "Field `qspi` writer - Resets QSPI flash controller"]
pub type QspiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4wd0` reader - Resets watchdog 0 connected to L4"]
pub type L4wd0R = crate::BitReader;
#[doc = "Field `l4wd0` writer - Resets watchdog 0 connected to L4"]
pub type L4wd0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4wd1` reader - Resets watchdog 1 connected to L4"]
pub type L4wd1R = crate::BitReader;
#[doc = "Field `l4wd1` writer - Resets watchdog 1 connected to L4"]
pub type L4wd1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `osc1timer0` reader - Resets OSC1 timer 0 connected to L4"]
pub type Osc1timer0R = crate::BitReader;
#[doc = "Field `osc1timer0` writer - Resets OSC1 timer 0 connected to L4"]
pub type Osc1timer0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `osc1timer1` reader - Resets OSC1 timer 1 connected to L4"]
pub type Osc1timer1R = crate::BitReader;
#[doc = "Field `osc1timer1` writer - Resets OSC1 timer 1 connected to L4"]
pub type Osc1timer1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sptimer0` reader - Resets SP timer 0 connected to L4"]
pub type Sptimer0R = crate::BitReader;
#[doc = "Field `sptimer0` writer - Resets SP timer 0 connected to L4"]
pub type Sptimer0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sptimer1` reader - Resets SP timer 1 connected to L4"]
pub type Sptimer1R = crate::BitReader;
#[doc = "Field `sptimer1` writer - Resets SP timer 1 connected to L4"]
pub type Sptimer1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `i2c0` reader - Resets I2C0 controller"]
pub type I2c0R = crate::BitReader;
#[doc = "Field `i2c0` writer - Resets I2C0 controller"]
pub type I2c0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `i2c1` reader - Resets I2C1 controller"]
pub type I2c1R = crate::BitReader;
#[doc = "Field `i2c1` writer - Resets I2C1 controller"]
pub type I2c1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `i2c2` reader - Resets I2C2 controller"]
pub type I2c2R = crate::BitReader;
#[doc = "Field `i2c2` writer - Resets I2C2 controller"]
pub type I2c2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `i2c3` reader - Resets I2C3 controller"]
pub type I2c3R = crate::BitReader;
#[doc = "Field `i2c3` writer - Resets I2C3 controller"]
pub type I2c3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `uart0` reader - Resets UART0"]
pub type Uart0R = crate::BitReader;
#[doc = "Field `uart0` writer - Resets UART0"]
pub type Uart0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `uart1` reader - Resets UART1"]
pub type Uart1R = crate::BitReader;
#[doc = "Field `uart1` writer - Resets UART1"]
pub type Uart1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `spim0` reader - Resets SPIM0 controller"]
pub type Spim0R = crate::BitReader;
#[doc = "Field `spim0` writer - Resets SPIM0 controller"]
pub type Spim0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `spim1` reader - Resets SPIM1 controller"]
pub type Spim1R = crate::BitReader;
#[doc = "Field `spim1` writer - Resets SPIM1 controller"]
pub type Spim1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `spis0` reader - Resets SPIS0 controller"]
pub type Spis0R = crate::BitReader;
#[doc = "Field `spis0` writer - Resets SPIS0 controller"]
pub type Spis0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `spis1` reader - Resets SPIS1 controller"]
pub type Spis1R = crate::BitReader;
#[doc = "Field `spis1` writer - Resets SPIS1 controller"]
pub type Spis1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdmmc` reader - Resets SD/MMC controller"]
pub type SdmmcR = crate::BitReader;
#[doc = "Field `sdmmc` writer - Resets SD/MMC controller"]
pub type SdmmcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `can0` reader - Resets CAN0 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
pub type Can0R = crate::BitReader;
#[doc = "Field `can0` writer - Resets CAN0 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
pub type Can0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `can1` reader - Resets CAN1 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
pub type Can1R = crate::BitReader;
#[doc = "Field `can1` writer - Resets CAN1 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
pub type Can1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gpio0` reader - Resets GPIO0"]
pub type Gpio0R = crate::BitReader;
#[doc = "Field `gpio0` writer - Resets GPIO0"]
pub type Gpio0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gpio1` reader - Resets GPIO1"]
pub type Gpio1R = crate::BitReader;
#[doc = "Field `gpio1` writer - Resets GPIO1"]
pub type Gpio1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gpio2` reader - Resets GPIO2"]
pub type Gpio2R = crate::BitReader;
#[doc = "Field `gpio2` writer - Resets GPIO2"]
pub type Gpio2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dma` reader - Resets DMA controller"]
pub type DmaR = crate::BitReader;
#[doc = "Field `dma` writer - Resets DMA controller"]
pub type DmaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdr` reader - Resets SDRAM Controller Subsystem affected by a warm or cold reset."]
pub type SdrR = crate::BitReader;
#[doc = "Field `sdr` writer - Resets SDRAM Controller Subsystem affected by a warm or cold reset."]
pub type SdrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Resets EMAC0"]
    #[inline(always)]
    pub fn emac0(&self) -> Emac0R {
        Emac0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Resets EMAC1"]
    #[inline(always)]
    pub fn emac1(&self) -> Emac1R {
        Emac1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Resets USB0"]
    #[inline(always)]
    pub fn usb0(&self) -> Usb0R {
        Usb0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Resets USB1"]
    #[inline(always)]
    pub fn usb1(&self) -> Usb1R {
        Usb1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Resets NAND flash controller"]
    #[inline(always)]
    pub fn nand(&self) -> NandR {
        NandR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Resets QSPI flash controller"]
    #[inline(always)]
    pub fn qspi(&self) -> QspiR {
        QspiR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Resets watchdog 0 connected to L4"]
    #[inline(always)]
    pub fn l4wd0(&self) -> L4wd0R {
        L4wd0R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Resets watchdog 1 connected to L4"]
    #[inline(always)]
    pub fn l4wd1(&self) -> L4wd1R {
        L4wd1R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Resets OSC1 timer 0 connected to L4"]
    #[inline(always)]
    pub fn osc1timer0(&self) -> Osc1timer0R {
        Osc1timer0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Resets OSC1 timer 1 connected to L4"]
    #[inline(always)]
    pub fn osc1timer1(&self) -> Osc1timer1R {
        Osc1timer1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Resets SP timer 0 connected to L4"]
    #[inline(always)]
    pub fn sptimer0(&self) -> Sptimer0R {
        Sptimer0R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Resets SP timer 1 connected to L4"]
    #[inline(always)]
    pub fn sptimer1(&self) -> Sptimer1R {
        Sptimer1R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Resets I2C0 controller"]
    #[inline(always)]
    pub fn i2c0(&self) -> I2c0R {
        I2c0R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Resets I2C1 controller"]
    #[inline(always)]
    pub fn i2c1(&self) -> I2c1R {
        I2c1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Resets I2C2 controller"]
    #[inline(always)]
    pub fn i2c2(&self) -> I2c2R {
        I2c2R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Resets I2C3 controller"]
    #[inline(always)]
    pub fn i2c3(&self) -> I2c3R {
        I2c3R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Resets UART0"]
    #[inline(always)]
    pub fn uart0(&self) -> Uart0R {
        Uart0R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Resets UART1"]
    #[inline(always)]
    pub fn uart1(&self) -> Uart1R {
        Uart1R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Resets SPIM0 controller"]
    #[inline(always)]
    pub fn spim0(&self) -> Spim0R {
        Spim0R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Resets SPIM1 controller"]
    #[inline(always)]
    pub fn spim1(&self) -> Spim1R {
        Spim1R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Resets SPIS0 controller"]
    #[inline(always)]
    pub fn spis0(&self) -> Spis0R {
        Spis0R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Resets SPIS1 controller"]
    #[inline(always)]
    pub fn spis1(&self) -> Spis1R {
        Spis1R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Resets SD/MMC controller"]
    #[inline(always)]
    pub fn sdmmc(&self) -> SdmmcR {
        SdmmcR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Resets CAN0 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
    #[inline(always)]
    pub fn can0(&self) -> Can0R {
        Can0R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Resets CAN1 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
    #[inline(always)]
    pub fn can1(&self) -> Can1R {
        Can1R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Resets GPIO0"]
    #[inline(always)]
    pub fn gpio0(&self) -> Gpio0R {
        Gpio0R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Resets GPIO1"]
    #[inline(always)]
    pub fn gpio1(&self) -> Gpio1R {
        Gpio1R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Resets GPIO2"]
    #[inline(always)]
    pub fn gpio2(&self) -> Gpio2R {
        Gpio2R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Resets DMA controller"]
    #[inline(always)]
    pub fn dma(&self) -> DmaR {
        DmaR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Resets SDRAM Controller Subsystem affected by a warm or cold reset."]
    #[inline(always)]
    pub fn sdr(&self) -> SdrR {
        SdrR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Resets EMAC0"]
    #[inline(always)]
    #[must_use]
    pub fn emac0(&mut self) -> Emac0W<PermodrstSpec> {
        Emac0W::new(self, 0)
    }
    #[doc = "Bit 1 - Resets EMAC1"]
    #[inline(always)]
    #[must_use]
    pub fn emac1(&mut self) -> Emac1W<PermodrstSpec> {
        Emac1W::new(self, 1)
    }
    #[doc = "Bit 2 - Resets USB0"]
    #[inline(always)]
    #[must_use]
    pub fn usb0(&mut self) -> Usb0W<PermodrstSpec> {
        Usb0W::new(self, 2)
    }
    #[doc = "Bit 3 - Resets USB1"]
    #[inline(always)]
    #[must_use]
    pub fn usb1(&mut self) -> Usb1W<PermodrstSpec> {
        Usb1W::new(self, 3)
    }
    #[doc = "Bit 4 - Resets NAND flash controller"]
    #[inline(always)]
    #[must_use]
    pub fn nand(&mut self) -> NandW<PermodrstSpec> {
        NandW::new(self, 4)
    }
    #[doc = "Bit 5 - Resets QSPI flash controller"]
    #[inline(always)]
    #[must_use]
    pub fn qspi(&mut self) -> QspiW<PermodrstSpec> {
        QspiW::new(self, 5)
    }
    #[doc = "Bit 6 - Resets watchdog 0 connected to L4"]
    #[inline(always)]
    #[must_use]
    pub fn l4wd0(&mut self) -> L4wd0W<PermodrstSpec> {
        L4wd0W::new(self, 6)
    }
    #[doc = "Bit 7 - Resets watchdog 1 connected to L4"]
    #[inline(always)]
    #[must_use]
    pub fn l4wd1(&mut self) -> L4wd1W<PermodrstSpec> {
        L4wd1W::new(self, 7)
    }
    #[doc = "Bit 8 - Resets OSC1 timer 0 connected to L4"]
    #[inline(always)]
    #[must_use]
    pub fn osc1timer0(&mut self) -> Osc1timer0W<PermodrstSpec> {
        Osc1timer0W::new(self, 8)
    }
    #[doc = "Bit 9 - Resets OSC1 timer 1 connected to L4"]
    #[inline(always)]
    #[must_use]
    pub fn osc1timer1(&mut self) -> Osc1timer1W<PermodrstSpec> {
        Osc1timer1W::new(self, 9)
    }
    #[doc = "Bit 10 - Resets SP timer 0 connected to L4"]
    #[inline(always)]
    #[must_use]
    pub fn sptimer0(&mut self) -> Sptimer0W<PermodrstSpec> {
        Sptimer0W::new(self, 10)
    }
    #[doc = "Bit 11 - Resets SP timer 1 connected to L4"]
    #[inline(always)]
    #[must_use]
    pub fn sptimer1(&mut self) -> Sptimer1W<PermodrstSpec> {
        Sptimer1W::new(self, 11)
    }
    #[doc = "Bit 12 - Resets I2C0 controller"]
    #[inline(always)]
    #[must_use]
    pub fn i2c0(&mut self) -> I2c0W<PermodrstSpec> {
        I2c0W::new(self, 12)
    }
    #[doc = "Bit 13 - Resets I2C1 controller"]
    #[inline(always)]
    #[must_use]
    pub fn i2c1(&mut self) -> I2c1W<PermodrstSpec> {
        I2c1W::new(self, 13)
    }
    #[doc = "Bit 14 - Resets I2C2 controller"]
    #[inline(always)]
    #[must_use]
    pub fn i2c2(&mut self) -> I2c2W<PermodrstSpec> {
        I2c2W::new(self, 14)
    }
    #[doc = "Bit 15 - Resets I2C3 controller"]
    #[inline(always)]
    #[must_use]
    pub fn i2c3(&mut self) -> I2c3W<PermodrstSpec> {
        I2c3W::new(self, 15)
    }
    #[doc = "Bit 16 - Resets UART0"]
    #[inline(always)]
    #[must_use]
    pub fn uart0(&mut self) -> Uart0W<PermodrstSpec> {
        Uart0W::new(self, 16)
    }
    #[doc = "Bit 17 - Resets UART1"]
    #[inline(always)]
    #[must_use]
    pub fn uart1(&mut self) -> Uart1W<PermodrstSpec> {
        Uart1W::new(self, 17)
    }
    #[doc = "Bit 18 - Resets SPIM0 controller"]
    #[inline(always)]
    #[must_use]
    pub fn spim0(&mut self) -> Spim0W<PermodrstSpec> {
        Spim0W::new(self, 18)
    }
    #[doc = "Bit 19 - Resets SPIM1 controller"]
    #[inline(always)]
    #[must_use]
    pub fn spim1(&mut self) -> Spim1W<PermodrstSpec> {
        Spim1W::new(self, 19)
    }
    #[doc = "Bit 20 - Resets SPIS0 controller"]
    #[inline(always)]
    #[must_use]
    pub fn spis0(&mut self) -> Spis0W<PermodrstSpec> {
        Spis0W::new(self, 20)
    }
    #[doc = "Bit 21 - Resets SPIS1 controller"]
    #[inline(always)]
    #[must_use]
    pub fn spis1(&mut self) -> Spis1W<PermodrstSpec> {
        Spis1W::new(self, 21)
    }
    #[doc = "Bit 22 - Resets SD/MMC controller"]
    #[inline(always)]
    #[must_use]
    pub fn sdmmc(&mut self) -> SdmmcW<PermodrstSpec> {
        SdmmcW::new(self, 22)
    }
    #[doc = "Bit 23 - Resets CAN0 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
    #[inline(always)]
    #[must_use]
    pub fn can0(&mut self) -> Can0W<PermodrstSpec> {
        Can0W::new(self, 23)
    }
    #[doc = "Bit 24 - Resets CAN1 controller. Writes to this field on devices not containing CAN controllers will be ignored."]
    #[inline(always)]
    #[must_use]
    pub fn can1(&mut self) -> Can1W<PermodrstSpec> {
        Can1W::new(self, 24)
    }
    #[doc = "Bit 25 - Resets GPIO0"]
    #[inline(always)]
    #[must_use]
    pub fn gpio0(&mut self) -> Gpio0W<PermodrstSpec> {
        Gpio0W::new(self, 25)
    }
    #[doc = "Bit 26 - Resets GPIO1"]
    #[inline(always)]
    #[must_use]
    pub fn gpio1(&mut self) -> Gpio1W<PermodrstSpec> {
        Gpio1W::new(self, 26)
    }
    #[doc = "Bit 27 - Resets GPIO2"]
    #[inline(always)]
    #[must_use]
    pub fn gpio2(&mut self) -> Gpio2W<PermodrstSpec> {
        Gpio2W::new(self, 27)
    }
    #[doc = "Bit 28 - Resets DMA controller"]
    #[inline(always)]
    #[must_use]
    pub fn dma(&mut self) -> DmaW<PermodrstSpec> {
        DmaW::new(self, 28)
    }
    #[doc = "Bit 29 - Resets SDRAM Controller Subsystem affected by a warm or cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn sdr(&mut self) -> SdrW<PermodrstSpec> {
        SdrW::new(self, 29)
    }
}
#[doc = "The PERMODRST register is used by software to trigger module resets (individual module reset signals). Software explicitly asserts and de-asserts module reset signals by writing bits in the appropriate *MODRST register. It is up to software to ensure module reset signals are asserted for the appropriate length of time and are de-asserted in the correct order. It is also up to software to not assert a module reset signal that would prevent software from de-asserting the module reset signal. For example, software should not assert the module reset to the CPU executing the software. Software writes a bit to 1 to assert the module reset signal and to 0 to de-assert the module reset signal. All fields are reset by a cold reset.All fields are also reset by a warm reset if not masked by the corresponding PERWARMMASK field. The reset value of all fields is 1. This holds the corresponding module in reset until software is ready to release the module from reset by writing 0 to its field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`permodrst::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`permodrst::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PermodrstSpec;
impl crate::RegisterSpec for PermodrstSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`permodrst::R`](R) reader structure"]
impl crate::Readable for PermodrstSpec {}
#[doc = "`write(|w| ..)` method takes [`permodrst::W`](W) writer structure"]
impl crate::Writable for PermodrstSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets permodrst to value 0x3fff_ffff"]
impl crate::Resettable for PermodrstSpec {
    const RESET_VALUE: u32 = 0x3fff_ffff;
}
