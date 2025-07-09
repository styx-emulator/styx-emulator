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
#[doc = "Register `stat` reader"]
pub type R = crate::R<StatSpec>;
#[doc = "Register `stat` writer"]
pub type W = crate::W<StatSpec>;
#[doc = "Field `porvoltrst` reader - Built-in POR voltage detector triggered a cold reset (por_voltage_req = 1)"]
pub type PorvoltrstR = crate::BitReader;
#[doc = "Field `porvoltrst` writer - Built-in POR voltage detector triggered a cold reset (por_voltage_req = 1)"]
pub type PorvoltrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `nporpinrst` reader - nPOR pin triggered a cold reset (por_pin_req = 1)"]
pub type NporpinrstR = crate::BitReader;
#[doc = "Field `nporpinrst` writer - nPOR pin triggered a cold reset (por_pin_req = 1)"]
pub type NporpinrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `fpgacoldrst` reader - FPGA core triggered a cold reset (f2h_cold_rst_req_n = 1)"]
pub type FpgacoldrstR = crate::BitReader;
#[doc = "Field `fpgacoldrst` writer - FPGA core triggered a cold reset (f2h_cold_rst_req_n = 1)"]
pub type FpgacoldrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `configiocoldrst` reader - FPGA entered CONFIG_IO mode and a triggered a cold reset"]
pub type ConfigiocoldrstR = crate::BitReader;
#[doc = "Field `configiocoldrst` writer - FPGA entered CONFIG_IO mode and a triggered a cold reset"]
pub type ConfigiocoldrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `swcoldrst` reader - Software wrote CTRL.SWCOLDRSTREQ to 1 and triggered a cold reset"]
pub type SwcoldrstR = crate::BitReader;
#[doc = "Field `swcoldrst` writer - Software wrote CTRL.SWCOLDRSTREQ to 1 and triggered a cold reset"]
pub type SwcoldrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `nrstpinrst` reader - nRST pin triggered a hardware sequenced warm reset"]
pub type NrstpinrstR = crate::BitReader;
#[doc = "Field `nrstpinrst` writer - nRST pin triggered a hardware sequenced warm reset"]
pub type NrstpinrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `fpgawarmrst` reader - FPGA core triggered a hardware sequenced warm reset (f2h_warm_rst_req_n = 1)"]
pub type FpgawarmrstR = crate::BitReader;
#[doc = "Field `fpgawarmrst` writer - FPGA core triggered a hardware sequenced warm reset (f2h_warm_rst_req_n = 1)"]
pub type FpgawarmrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `swwarmrst` reader - Software wrote CTRL.SWWARMRSTREQ to 1 and triggered a hardware sequenced warm reset"]
pub type SwwarmrstR = crate::BitReader;
#[doc = "Field `swwarmrst` writer - Software wrote CTRL.SWWARMRSTREQ to 1 and triggered a hardware sequenced warm reset"]
pub type SwwarmrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `mpuwd0rst` reader - MPU Watchdog 0 triggered a hardware sequenced warm reset"]
pub type Mpuwd0rstR = crate::BitReader;
#[doc = "Field `mpuwd0rst` writer - MPU Watchdog 0 triggered a hardware sequenced warm reset"]
pub type Mpuwd0rstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `mpuwd1rst` reader - MPU Watchdog 1 triggered a hardware sequenced warm reset"]
pub type Mpuwd1rstR = crate::BitReader;
#[doc = "Field `mpuwd1rst` writer - MPU Watchdog 1 triggered a hardware sequenced warm reset"]
pub type Mpuwd1rstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `l4wd0rst` reader - L4 Watchdog 0 triggered a hardware sequenced warm reset"]
pub type L4wd0rstR = crate::BitReader;
#[doc = "Field `l4wd0rst` writer - L4 Watchdog 0 triggered a hardware sequenced warm reset"]
pub type L4wd0rstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `l4wd1rst` reader - L4 Watchdog 1 triggered a hardware sequenced warm reset"]
pub type L4wd1rstR = crate::BitReader;
#[doc = "Field `l4wd1rst` writer - L4 Watchdog 1 triggered a hardware sequenced warm reset"]
pub type L4wd1rstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `fpgadbgrst` reader - FPGA triggered debug reset (f2h_dbg_rst_req_n = 1)"]
pub type FpgadbgrstR = crate::BitReader;
#[doc = "Field `fpgadbgrst` writer - FPGA triggered debug reset (f2h_dbg_rst_req_n = 1)"]
pub type FpgadbgrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `cdbgreqrst` reader - DAP triggered debug reset"]
pub type CdbgreqrstR = crate::BitReader;
#[doc = "Field `cdbgreqrst` writer - DAP triggered debug reset"]
pub type CdbgreqrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `sdrselfreftimeout` reader - A 1 indicates that Reset Manager's request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type SdrselfreftimeoutR = crate::BitReader;
#[doc = "Field `sdrselfreftimeout` writer - A 1 indicates that Reset Manager's request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type SdrselfreftimeoutW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `fpgamgrhstimeout` reader - A 1 indicates that Reset Manager's request to the FPGA manager to stop driving configuration clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type FpgamgrhstimeoutR = crate::BitReader;
#[doc = "Field `fpgamgrhstimeout` writer - A 1 indicates that Reset Manager's request to the FPGA manager to stop driving configuration clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type FpgamgrhstimeoutW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `scanhstimeout` reader - A 1 indicates that Reset Manager's request to the SCAN manager to stop driving JTAG clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type ScanhstimeoutR = crate::BitReader;
#[doc = "Field `scanhstimeout` writer - A 1 indicates that Reset Manager's request to the SCAN manager to stop driving JTAG clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type ScanhstimeoutW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `fpgahstimeout` reader - A 1 indicates that Reset Manager's handshake request to FPGA before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type FpgahstimeoutR = crate::BitReader;
#[doc = "Field `fpgahstimeout` writer - A 1 indicates that Reset Manager's handshake request to FPGA before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type FpgahstimeoutW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `etrstalltimeout` reader - A 1 indicates that Reset Manager's request to the ETR (Embedded Trace Router) to stall its AXI master port before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type EtrstalltimeoutR = crate::BitReader;
#[doc = "Field `etrstalltimeout` writer - A 1 indicates that Reset Manager's request to the ETR (Embedded Trace Router) to stall its AXI master port before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
pub type EtrstalltimeoutW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - Built-in POR voltage detector triggered a cold reset (por_voltage_req = 1)"]
    #[inline(always)]
    pub fn porvoltrst(&self) -> PorvoltrstR {
        PorvoltrstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - nPOR pin triggered a cold reset (por_pin_req = 1)"]
    #[inline(always)]
    pub fn nporpinrst(&self) -> NporpinrstR {
        NporpinrstR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - FPGA core triggered a cold reset (f2h_cold_rst_req_n = 1)"]
    #[inline(always)]
    pub fn fpgacoldrst(&self) -> FpgacoldrstR {
        FpgacoldrstR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - FPGA entered CONFIG_IO mode and a triggered a cold reset"]
    #[inline(always)]
    pub fn configiocoldrst(&self) -> ConfigiocoldrstR {
        ConfigiocoldrstR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Software wrote CTRL.SWCOLDRSTREQ to 1 and triggered a cold reset"]
    #[inline(always)]
    pub fn swcoldrst(&self) -> SwcoldrstR {
        SwcoldrstR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 8 - nRST pin triggered a hardware sequenced warm reset"]
    #[inline(always)]
    pub fn nrstpinrst(&self) -> NrstpinrstR {
        NrstpinrstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - FPGA core triggered a hardware sequenced warm reset (f2h_warm_rst_req_n = 1)"]
    #[inline(always)]
    pub fn fpgawarmrst(&self) -> FpgawarmrstR {
        FpgawarmrstR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Software wrote CTRL.SWWARMRSTREQ to 1 and triggered a hardware sequenced warm reset"]
    #[inline(always)]
    pub fn swwarmrst(&self) -> SwwarmrstR {
        SwwarmrstR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 12 - MPU Watchdog 0 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    pub fn mpuwd0rst(&self) -> Mpuwd0rstR {
        Mpuwd0rstR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - MPU Watchdog 1 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    pub fn mpuwd1rst(&self) -> Mpuwd1rstR {
        Mpuwd1rstR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - L4 Watchdog 0 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    pub fn l4wd0rst(&self) -> L4wd0rstR {
        L4wd0rstR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - L4 Watchdog 1 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    pub fn l4wd1rst(&self) -> L4wd1rstR {
        L4wd1rstR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 18 - FPGA triggered debug reset (f2h_dbg_rst_req_n = 1)"]
    #[inline(always)]
    pub fn fpgadbgrst(&self) -> FpgadbgrstR {
        FpgadbgrstR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - DAP triggered debug reset"]
    #[inline(always)]
    pub fn cdbgreqrst(&self) -> CdbgreqrstR {
        CdbgreqrstR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 24 - A 1 indicates that Reset Manager's request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    pub fn sdrselfreftimeout(&self) -> SdrselfreftimeoutR {
        SdrselfreftimeoutR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - A 1 indicates that Reset Manager's request to the FPGA manager to stop driving configuration clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    pub fn fpgamgrhstimeout(&self) -> FpgamgrhstimeoutR {
        FpgamgrhstimeoutR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - A 1 indicates that Reset Manager's request to the SCAN manager to stop driving JTAG clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    pub fn scanhstimeout(&self) -> ScanhstimeoutR {
        ScanhstimeoutR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - A 1 indicates that Reset Manager's handshake request to FPGA before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    pub fn fpgahstimeout(&self) -> FpgahstimeoutR {
        FpgahstimeoutR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - A 1 indicates that Reset Manager's request to the ETR (Embedded Trace Router) to stall its AXI master port before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    pub fn etrstalltimeout(&self) -> EtrstalltimeoutR {
        EtrstalltimeoutR::new(((self.bits >> 28) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Built-in POR voltage detector triggered a cold reset (por_voltage_req = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn porvoltrst(&mut self) -> PorvoltrstW<StatSpec> {
        PorvoltrstW::new(self, 0)
    }
    #[doc = "Bit 1 - nPOR pin triggered a cold reset (por_pin_req = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn nporpinrst(&mut self) -> NporpinrstW<StatSpec> {
        NporpinrstW::new(self, 1)
    }
    #[doc = "Bit 2 - FPGA core triggered a cold reset (f2h_cold_rst_req_n = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn fpgacoldrst(&mut self) -> FpgacoldrstW<StatSpec> {
        FpgacoldrstW::new(self, 2)
    }
    #[doc = "Bit 3 - FPGA entered CONFIG_IO mode and a triggered a cold reset"]
    #[inline(always)]
    #[must_use]
    pub fn configiocoldrst(&mut self) -> ConfigiocoldrstW<StatSpec> {
        ConfigiocoldrstW::new(self, 3)
    }
    #[doc = "Bit 4 - Software wrote CTRL.SWCOLDRSTREQ to 1 and triggered a cold reset"]
    #[inline(always)]
    #[must_use]
    pub fn swcoldrst(&mut self) -> SwcoldrstW<StatSpec> {
        SwcoldrstW::new(self, 4)
    }
    #[doc = "Bit 8 - nRST pin triggered a hardware sequenced warm reset"]
    #[inline(always)]
    #[must_use]
    pub fn nrstpinrst(&mut self) -> NrstpinrstW<StatSpec> {
        NrstpinrstW::new(self, 8)
    }
    #[doc = "Bit 9 - FPGA core triggered a hardware sequenced warm reset (f2h_warm_rst_req_n = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn fpgawarmrst(&mut self) -> FpgawarmrstW<StatSpec> {
        FpgawarmrstW::new(self, 9)
    }
    #[doc = "Bit 10 - Software wrote CTRL.SWWARMRSTREQ to 1 and triggered a hardware sequenced warm reset"]
    #[inline(always)]
    #[must_use]
    pub fn swwarmrst(&mut self) -> SwwarmrstW<StatSpec> {
        SwwarmrstW::new(self, 10)
    }
    #[doc = "Bit 12 - MPU Watchdog 0 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    #[must_use]
    pub fn mpuwd0rst(&mut self) -> Mpuwd0rstW<StatSpec> {
        Mpuwd0rstW::new(self, 12)
    }
    #[doc = "Bit 13 - MPU Watchdog 1 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    #[must_use]
    pub fn mpuwd1rst(&mut self) -> Mpuwd1rstW<StatSpec> {
        Mpuwd1rstW::new(self, 13)
    }
    #[doc = "Bit 14 - L4 Watchdog 0 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    #[must_use]
    pub fn l4wd0rst(&mut self) -> L4wd0rstW<StatSpec> {
        L4wd0rstW::new(self, 14)
    }
    #[doc = "Bit 15 - L4 Watchdog 1 triggered a hardware sequenced warm reset"]
    #[inline(always)]
    #[must_use]
    pub fn l4wd1rst(&mut self) -> L4wd1rstW<StatSpec> {
        L4wd1rstW::new(self, 15)
    }
    #[doc = "Bit 18 - FPGA triggered debug reset (f2h_dbg_rst_req_n = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn fpgadbgrst(&mut self) -> FpgadbgrstW<StatSpec> {
        FpgadbgrstW::new(self, 18)
    }
    #[doc = "Bit 19 - DAP triggered debug reset"]
    #[inline(always)]
    #[must_use]
    pub fn cdbgreqrst(&mut self) -> CdbgreqrstW<StatSpec> {
        CdbgreqrstW::new(self, 19)
    }
    #[doc = "Bit 24 - A 1 indicates that Reset Manager's request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    #[must_use]
    pub fn sdrselfreftimeout(&mut self) -> SdrselfreftimeoutW<StatSpec> {
        SdrselfreftimeoutW::new(self, 24)
    }
    #[doc = "Bit 25 - A 1 indicates that Reset Manager's request to the FPGA manager to stop driving configuration clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    #[must_use]
    pub fn fpgamgrhstimeout(&mut self) -> FpgamgrhstimeoutW<StatSpec> {
        FpgamgrhstimeoutW::new(self, 25)
    }
    #[doc = "Bit 26 - A 1 indicates that Reset Manager's request to the SCAN manager to stop driving JTAG clock to FPGA CB before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    #[must_use]
    pub fn scanhstimeout(&mut self) -> ScanhstimeoutW<StatSpec> {
        ScanhstimeoutW::new(self, 26)
    }
    #[doc = "Bit 27 - A 1 indicates that Reset Manager's handshake request to FPGA before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    #[must_use]
    pub fn fpgahstimeout(&mut self) -> FpgahstimeoutW<StatSpec> {
        FpgahstimeoutW::new(self, 27)
    }
    #[doc = "Bit 28 - A 1 indicates that Reset Manager's request to the ETR (Embedded Trace Router) to stall its AXI master port before starting a hardware sequenced warm reset timed-out and the Reset Manager had to proceed with the warm reset anyway."]
    #[inline(always)]
    #[must_use]
    pub fn etrstalltimeout(&mut self) -> EtrstalltimeoutW<StatSpec> {
        EtrstalltimeoutW::new(self, 28)
    }
}
#[doc = "The STAT register contains bits that indicate the reset source or a timeout event. For reset sources, a field is 1 if its associated reset requester caused the reset. For timeout events, a field is 1 if its associated timeout occured as part of a hardware sequenced warm/debug reset. Software clears bits by writing them with a value of 1. Writes to bits with a value of 0 are ignored. After a cold reset is complete, all bits are reset to their reset value except for the bit(s) that indicate the source of the cold reset. If multiple cold reset requests overlap with each other, the source de-asserts the request last will be logged. The other reset request source(s) de-assert the request in the same cycle will also be logged, the rest of the fields are reset to default value of 0. After a warm reset is complete, the bit(s) that indicate the source of the warm reset are set to 1. A warm reset doesn't clear any of the bits in the STAT register; these bits must be cleared by software writing the STAT register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stat::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatSpec;
impl crate::RegisterSpec for StatSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`stat::R`](R) reader structure"]
impl crate::Readable for StatSpec {}
#[doc = "`write(|w| ..)` method takes [`stat::W`](W) writer structure"]
impl crate::Writable for StatSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x1f0c_f71f;
}
#[doc = "`reset()` method sets stat to value 0"]
impl crate::Resettable for StatSpec {
    const RESET_VALUE: u32 = 0;
}
