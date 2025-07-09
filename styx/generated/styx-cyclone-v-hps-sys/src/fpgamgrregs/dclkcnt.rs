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
#[doc = "Register `dclkcnt` reader"]
pub type R = crate::R<DclkcntSpec>;
#[doc = "Register `dclkcnt` writer"]
pub type W = crate::W<DclkcntSpec>;
#[doc = "Field `cnt` reader - Controls DCLK counter. Software writes a non-zero value into CNT and the FPGA Manager generates the specified number of DCLK pulses and decrements COUNT. This register will read back the original value written by software. Software can write CNT at any time."]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Controls DCLK counter. Software writes a non-zero value into CNT and the FPGA Manager generates the specified number of DCLK pulses and decrements COUNT. This register will read back the original value written by software. Software can write CNT at any time."]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Controls DCLK counter. Software writes a non-zero value into CNT and the FPGA Manager generates the specified number of DCLK pulses and decrements COUNT. This register will read back the original value written by software. Software can write CNT at any time."]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Controls DCLK counter. Software writes a non-zero value into CNT and the FPGA Manager generates the specified number of DCLK pulses and decrements COUNT. This register will read back the original value written by software. Software can write CNT at any time."]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<DclkcntSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Used to give software control in enabling DCLK at any time. SW will need control of the DCLK in specific configuration and partial reconfiguration initialization steps to send spurious DCLKs required by the CB. SW takes ownership for DCLK during normal configuration, partial reconfiguration, error scenerio handshakes including SEU CRC error during partial reconfiguration, SW early abort of partial reconfiguration, and initializatin phase DCLK driving. During initialization phase, a configuration image loaded into the FPGA can request that DCLK be used as the initialization phase clock instead of the default internal oscillator or optionally the CLKUSR pin. In the case that DCLK is requested, the DCLKCNT register is used by software to control DCLK during the initialization phase. Software should poll the DCLKSTAT.DCNTDONE write one to clear register to be set when the correct number of DCLKs have completed. Software should clear DCLKSTAT.DCNTDONE before writing to the DCLKCNT register again. This field only affects the FPGA if CTRL.EN is 1.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dclkcnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dclkcnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DclkcntSpec;
impl crate::RegisterSpec for DclkcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`dclkcnt::R`](R) reader structure"]
impl crate::Readable for DclkcntSpec {}
#[doc = "`write(|w| ..)` method takes [`dclkcnt::W`](W) writer structure"]
impl crate::Writable for DclkcntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dclkcnt to value 0"]
impl crate::Resettable for DclkcntSpec {
    const RESET_VALUE: u32 = 0;
}
