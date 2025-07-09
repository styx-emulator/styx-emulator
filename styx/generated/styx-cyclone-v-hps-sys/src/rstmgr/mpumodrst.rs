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
#[doc = "Register `mpumodrst` reader"]
pub type R = crate::R<MpumodrstSpec>;
#[doc = "Register `mpumodrst` writer"]
pub type W = crate::W<MpumodrstSpec>;
#[doc = "Field `cpu0` reader - Resets Cortex-A9 CPU0 in MPU. Whe software changes this field from 0 to 1, ittriggers the following sequence: 1. CPU0 reset is asserted. cpu0 clkoff is de-asserted 2. after 32 osc1_clk cycles, cpu0 clkoff is asserted. When software changes this field from 1 to 0, it triggers the following sequence: 1.CPU0 reset is de-asserted. 2. after 32 cycles, cpu0 clkoff is de-asserted. Software needs to wait for at least 64 osc1_clk cycles between each change of this field to keep the proper reset/clkoff sequence."]
pub type Cpu0R = crate::BitReader;
#[doc = "Field `cpu0` writer - Resets Cortex-A9 CPU0 in MPU. Whe software changes this field from 0 to 1, ittriggers the following sequence: 1. CPU0 reset is asserted. cpu0 clkoff is de-asserted 2. after 32 osc1_clk cycles, cpu0 clkoff is asserted. When software changes this field from 1 to 0, it triggers the following sequence: 1.CPU0 reset is de-asserted. 2. after 32 cycles, cpu0 clkoff is de-asserted. Software needs to wait for at least 64 osc1_clk cycles between each change of this field to keep the proper reset/clkoff sequence."]
pub type Cpu0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cpu1` reader - Resets Cortex-A9 CPU1 in MPU. It is reset to 1 on a cold or warm reset. This holds CPU1 in reset until software is ready to release CPU1 from reset by writing 0 to this field. On single-core devices, writes to this field are ignored.On dual-core devices, writes to this field trigger the same sequence as writes to the CPU0 field (except the sequence is performed on CPU1)."]
pub type Cpu1R = crate::BitReader;
#[doc = "Field `cpu1` writer - Resets Cortex-A9 CPU1 in MPU. It is reset to 1 on a cold or warm reset. This holds CPU1 in reset until software is ready to release CPU1 from reset by writing 0 to this field. On single-core devices, writes to this field are ignored.On dual-core devices, writes to this field trigger the same sequence as writes to the CPU0 field (except the sequence is performed on CPU1)."]
pub type Cpu1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `wds` reader - Resets both per-CPU Watchdog Reset Status registers in MPU."]
pub type WdsR = crate::BitReader;
#[doc = "Field `wds` writer - Resets both per-CPU Watchdog Reset Status registers in MPU."]
pub type WdsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `scuper` reader - Resets SCU and peripherals. Peripherals consist of the interrupt controller, global timer, both per-CPU private timers, and both per-CPU watchdogs (except for the Watchdog Reset Status registers)."]
pub type ScuperR = crate::BitReader;
#[doc = "Field `scuper` writer - Resets SCU and peripherals. Peripherals consist of the interrupt controller, global timer, both per-CPU private timers, and both per-CPU watchdogs (except for the Watchdog Reset Status registers)."]
pub type ScuperW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l2` reader - Resets L2 cache controller"]
pub type L2R = crate::BitReader;
#[doc = "Field `l2` writer - Resets L2 cache controller"]
pub type L2W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Resets Cortex-A9 CPU0 in MPU. Whe software changes this field from 0 to 1, ittriggers the following sequence: 1. CPU0 reset is asserted. cpu0 clkoff is de-asserted 2. after 32 osc1_clk cycles, cpu0 clkoff is asserted. When software changes this field from 1 to 0, it triggers the following sequence: 1.CPU0 reset is de-asserted. 2. after 32 cycles, cpu0 clkoff is de-asserted. Software needs to wait for at least 64 osc1_clk cycles between each change of this field to keep the proper reset/clkoff sequence."]
    #[inline(always)]
    pub fn cpu0(&self) -> Cpu0R {
        Cpu0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Resets Cortex-A9 CPU1 in MPU. It is reset to 1 on a cold or warm reset. This holds CPU1 in reset until software is ready to release CPU1 from reset by writing 0 to this field. On single-core devices, writes to this field are ignored.On dual-core devices, writes to this field trigger the same sequence as writes to the CPU0 field (except the sequence is performed on CPU1)."]
    #[inline(always)]
    pub fn cpu1(&self) -> Cpu1R {
        Cpu1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Resets both per-CPU Watchdog Reset Status registers in MPU."]
    #[inline(always)]
    pub fn wds(&self) -> WdsR {
        WdsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Resets SCU and peripherals. Peripherals consist of the interrupt controller, global timer, both per-CPU private timers, and both per-CPU watchdogs (except for the Watchdog Reset Status registers)."]
    #[inline(always)]
    pub fn scuper(&self) -> ScuperR {
        ScuperR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Resets L2 cache controller"]
    #[inline(always)]
    pub fn l2(&self) -> L2R {
        L2R::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Resets Cortex-A9 CPU0 in MPU. Whe software changes this field from 0 to 1, ittriggers the following sequence: 1. CPU0 reset is asserted. cpu0 clkoff is de-asserted 2. after 32 osc1_clk cycles, cpu0 clkoff is asserted. When software changes this field from 1 to 0, it triggers the following sequence: 1.CPU0 reset is de-asserted. 2. after 32 cycles, cpu0 clkoff is de-asserted. Software needs to wait for at least 64 osc1_clk cycles between each change of this field to keep the proper reset/clkoff sequence."]
    #[inline(always)]
    #[must_use]
    pub fn cpu0(&mut self) -> Cpu0W<MpumodrstSpec> {
        Cpu0W::new(self, 0)
    }
    #[doc = "Bit 1 - Resets Cortex-A9 CPU1 in MPU. It is reset to 1 on a cold or warm reset. This holds CPU1 in reset until software is ready to release CPU1 from reset by writing 0 to this field. On single-core devices, writes to this field are ignored.On dual-core devices, writes to this field trigger the same sequence as writes to the CPU0 field (except the sequence is performed on CPU1)."]
    #[inline(always)]
    #[must_use]
    pub fn cpu1(&mut self) -> Cpu1W<MpumodrstSpec> {
        Cpu1W::new(self, 1)
    }
    #[doc = "Bit 2 - Resets both per-CPU Watchdog Reset Status registers in MPU."]
    #[inline(always)]
    #[must_use]
    pub fn wds(&mut self) -> WdsW<MpumodrstSpec> {
        WdsW::new(self, 2)
    }
    #[doc = "Bit 3 - Resets SCU and peripherals. Peripherals consist of the interrupt controller, global timer, both per-CPU private timers, and both per-CPU watchdogs (except for the Watchdog Reset Status registers)."]
    #[inline(always)]
    #[must_use]
    pub fn scuper(&mut self) -> ScuperW<MpumodrstSpec> {
        ScuperW::new(self, 3)
    }
    #[doc = "Bit 4 - Resets L2 cache controller"]
    #[inline(always)]
    #[must_use]
    pub fn l2(&mut self) -> L2W<MpumodrstSpec> {
        L2W::new(self, 4)
    }
}
#[doc = "The MPUMODRST register is used by software to trigger module resets (individual module reset signals). Software explicitly asserts and de-asserts module reset signals by writing bits in the appropriate *MODRST register. It is up to software to ensure module reset signals are asserted for the appropriate length of time and are de-asserted in the correct order. It is also up to software to not assert a module reset signal that would prevent software from de-asserting the module reset signal. For example, software should not assert the module reset to the CPU executing the software. Software writes a bit to 1 to assert the module reset signal and to 0 to de-assert the module reset signal. All fields except CPU1 are only reset by a cold reset. The CPU1 field is reset by a cold reset. The CPU1 field is also reset by a warm reset if not masked by the corresponding MPUWARMMASK field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpumodrst::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpumodrst::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MpumodrstSpec;
impl crate::RegisterSpec for MpumodrstSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`mpumodrst::R`](R) reader structure"]
impl crate::Readable for MpumodrstSpec {}
#[doc = "`write(|w| ..)` method takes [`mpumodrst::W`](W) writer structure"]
impl crate::Writable for MpumodrstSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mpumodrst to value 0x02"]
impl crate::Resettable for MpumodrstSpec {
    const RESET_VALUE: u32 = 0x02;
}
