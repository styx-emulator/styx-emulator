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
#[doc = "Register `miscmodrst` reader"]
pub type R = crate::R<MiscmodrstSpec>;
#[doc = "Register `miscmodrst` writer"]
pub type W = crate::W<MiscmodrstSpec>;
#[doc = "Field `rom` reader - Resets Boot ROM"]
pub type RomR = crate::BitReader;
#[doc = "Field `rom` writer - Resets Boot ROM"]
pub type RomW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ocram` reader - Resets On-chip RAM"]
pub type OcramR = crate::BitReader;
#[doc = "Field `ocram` writer - Resets On-chip RAM"]
pub type OcramW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sysmgr` reader - Resets logic in System Manager that doesn't differentiate between cold and warm resets"]
pub type SysmgrR = crate::BitReader;
#[doc = "Field `sysmgr` writer - Resets logic in System Manager that doesn't differentiate between cold and warm resets"]
pub type SysmgrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sysmgrcold` reader - Resets logic in System Manager that is only reset by a cold reset (ignores warm reset)"]
pub type SysmgrcoldR = crate::BitReader;
#[doc = "Field `sysmgrcold` writer - Resets logic in System Manager that is only reset by a cold reset (ignores warm reset)"]
pub type SysmgrcoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgamgr` reader - Resets FPGA Manager"]
pub type FpgamgrR = crate::BitReader;
#[doc = "Field `fpgamgr` writer - Resets FPGA Manager"]
pub type FpgamgrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `acpidmap` reader - Resets ACP ID Mapper"]
pub type AcpidmapR = crate::BitReader;
#[doc = "Field `acpidmap` writer - Resets ACP ID Mapper"]
pub type AcpidmapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `s2f` reader - Resets logic in FPGA core that doesn't differentiate between HPS cold and warm resets (h2f_rst_n = 1)"]
pub type S2fR = crate::BitReader;
#[doc = "Field `s2f` writer - Resets logic in FPGA core that doesn't differentiate between HPS cold and warm resets (h2f_rst_n = 1)"]
pub type S2fW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `s2fcold` reader - Resets logic in FPGA core that is only reset by a cold reset (ignores warm reset) (h2f_cold_rst_n = 1)"]
pub type S2fcoldR = crate::BitReader;
#[doc = "Field `s2fcold` writer - Resets logic in FPGA core that is only reset by a cold reset (ignores warm reset) (h2f_cold_rst_n = 1)"]
pub type S2fcoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nrstpin` reader - Pulls nRST pin low"]
pub type NrstpinR = crate::BitReader;
#[doc = "Field `nrstpin` writer - Pulls nRST pin low"]
pub type NrstpinW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `timestampcold` reader - Resets debug timestamp to 0 (cold reset only)"]
pub type TimestampcoldR = crate::BitReader;
#[doc = "Field `timestampcold` writer - Resets debug timestamp to 0 (cold reset only)"]
pub type TimestampcoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `clkmgrcold` reader - Resets Clock Manager (cold reset only)"]
pub type ClkmgrcoldR = crate::BitReader;
#[doc = "Field `clkmgrcold` writer - Resets Clock Manager (cold reset only)"]
pub type ClkmgrcoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `scanmgr` reader - Resets Scan Manager"]
pub type ScanmgrR = crate::BitReader;
#[doc = "Field `scanmgr` writer - Resets Scan Manager"]
pub type ScanmgrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `frzctrlcold` reader - Resets Freeze Controller in System Manager (cold reset only)"]
pub type FrzctrlcoldR = crate::BitReader;
#[doc = "Field `frzctrlcold` writer - Resets Freeze Controller in System Manager (cold reset only)"]
pub type FrzctrlcoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sysdbg` reader - Resets logic that spans the system and debug domains."]
pub type SysdbgR = crate::BitReader;
#[doc = "Field `sysdbg` writer - Resets logic that spans the system and debug domains."]
pub type SysdbgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbg` reader - Resets logic located only in the debug domain."]
pub type DbgR = crate::BitReader;
#[doc = "Field `dbg` writer - Resets logic located only in the debug domain."]
pub type DbgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tapcold` reader - Resets portion of DAP JTAG TAP controller no reset by a debug probe reset (i.e. nTRST pin). Cold reset only."]
pub type TapcoldR = crate::BitReader;
#[doc = "Field `tapcold` writer - Resets portion of DAP JTAG TAP controller no reset by a debug probe reset (i.e. nTRST pin). Cold reset only."]
pub type TapcoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrcold` reader - Resets logic in SDRAM Controller Subsystem affected only by a cold reset."]
pub type SdrcoldR = crate::BitReader;
#[doc = "Field `sdrcold` writer - Resets logic in SDRAM Controller Subsystem affected only by a cold reset."]
pub type SdrcoldW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Resets Boot ROM"]
    #[inline(always)]
    pub fn rom(&self) -> RomR {
        RomR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Resets On-chip RAM"]
    #[inline(always)]
    pub fn ocram(&self) -> OcramR {
        OcramR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Resets logic in System Manager that doesn't differentiate between cold and warm resets"]
    #[inline(always)]
    pub fn sysmgr(&self) -> SysmgrR {
        SysmgrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Resets logic in System Manager that is only reset by a cold reset (ignores warm reset)"]
    #[inline(always)]
    pub fn sysmgrcold(&self) -> SysmgrcoldR {
        SysmgrcoldR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Resets FPGA Manager"]
    #[inline(always)]
    pub fn fpgamgr(&self) -> FpgamgrR {
        FpgamgrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Resets ACP ID Mapper"]
    #[inline(always)]
    pub fn acpidmap(&self) -> AcpidmapR {
        AcpidmapR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Resets logic in FPGA core that doesn't differentiate between HPS cold and warm resets (h2f_rst_n = 1)"]
    #[inline(always)]
    pub fn s2f(&self) -> S2fR {
        S2fR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Resets logic in FPGA core that is only reset by a cold reset (ignores warm reset) (h2f_cold_rst_n = 1)"]
    #[inline(always)]
    pub fn s2fcold(&self) -> S2fcoldR {
        S2fcoldR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Pulls nRST pin low"]
    #[inline(always)]
    pub fn nrstpin(&self) -> NrstpinR {
        NrstpinR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Resets debug timestamp to 0 (cold reset only)"]
    #[inline(always)]
    pub fn timestampcold(&self) -> TimestampcoldR {
        TimestampcoldR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Resets Clock Manager (cold reset only)"]
    #[inline(always)]
    pub fn clkmgrcold(&self) -> ClkmgrcoldR {
        ClkmgrcoldR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Resets Scan Manager"]
    #[inline(always)]
    pub fn scanmgr(&self) -> ScanmgrR {
        ScanmgrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Resets Freeze Controller in System Manager (cold reset only)"]
    #[inline(always)]
    pub fn frzctrlcold(&self) -> FrzctrlcoldR {
        FrzctrlcoldR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Resets logic that spans the system and debug domains."]
    #[inline(always)]
    pub fn sysdbg(&self) -> SysdbgR {
        SysdbgR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Resets logic located only in the debug domain."]
    #[inline(always)]
    pub fn dbg(&self) -> DbgR {
        DbgR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Resets portion of DAP JTAG TAP controller no reset by a debug probe reset (i.e. nTRST pin). Cold reset only."]
    #[inline(always)]
    pub fn tapcold(&self) -> TapcoldR {
        TapcoldR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Resets logic in SDRAM Controller Subsystem affected only by a cold reset."]
    #[inline(always)]
    pub fn sdrcold(&self) -> SdrcoldR {
        SdrcoldR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Resets Boot ROM"]
    #[inline(always)]
    #[must_use]
    pub fn rom(&mut self) -> RomW<MiscmodrstSpec> {
        RomW::new(self, 0)
    }
    #[doc = "Bit 1 - Resets On-chip RAM"]
    #[inline(always)]
    #[must_use]
    pub fn ocram(&mut self) -> OcramW<MiscmodrstSpec> {
        OcramW::new(self, 1)
    }
    #[doc = "Bit 2 - Resets logic in System Manager that doesn't differentiate between cold and warm resets"]
    #[inline(always)]
    #[must_use]
    pub fn sysmgr(&mut self) -> SysmgrW<MiscmodrstSpec> {
        SysmgrW::new(self, 2)
    }
    #[doc = "Bit 3 - Resets logic in System Manager that is only reset by a cold reset (ignores warm reset)"]
    #[inline(always)]
    #[must_use]
    pub fn sysmgrcold(&mut self) -> SysmgrcoldW<MiscmodrstSpec> {
        SysmgrcoldW::new(self, 3)
    }
    #[doc = "Bit 4 - Resets FPGA Manager"]
    #[inline(always)]
    #[must_use]
    pub fn fpgamgr(&mut self) -> FpgamgrW<MiscmodrstSpec> {
        FpgamgrW::new(self, 4)
    }
    #[doc = "Bit 5 - Resets ACP ID Mapper"]
    #[inline(always)]
    #[must_use]
    pub fn acpidmap(&mut self) -> AcpidmapW<MiscmodrstSpec> {
        AcpidmapW::new(self, 5)
    }
    #[doc = "Bit 6 - Resets logic in FPGA core that doesn't differentiate between HPS cold and warm resets (h2f_rst_n = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn s2f(&mut self) -> S2fW<MiscmodrstSpec> {
        S2fW::new(self, 6)
    }
    #[doc = "Bit 7 - Resets logic in FPGA core that is only reset by a cold reset (ignores warm reset) (h2f_cold_rst_n = 1)"]
    #[inline(always)]
    #[must_use]
    pub fn s2fcold(&mut self) -> S2fcoldW<MiscmodrstSpec> {
        S2fcoldW::new(self, 7)
    }
    #[doc = "Bit 8 - Pulls nRST pin low"]
    #[inline(always)]
    #[must_use]
    pub fn nrstpin(&mut self) -> NrstpinW<MiscmodrstSpec> {
        NrstpinW::new(self, 8)
    }
    #[doc = "Bit 9 - Resets debug timestamp to 0 (cold reset only)"]
    #[inline(always)]
    #[must_use]
    pub fn timestampcold(&mut self) -> TimestampcoldW<MiscmodrstSpec> {
        TimestampcoldW::new(self, 9)
    }
    #[doc = "Bit 10 - Resets Clock Manager (cold reset only)"]
    #[inline(always)]
    #[must_use]
    pub fn clkmgrcold(&mut self) -> ClkmgrcoldW<MiscmodrstSpec> {
        ClkmgrcoldW::new(self, 10)
    }
    #[doc = "Bit 11 - Resets Scan Manager"]
    #[inline(always)]
    #[must_use]
    pub fn scanmgr(&mut self) -> ScanmgrW<MiscmodrstSpec> {
        ScanmgrW::new(self, 11)
    }
    #[doc = "Bit 12 - Resets Freeze Controller in System Manager (cold reset only)"]
    #[inline(always)]
    #[must_use]
    pub fn frzctrlcold(&mut self) -> FrzctrlcoldW<MiscmodrstSpec> {
        FrzctrlcoldW::new(self, 12)
    }
    #[doc = "Bit 13 - Resets logic that spans the system and debug domains."]
    #[inline(always)]
    #[must_use]
    pub fn sysdbg(&mut self) -> SysdbgW<MiscmodrstSpec> {
        SysdbgW::new(self, 13)
    }
    #[doc = "Bit 14 - Resets logic located only in the debug domain."]
    #[inline(always)]
    #[must_use]
    pub fn dbg(&mut self) -> DbgW<MiscmodrstSpec> {
        DbgW::new(self, 14)
    }
    #[doc = "Bit 15 - Resets portion of DAP JTAG TAP controller no reset by a debug probe reset (i.e. nTRST pin). Cold reset only."]
    #[inline(always)]
    #[must_use]
    pub fn tapcold(&mut self) -> TapcoldW<MiscmodrstSpec> {
        TapcoldW::new(self, 15)
    }
    #[doc = "Bit 16 - Resets logic in SDRAM Controller Subsystem affected only by a cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn sdrcold(&mut self) -> SdrcoldW<MiscmodrstSpec> {
        SdrcoldW::new(self, 16)
    }
}
#[doc = "The MISCMODRST register is used by software to trigger module resets (individual module reset signals). Software explicitly asserts and de-asserts module reset signals by writing bits in the appropriate *MODRST register. It is up to software to ensure module reset signals are asserted for the appropriate length of time and are de-asserted in the correct order. It is also up to software to not assert a module reset signal that would prevent software from de-asserting the module reset signal. For example, software should not assert the module reset to the CPU executing the software. Software writes a bit to 1 to assert the module reset signal and to 0 to de-assert the module reset signal. All fields are only reset by a cold reset\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`miscmodrst::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`miscmodrst::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MiscmodrstSpec;
impl crate::RegisterSpec for MiscmodrstSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`miscmodrst::R`](R) reader structure"]
impl crate::Readable for MiscmodrstSpec {}
#[doc = "`write(|w| ..)` method takes [`miscmodrst::W`](W) writer structure"]
impl crate::Writable for MiscmodrstSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets miscmodrst to value 0"]
impl crate::Resettable for MiscmodrstSpec {
    const RESET_VALUE: u32 = 0;
}
