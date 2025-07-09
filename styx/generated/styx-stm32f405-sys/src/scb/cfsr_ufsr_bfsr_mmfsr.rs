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
#[doc = "Register `CFSR_UFSR_BFSR_MMFSR` reader"]
pub type R = crate::R<CfsrUfsrBfsrMmfsrSpec>;
#[doc = "Register `CFSR_UFSR_BFSR_MMFSR` writer"]
pub type W = crate::W<CfsrUfsrBfsrMmfsrSpec>;
#[doc = "Field `IACCVIOL` reader - Instruction access violation flag"]
pub type IaccviolR = crate::BitReader;
#[doc = "Field `IACCVIOL` writer - Instruction access violation flag"]
pub type IaccviolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUNSTKERR` reader - Memory manager fault on unstacking for a return from exception"]
pub type MunstkerrR = crate::BitReader;
#[doc = "Field `MUNSTKERR` writer - Memory manager fault on unstacking for a return from exception"]
pub type MunstkerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MSTKERR` reader - Memory manager fault on stacking for exception entry."]
pub type MstkerrR = crate::BitReader;
#[doc = "Field `MSTKERR` writer - Memory manager fault on stacking for exception entry."]
pub type MstkerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MLSPERR` reader - MLSPERR"]
pub type MlsperrR = crate::BitReader;
#[doc = "Field `MLSPERR` writer - MLSPERR"]
pub type MlsperrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMARVALID` reader - Memory Management Fault Address Register (MMAR) valid flag"]
pub type MmarvalidR = crate::BitReader;
#[doc = "Field `MMARVALID` writer - Memory Management Fault Address Register (MMAR) valid flag"]
pub type MmarvalidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IBUSERR` reader - Instruction bus error"]
pub type IbuserrR = crate::BitReader;
#[doc = "Field `IBUSERR` writer - Instruction bus error"]
pub type IbuserrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRECISERR` reader - Precise data bus error"]
pub type PreciserrR = crate::BitReader;
#[doc = "Field `PRECISERR` writer - Precise data bus error"]
pub type PreciserrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IMPRECISERR` reader - Imprecise data bus error"]
pub type ImpreciserrR = crate::BitReader;
#[doc = "Field `IMPRECISERR` writer - Imprecise data bus error"]
pub type ImpreciserrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UNSTKERR` reader - Bus fault on unstacking for a return from exception"]
pub type UnstkerrR = crate::BitReader;
#[doc = "Field `UNSTKERR` writer - Bus fault on unstacking for a return from exception"]
pub type UnstkerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STKERR` reader - Bus fault on stacking for exception entry"]
pub type StkerrR = crate::BitReader;
#[doc = "Field `STKERR` writer - Bus fault on stacking for exception entry"]
pub type StkerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSPERR` reader - Bus fault on floating-point lazy state preservation"]
pub type LsperrR = crate::BitReader;
#[doc = "Field `LSPERR` writer - Bus fault on floating-point lazy state preservation"]
pub type LsperrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BFARVALID` reader - Bus Fault Address Register (BFAR) valid flag"]
pub type BfarvalidR = crate::BitReader;
#[doc = "Field `BFARVALID` writer - Bus Fault Address Register (BFAR) valid flag"]
pub type BfarvalidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UNDEFINSTR` reader - Undefined instruction usage fault"]
pub type UndefinstrR = crate::BitReader;
#[doc = "Field `UNDEFINSTR` writer - Undefined instruction usage fault"]
pub type UndefinstrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `INVSTATE` reader - Invalid state usage fault"]
pub type InvstateR = crate::BitReader;
#[doc = "Field `INVSTATE` writer - Invalid state usage fault"]
pub type InvstateW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `INVPC` reader - Invalid PC load usage fault"]
pub type InvpcR = crate::BitReader;
#[doc = "Field `INVPC` writer - Invalid PC load usage fault"]
pub type InvpcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NOCP` reader - No coprocessor usage fault."]
pub type NocpR = crate::BitReader;
#[doc = "Field `NOCP` writer - No coprocessor usage fault."]
pub type NocpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UNALIGNED` reader - Unaligned access usage fault"]
pub type UnalignedR = crate::BitReader;
#[doc = "Field `UNALIGNED` writer - Unaligned access usage fault"]
pub type UnalignedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DIVBYZERO` reader - Divide by zero usage fault"]
pub type DivbyzeroR = crate::BitReader;
#[doc = "Field `DIVBYZERO` writer - Divide by zero usage fault"]
pub type DivbyzeroW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - Instruction access violation flag"]
    #[inline(always)]
    pub fn iaccviol(&self) -> IaccviolR {
        IaccviolR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Memory manager fault on unstacking for a return from exception"]
    #[inline(always)]
    pub fn munstkerr(&self) -> MunstkerrR {
        MunstkerrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Memory manager fault on stacking for exception entry."]
    #[inline(always)]
    pub fn mstkerr(&self) -> MstkerrR {
        MstkerrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - MLSPERR"]
    #[inline(always)]
    pub fn mlsperr(&self) -> MlsperrR {
        MlsperrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 7 - Memory Management Fault Address Register (MMAR) valid flag"]
    #[inline(always)]
    pub fn mmarvalid(&self) -> MmarvalidR {
        MmarvalidR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Instruction bus error"]
    #[inline(always)]
    pub fn ibuserr(&self) -> IbuserrR {
        IbuserrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Precise data bus error"]
    #[inline(always)]
    pub fn preciserr(&self) -> PreciserrR {
        PreciserrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Imprecise data bus error"]
    #[inline(always)]
    pub fn impreciserr(&self) -> ImpreciserrR {
        ImpreciserrR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Bus fault on unstacking for a return from exception"]
    #[inline(always)]
    pub fn unstkerr(&self) -> UnstkerrR {
        UnstkerrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Bus fault on stacking for exception entry"]
    #[inline(always)]
    pub fn stkerr(&self) -> StkerrR {
        StkerrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Bus fault on floating-point lazy state preservation"]
    #[inline(always)]
    pub fn lsperr(&self) -> LsperrR {
        LsperrR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 15 - Bus Fault Address Register (BFAR) valid flag"]
    #[inline(always)]
    pub fn bfarvalid(&self) -> BfarvalidR {
        BfarvalidR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Undefined instruction usage fault"]
    #[inline(always)]
    pub fn undefinstr(&self) -> UndefinstrR {
        UndefinstrR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Invalid state usage fault"]
    #[inline(always)]
    pub fn invstate(&self) -> InvstateR {
        InvstateR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Invalid PC load usage fault"]
    #[inline(always)]
    pub fn invpc(&self) -> InvpcR {
        InvpcR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - No coprocessor usage fault."]
    #[inline(always)]
    pub fn nocp(&self) -> NocpR {
        NocpR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 24 - Unaligned access usage fault"]
    #[inline(always)]
    pub fn unaligned(&self) -> UnalignedR {
        UnalignedR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Divide by zero usage fault"]
    #[inline(always)]
    pub fn divbyzero(&self) -> DivbyzeroR {
        DivbyzeroR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - Instruction access violation flag"]
    #[inline(always)]
    #[must_use]
    pub fn iaccviol(&mut self) -> IaccviolW<CfsrUfsrBfsrMmfsrSpec> {
        IaccviolW::new(self, 1)
    }
    #[doc = "Bit 3 - Memory manager fault on unstacking for a return from exception"]
    #[inline(always)]
    #[must_use]
    pub fn munstkerr(&mut self) -> MunstkerrW<CfsrUfsrBfsrMmfsrSpec> {
        MunstkerrW::new(self, 3)
    }
    #[doc = "Bit 4 - Memory manager fault on stacking for exception entry."]
    #[inline(always)]
    #[must_use]
    pub fn mstkerr(&mut self) -> MstkerrW<CfsrUfsrBfsrMmfsrSpec> {
        MstkerrW::new(self, 4)
    }
    #[doc = "Bit 5 - MLSPERR"]
    #[inline(always)]
    #[must_use]
    pub fn mlsperr(&mut self) -> MlsperrW<CfsrUfsrBfsrMmfsrSpec> {
        MlsperrW::new(self, 5)
    }
    #[doc = "Bit 7 - Memory Management Fault Address Register (MMAR) valid flag"]
    #[inline(always)]
    #[must_use]
    pub fn mmarvalid(&mut self) -> MmarvalidW<CfsrUfsrBfsrMmfsrSpec> {
        MmarvalidW::new(self, 7)
    }
    #[doc = "Bit 8 - Instruction bus error"]
    #[inline(always)]
    #[must_use]
    pub fn ibuserr(&mut self) -> IbuserrW<CfsrUfsrBfsrMmfsrSpec> {
        IbuserrW::new(self, 8)
    }
    #[doc = "Bit 9 - Precise data bus error"]
    #[inline(always)]
    #[must_use]
    pub fn preciserr(&mut self) -> PreciserrW<CfsrUfsrBfsrMmfsrSpec> {
        PreciserrW::new(self, 9)
    }
    #[doc = "Bit 10 - Imprecise data bus error"]
    #[inline(always)]
    #[must_use]
    pub fn impreciserr(&mut self) -> ImpreciserrW<CfsrUfsrBfsrMmfsrSpec> {
        ImpreciserrW::new(self, 10)
    }
    #[doc = "Bit 11 - Bus fault on unstacking for a return from exception"]
    #[inline(always)]
    #[must_use]
    pub fn unstkerr(&mut self) -> UnstkerrW<CfsrUfsrBfsrMmfsrSpec> {
        UnstkerrW::new(self, 11)
    }
    #[doc = "Bit 12 - Bus fault on stacking for exception entry"]
    #[inline(always)]
    #[must_use]
    pub fn stkerr(&mut self) -> StkerrW<CfsrUfsrBfsrMmfsrSpec> {
        StkerrW::new(self, 12)
    }
    #[doc = "Bit 13 - Bus fault on floating-point lazy state preservation"]
    #[inline(always)]
    #[must_use]
    pub fn lsperr(&mut self) -> LsperrW<CfsrUfsrBfsrMmfsrSpec> {
        LsperrW::new(self, 13)
    }
    #[doc = "Bit 15 - Bus Fault Address Register (BFAR) valid flag"]
    #[inline(always)]
    #[must_use]
    pub fn bfarvalid(&mut self) -> BfarvalidW<CfsrUfsrBfsrMmfsrSpec> {
        BfarvalidW::new(self, 15)
    }
    #[doc = "Bit 16 - Undefined instruction usage fault"]
    #[inline(always)]
    #[must_use]
    pub fn undefinstr(&mut self) -> UndefinstrW<CfsrUfsrBfsrMmfsrSpec> {
        UndefinstrW::new(self, 16)
    }
    #[doc = "Bit 17 - Invalid state usage fault"]
    #[inline(always)]
    #[must_use]
    pub fn invstate(&mut self) -> InvstateW<CfsrUfsrBfsrMmfsrSpec> {
        InvstateW::new(self, 17)
    }
    #[doc = "Bit 18 - Invalid PC load usage fault"]
    #[inline(always)]
    #[must_use]
    pub fn invpc(&mut self) -> InvpcW<CfsrUfsrBfsrMmfsrSpec> {
        InvpcW::new(self, 18)
    }
    #[doc = "Bit 19 - No coprocessor usage fault."]
    #[inline(always)]
    #[must_use]
    pub fn nocp(&mut self) -> NocpW<CfsrUfsrBfsrMmfsrSpec> {
        NocpW::new(self, 19)
    }
    #[doc = "Bit 24 - Unaligned access usage fault"]
    #[inline(always)]
    #[must_use]
    pub fn unaligned(&mut self) -> UnalignedW<CfsrUfsrBfsrMmfsrSpec> {
        UnalignedW::new(self, 24)
    }
    #[doc = "Bit 25 - Divide by zero usage fault"]
    #[inline(always)]
    #[must_use]
    pub fn divbyzero(&mut self) -> DivbyzeroW<CfsrUfsrBfsrMmfsrSpec> {
        DivbyzeroW::new(self, 25)
    }
}
#[doc = "Configurable fault status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfsr_ufsr_bfsr_mmfsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfsr_ufsr_bfsr_mmfsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CfsrUfsrBfsrMmfsrSpec;
impl crate::RegisterSpec for CfsrUfsrBfsrMmfsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`cfsr_ufsr_bfsr_mmfsr::R`](R) reader structure"]
impl crate::Readable for CfsrUfsrBfsrMmfsrSpec {}
#[doc = "`write(|w| ..)` method takes [`cfsr_ufsr_bfsr_mmfsr::W`](W) writer structure"]
impl crate::Writable for CfsrUfsrBfsrMmfsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CFSR_UFSR_BFSR_MMFSR to value 0"]
impl crate::Resettable for CfsrUfsrBfsrMmfsrSpec {
    const RESET_VALUE: u32 = 0;
}
