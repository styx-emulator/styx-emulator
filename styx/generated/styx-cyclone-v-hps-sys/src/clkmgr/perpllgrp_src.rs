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
#[doc = "Register `perpllgrp_src` reader"]
pub type R = crate::R<PerpllgrpSrcSpec>;
#[doc = "Register `perpllgrp_src` writer"]
pub type W = crate::W<PerpllgrpSrcSpec>;
#[doc = "Selects the source clock for the SDMMC. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Sdmmc {
    #[doc = "0: `0`"]
    F2sPeriphRefClk = 0,
    #[doc = "1: `1`"]
    MainNandClk = 1,
    #[doc = "2: `10`"]
    PeriphNandClk = 2,
}
impl From<Sdmmc> for u8 {
    #[inline(always)]
    fn from(variant: Sdmmc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Sdmmc {
    type Ux = u8;
}
#[doc = "Field `sdmmc` reader - Selects the source clock for the SDMMC. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
pub type SdmmcR = crate::FieldReader<Sdmmc>;
impl SdmmcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Sdmmc> {
        match self.bits {
            0 => Some(Sdmmc::F2sPeriphRefClk),
            1 => Some(Sdmmc::MainNandClk),
            2 => Some(Sdmmc::PeriphNandClk),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_f2s_periph_ref_clk(&self) -> bool {
        *self == Sdmmc::F2sPeriphRefClk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_main_nand_clk(&self) -> bool {
        *self == Sdmmc::MainNandClk
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_periph_nand_clk(&self) -> bool {
        *self == Sdmmc::PeriphNandClk
    }
}
#[doc = "Field `sdmmc` writer - Selects the source clock for the SDMMC. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
pub type SdmmcW<'a, REG> = crate::FieldWriter<'a, REG, 2, Sdmmc>;
impl<'a, REG> SdmmcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn f2s_periph_ref_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmmc::F2sPeriphRefClk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn main_nand_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmmc::MainNandClk)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn periph_nand_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmmc::PeriphNandClk)
    }
}
#[doc = "Selects the source clock for the NAND. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Nand {
    #[doc = "0: `0`"]
    F2sPeriphRefClk = 0,
    #[doc = "1: `1`"]
    MainNandClk = 1,
    #[doc = "2: `10`"]
    PeriphNandClk = 2,
}
impl From<Nand> for u8 {
    #[inline(always)]
    fn from(variant: Nand) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Nand {
    type Ux = u8;
}
#[doc = "Field `nand` reader - Selects the source clock for the NAND. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
pub type NandR = crate::FieldReader<Nand>;
impl NandR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Nand> {
        match self.bits {
            0 => Some(Nand::F2sPeriphRefClk),
            1 => Some(Nand::MainNandClk),
            2 => Some(Nand::PeriphNandClk),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_f2s_periph_ref_clk(&self) -> bool {
        *self == Nand::F2sPeriphRefClk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_main_nand_clk(&self) -> bool {
        *self == Nand::MainNandClk
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_periph_nand_clk(&self) -> bool {
        *self == Nand::PeriphNandClk
    }
}
#[doc = "Field `nand` writer - Selects the source clock for the NAND. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
pub type NandW<'a, REG> = crate::FieldWriter<'a, REG, 2, Nand>;
impl<'a, REG> NandW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn f2s_periph_ref_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Nand::F2sPeriphRefClk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn main_nand_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Nand::MainNandClk)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn periph_nand_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Nand::PeriphNandClk)
    }
}
#[doc = "Selects the source clock for the QSPI. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Qspi {
    #[doc = "0: `0`"]
    F2sPeriphRefClk = 0,
    #[doc = "1: `1`"]
    MainQspiClk = 1,
    #[doc = "2: `10`"]
    PeriphQspiClk = 2,
}
impl From<Qspi> for u8 {
    #[inline(always)]
    fn from(variant: Qspi) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Qspi {
    type Ux = u8;
}
#[doc = "Field `qspi` reader - Selects the source clock for the QSPI. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
pub type QspiR = crate::FieldReader<Qspi>;
impl QspiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Qspi> {
        match self.bits {
            0 => Some(Qspi::F2sPeriphRefClk),
            1 => Some(Qspi::MainQspiClk),
            2 => Some(Qspi::PeriphQspiClk),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_f2s_periph_ref_clk(&self) -> bool {
        *self == Qspi::F2sPeriphRefClk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_main_qspi_clk(&self) -> bool {
        *self == Qspi::MainQspiClk
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_periph_qspi_clk(&self) -> bool {
        *self == Qspi::PeriphQspiClk
    }
}
#[doc = "Field `qspi` writer - Selects the source clock for the QSPI. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
pub type QspiW<'a, REG> = crate::FieldWriter<'a, REG, 2, Qspi>;
impl<'a, REG> QspiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn f2s_periph_ref_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Qspi::F2sPeriphRefClk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn main_qspi_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Qspi::MainQspiClk)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn periph_qspi_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Qspi::PeriphQspiClk)
    }
}
impl R {
    #[doc = "Bits 0:1 - Selects the source clock for the SDMMC. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
    #[inline(always)]
    pub fn sdmmc(&self) -> SdmmcR {
        SdmmcR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Selects the source clock for the NAND. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
    #[inline(always)]
    pub fn nand(&self) -> NandR {
        NandR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - Selects the source clock for the QSPI. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
    #[inline(always)]
    pub fn qspi(&self) -> QspiR {
        QspiR::new(((self.bits >> 4) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Selects the source clock for the SDMMC. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
    #[inline(always)]
    #[must_use]
    pub fn sdmmc(&mut self) -> SdmmcW<PerpllgrpSrcSpec> {
        SdmmcW::new(self, 0)
    }
    #[doc = "Bits 2:3 - Selects the source clock for the NAND. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
    #[inline(always)]
    #[must_use]
    pub fn nand(&mut self) -> NandW<PerpllgrpSrcSpec> {
        NandW::new(self, 2)
    }
    #[doc = "Bits 4:5 - Selects the source clock for the QSPI. Qsys and user documenation refer to f2s_periph_ref_clk as f2h_periph_ref_clk."]
    #[inline(always)]
    #[must_use]
    pub fn qspi(&mut self) -> QspiW<PerpllgrpSrcSpec> {
        QspiW::new(self, 4)
    }
}
#[doc = "Contains fields that select the source clocks for the flash controllers. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_src::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_src::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpSrcSpec;
impl crate::RegisterSpec for PerpllgrpSrcSpec {
    type Ux = u32;
    const OFFSET: u64 = 172u64;
}
#[doc = "`read()` method returns [`perpllgrp_src::R`](R) reader structure"]
impl crate::Readable for PerpllgrpSrcSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_src::W`](W) writer structure"]
impl crate::Writable for PerpllgrpSrcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_src to value 0x15"]
impl crate::Resettable for PerpllgrpSrcSpec {
    const RESET_VALUE: u32 = 0x15;
}
