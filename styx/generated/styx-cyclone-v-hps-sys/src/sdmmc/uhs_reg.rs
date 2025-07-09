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
#[doc = "Register `uhs_reg` reader"]
pub type R = crate::R<UhsRegSpec>;
#[doc = "Register `uhs_reg` writer"]
pub type W = crate::W<UhsRegSpec>;
#[doc = "Determines the voltage fed to the buffers by an external voltage regulator. These bits function as the output of the host controller and are fed to an external voltage regulator. The voltage regulator must switch the voltage of the buffers of a particular card to either 3.3V or 1.8V, depending on the value programmed in the register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoltReg {
    #[doc = "0: `0`"]
    Buf33v = 0,
    #[doc = "1: `1`"]
    Buf18v = 1,
}
impl From<VoltReg> for bool {
    #[inline(always)]
    fn from(variant: VoltReg) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `volt_reg` reader - Determines the voltage fed to the buffers by an external voltage regulator. These bits function as the output of the host controller and are fed to an external voltage regulator. The voltage regulator must switch the voltage of the buffers of a particular card to either 3.3V or 1.8V, depending on the value programmed in the register."]
pub type VoltRegR = crate::BitReader<VoltReg>;
impl VoltRegR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> VoltReg {
        match self.bits {
            false => VoltReg::Buf33v,
            true => VoltReg::Buf18v,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_buf33v(&self) -> bool {
        *self == VoltReg::Buf33v
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_buf18v(&self) -> bool {
        *self == VoltReg::Buf18v
    }
}
#[doc = "Field `volt_reg` writer - Determines the voltage fed to the buffers by an external voltage regulator. These bits function as the output of the host controller and are fed to an external voltage regulator. The voltage regulator must switch the voltage of the buffers of a particular card to either 3.3V or 1.8V, depending on the value programmed in the register."]
pub type VoltRegW<'a, REG> = crate::BitWriter<'a, REG, VoltReg>;
impl<'a, REG> VoltRegW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn buf33v(self) -> &'a mut crate::W<REG> {
        self.variant(VoltReg::Buf33v)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn buf18v(self) -> &'a mut crate::W<REG> {
        self.variant(VoltReg::Buf18v)
    }
}
#[doc = "Determines the voltage fed to the buffers by an external voltage regulator.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DdrReg {
    #[doc = "0: `0`"]
    Nonddr = 0,
    #[doc = "1: `1`"]
    Ddr = 1,
}
impl From<DdrReg> for bool {
    #[inline(always)]
    fn from(variant: DdrReg) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ddr_reg` reader - Determines the voltage fed to the buffers by an external voltage regulator."]
pub type DdrRegR = crate::BitReader<DdrReg>;
impl DdrRegR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DdrReg {
        match self.bits {
            false => DdrReg::Nonddr,
            true => DdrReg::Ddr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nonddr(&self) -> bool {
        *self == DdrReg::Nonddr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ddr(&self) -> bool {
        *self == DdrReg::Ddr
    }
}
#[doc = "Field `ddr_reg` writer - Determines the voltage fed to the buffers by an external voltage regulator."]
pub type DdrRegW<'a, REG> = crate::BitWriter<'a, REG, DdrReg>;
impl<'a, REG> DdrRegW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nonddr(self) -> &'a mut crate::W<REG> {
        self.variant(DdrReg::Nonddr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ddr(self) -> &'a mut crate::W<REG> {
        self.variant(DdrReg::Ddr)
    }
}
impl R {
    #[doc = "Bit 0 - Determines the voltage fed to the buffers by an external voltage regulator. These bits function as the output of the host controller and are fed to an external voltage regulator. The voltage regulator must switch the voltage of the buffers of a particular card to either 3.3V or 1.8V, depending on the value programmed in the register."]
    #[inline(always)]
    pub fn volt_reg(&self) -> VoltRegR {
        VoltRegR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 16 - Determines the voltage fed to the buffers by an external voltage regulator."]
    #[inline(always)]
    pub fn ddr_reg(&self) -> DdrRegR {
        DdrRegR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Determines the voltage fed to the buffers by an external voltage regulator. These bits function as the output of the host controller and are fed to an external voltage regulator. The voltage regulator must switch the voltage of the buffers of a particular card to either 3.3V or 1.8V, depending on the value programmed in the register."]
    #[inline(always)]
    #[must_use]
    pub fn volt_reg(&mut self) -> VoltRegW<UhsRegSpec> {
        VoltRegW::new(self, 0)
    }
    #[doc = "Bit 16 - Determines the voltage fed to the buffers by an external voltage regulator."]
    #[inline(always)]
    #[must_use]
    pub fn ddr_reg(&mut self) -> DdrRegW<UhsRegSpec> {
        DdrRegW::new(self, 16)
    }
}
#[doc = "UHS-1 Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`uhs_reg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`uhs_reg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct UhsRegSpec;
impl crate::RegisterSpec for UhsRegSpec {
    type Ux = u32;
    const OFFSET: u64 = 116u64;
}
#[doc = "`read()` method returns [`uhs_reg::R`](R) reader structure"]
impl crate::Readable for UhsRegSpec {}
#[doc = "`write(|w| ..)` method takes [`uhs_reg::W`](W) writer structure"]
impl crate::Writable for UhsRegSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets uhs_reg to value 0"]
impl crate::Resettable for UhsRegSpec {
    const RESET_VALUE: u32 = 0;
}
