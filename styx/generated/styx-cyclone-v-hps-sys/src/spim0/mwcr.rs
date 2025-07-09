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
#[doc = "Register `mwcr` reader"]
pub type R = crate::R<MwcrSpec>;
#[doc = "Register `mwcr` writer"]
pub type W = crate::W<MwcrSpec>;
#[doc = "Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mwmod {
    #[doc = "0: `0`"]
    Nonseq = 0,
    #[doc = "1: `1`"]
    Seq = 1,
}
impl From<Mwmod> for bool {
    #[inline(always)]
    fn from(variant: Mwmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mwmod` reader - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
pub type MwmodR = crate::BitReader<Mwmod>;
impl MwmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mwmod {
        match self.bits {
            false => Mwmod::Nonseq,
            true => Mwmod::Seq,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nonseq(&self) -> bool {
        *self == Mwmod::Nonseq
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_seq(&self) -> bool {
        *self == Mwmod::Seq
    }
}
#[doc = "Field `mwmod` writer - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
pub type MwmodW<'a, REG> = crate::BitWriter<'a, REG, Mwmod>;
impl<'a, REG> MwmodW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nonseq(self) -> &'a mut crate::W<REG> {
        self.variant(Mwmod::Nonseq)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn seq(self) -> &'a mut crate::W<REG> {
        self.variant(Mwmod::Seq)
    }
}
#[doc = "Defines the direction of the data word when the Microwire serial protocol is used.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mdd {
    #[doc = "0: `0`"]
    Rxmode = 0,
    #[doc = "1: `1`"]
    Txmode = 1,
}
impl From<Mdd> for bool {
    #[inline(always)]
    fn from(variant: Mdd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mdd` reader - Defines the direction of the data word when the Microwire serial protocol is used."]
pub type MddR = crate::BitReader<Mdd>;
impl MddR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mdd {
        match self.bits {
            false => Mdd::Rxmode,
            true => Mdd::Txmode,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rxmode(&self) -> bool {
        *self == Mdd::Rxmode
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_txmode(&self) -> bool {
        *self == Mdd::Txmode
    }
}
#[doc = "Field `mdd` writer - Defines the direction of the data word when the Microwire serial protocol is used."]
pub type MddW<'a, REG> = crate::BitWriter<'a, REG, Mdd>;
impl<'a, REG> MddW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rxmode(self) -> &'a mut crate::W<REG> {
        self.variant(Mdd::Rxmode)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn txmode(self) -> &'a mut crate::W<REG> {
        self.variant(Mdd::Txmode)
    }
}
#[doc = "Used to enable and disable the busy/ready handshaking interface for the Microwire protocol. When enabled, the SPI Master checks for a ready status from the target slave, after the transfer of the last data/control bit, before clearing the BUSY status in the SR register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mhs {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Mhs> for bool {
    #[inline(always)]
    fn from(variant: Mhs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mhs` reader - Used to enable and disable the busy/ready handshaking interface for the Microwire protocol. When enabled, the SPI Master checks for a ready status from the target slave, after the transfer of the last data/control bit, before clearing the BUSY status in the SR register."]
pub type MhsR = crate::BitReader<Mhs>;
impl MhsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mhs {
        match self.bits {
            false => Mhs::Disabled,
            true => Mhs::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Mhs::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Mhs::Enabled
    }
}
#[doc = "Field `mhs` writer - Used to enable and disable the busy/ready handshaking interface for the Microwire protocol. When enabled, the SPI Master checks for a ready status from the target slave, after the transfer of the last data/control bit, before clearing the BUSY status in the SR register."]
pub type MhsW<'a, REG> = crate::BitWriter<'a, REG, Mhs>;
impl<'a, REG> MhsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Mhs::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Mhs::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
    #[inline(always)]
    pub fn mwmod(&self) -> MwmodR {
        MwmodR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Defines the direction of the data word when the Microwire serial protocol is used."]
    #[inline(always)]
    pub fn mdd(&self) -> MddR {
        MddR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Used to enable and disable the busy/ready handshaking interface for the Microwire protocol. When enabled, the SPI Master checks for a ready status from the target slave, after the transfer of the last data/control bit, before clearing the BUSY status in the SR register."]
    #[inline(always)]
    pub fn mhs(&self) -> MhsR {
        MhsR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
    #[inline(always)]
    #[must_use]
    pub fn mwmod(&mut self) -> MwmodW<MwcrSpec> {
        MwmodW::new(self, 0)
    }
    #[doc = "Bit 1 - Defines the direction of the data word when the Microwire serial protocol is used."]
    #[inline(always)]
    #[must_use]
    pub fn mdd(&mut self) -> MddW<MwcrSpec> {
        MddW::new(self, 1)
    }
    #[doc = "Bit 2 - Used to enable and disable the busy/ready handshaking interface for the Microwire protocol. When enabled, the SPI Master checks for a ready status from the target slave, after the transfer of the last data/control bit, before clearing the BUSY status in the SR register."]
    #[inline(always)]
    #[must_use]
    pub fn mhs(&mut self) -> MhsW<MwcrSpec> {
        MhsW::new(self, 2)
    }
}
#[doc = "This register controls the direction of the data word for the half-duplex Microwire serial protocol. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mwcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mwcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MwcrSpec;
impl crate::RegisterSpec for MwcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`mwcr::R`](R) reader structure"]
impl crate::Readable for MwcrSpec {}
#[doc = "`write(|w| ..)` method takes [`mwcr::W`](W) writer structure"]
impl crate::Writable for MwcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mwcr to value 0"]
impl crate::Resettable for MwcrSpec {
    const RESET_VALUE: u32 = 0;
}
