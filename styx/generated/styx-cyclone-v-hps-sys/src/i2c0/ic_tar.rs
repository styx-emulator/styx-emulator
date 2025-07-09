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
#[doc = "Register `ic_tar` reader"]
pub type R = crate::R<IcTarSpec>;
#[doc = "Register `ic_tar` writer"]
pub type W = crate::W<IcTarSpec>;
#[doc = "Field `ic_tar` reader - This is the target address for any master transaction. When transmitting a General Call, these bits are ignored. To generate a START BYTE, the CPU needs to write only once into these bits. If the ic_tar and ic_sar are the same, loopback exists but the FIFOs are shared between master and slave, so full loopback is not feasible. Only one direction loopback mode is supported (simplex), not duplex. A master cannot transmit to itself; it can transmit to only a slave."]
pub type IcTarR = crate::FieldReader<u16>;
#[doc = "Field `ic_tar` writer - This is the target address for any master transaction. When transmitting a General Call, these bits are ignored. To generate a START BYTE, the CPU needs to write only once into these bits. If the ic_tar and ic_sar are the same, loopback exists but the FIFOs are shared between master and slave, so full loopback is not feasible. Only one direction loopback mode is supported (simplex), not duplex. A master cannot transmit to itself; it can transmit to only a slave."]
pub type IcTarW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "If bit 11 (SPECIAL) of this Register is set to 1, then this bit indicates whether a General Call or START byte command is to be performed by the I2C or General Call Address after issuing a General Call, only writes may be performed. Attempting to issue a read command results in setting bit 6 (TX_ABRT) of the Raw Interrupt_Status register. The I2C remains in General Call mode until the special bit value (bit 11) is cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcOrStart {
    #[doc = "0: `0`"]
    Gencall = 0,
    #[doc = "1: `1`"]
    Startbyte = 1,
}
impl From<GcOrStart> for bool {
    #[inline(always)]
    fn from(variant: GcOrStart) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gc_or_start` reader - If bit 11 (SPECIAL) of this Register is set to 1, then this bit indicates whether a General Call or START byte command is to be performed by the I2C or General Call Address after issuing a General Call, only writes may be performed. Attempting to issue a read command results in setting bit 6 (TX_ABRT) of the Raw Interrupt_Status register. The I2C remains in General Call mode until the special bit value (bit 11) is cleared."]
pub type GcOrStartR = crate::BitReader<GcOrStart>;
impl GcOrStartR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> GcOrStart {
        match self.bits {
            false => GcOrStart::Gencall,
            true => GcOrStart::Startbyte,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gencall(&self) -> bool {
        *self == GcOrStart::Gencall
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_startbyte(&self) -> bool {
        *self == GcOrStart::Startbyte
    }
}
#[doc = "Field `gc_or_start` writer - If bit 11 (SPECIAL) of this Register is set to 1, then this bit indicates whether a General Call or START byte command is to be performed by the I2C or General Call Address after issuing a General Call, only writes may be performed. Attempting to issue a read command results in setting bit 6 (TX_ABRT) of the Raw Interrupt_Status register. The I2C remains in General Call mode until the special bit value (bit 11) is cleared."]
pub type GcOrStartW<'a, REG> = crate::BitWriter<'a, REG, GcOrStart>;
impl<'a, REG> GcOrStartW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn gencall(self) -> &'a mut crate::W<REG> {
        self.variant(GcOrStart::Gencall)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn startbyte(self) -> &'a mut crate::W<REG> {
        self.variant(GcOrStart::Startbyte)
    }
}
#[doc = "This bit indicates whether software performs a General Call or START BYTE command.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    #[doc = "0: `0`"]
    Gencall = 0,
    #[doc = "1: `1`"]
    Startbyte = 1,
}
impl From<Special> for bool {
    #[inline(always)]
    fn from(variant: Special) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `special` reader - This bit indicates whether software performs a General Call or START BYTE command."]
pub type SpecialR = crate::BitReader<Special>;
impl SpecialR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Special {
        match self.bits {
            false => Special::Gencall,
            true => Special::Startbyte,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gencall(&self) -> bool {
        *self == Special::Gencall
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_startbyte(&self) -> bool {
        *self == Special::Startbyte
    }
}
#[doc = "Field `special` writer - This bit indicates whether software performs a General Call or START BYTE command."]
pub type SpecialW<'a, REG> = crate::BitWriter<'a, REG, Special>;
impl<'a, REG> SpecialW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn gencall(self) -> &'a mut crate::W<REG> {
        self.variant(Special::Gencall)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn startbyte(self) -> &'a mut crate::W<REG> {
        self.variant(Special::Startbyte)
    }
}
#[doc = "This bit controls whether the i2c starts its transfers in 7-bit or 10-bit addressing mode when acting as a master.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ic10bitaddrMaster {
    #[doc = "0: `0`"]
    Start7 = 0,
    #[doc = "1: `1`"]
    Start10 = 1,
}
impl From<Ic10bitaddrMaster> for bool {
    #[inline(always)]
    fn from(variant: Ic10bitaddrMaster) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ic_10bitaddr_master` reader - This bit controls whether the i2c starts its transfers in 7-bit or 10-bit addressing mode when acting as a master."]
pub type Ic10bitaddrMasterR = crate::BitReader<Ic10bitaddrMaster>;
impl Ic10bitaddrMasterR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ic10bitaddrMaster {
        match self.bits {
            false => Ic10bitaddrMaster::Start7,
            true => Ic10bitaddrMaster::Start10,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_start7(&self) -> bool {
        *self == Ic10bitaddrMaster::Start7
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_start10(&self) -> bool {
        *self == Ic10bitaddrMaster::Start10
    }
}
#[doc = "Field `ic_10bitaddr_master` writer - This bit controls whether the i2c starts its transfers in 7-bit or 10-bit addressing mode when acting as a master."]
pub type Ic10bitaddrMasterW<'a, REG> = crate::BitWriter<'a, REG, Ic10bitaddrMaster>;
impl<'a, REG> Ic10bitaddrMasterW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn start7(self) -> &'a mut crate::W<REG> {
        self.variant(Ic10bitaddrMaster::Start7)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn start10(self) -> &'a mut crate::W<REG> {
        self.variant(Ic10bitaddrMaster::Start10)
    }
}
impl R {
    #[doc = "Bits 0:9 - This is the target address for any master transaction. When transmitting a General Call, these bits are ignored. To generate a START BYTE, the CPU needs to write only once into these bits. If the ic_tar and ic_sar are the same, loopback exists but the FIFOs are shared between master and slave, so full loopback is not feasible. Only one direction loopback mode is supported (simplex), not duplex. A master cannot transmit to itself; it can transmit to only a slave."]
    #[inline(always)]
    pub fn ic_tar(&self) -> IcTarR {
        IcTarR::new((self.bits & 0x03ff) as u16)
    }
    #[doc = "Bit 10 - If bit 11 (SPECIAL) of this Register is set to 1, then this bit indicates whether a General Call or START byte command is to be performed by the I2C or General Call Address after issuing a General Call, only writes may be performed. Attempting to issue a read command results in setting bit 6 (TX_ABRT) of the Raw Interrupt_Status register. The I2C remains in General Call mode until the special bit value (bit 11) is cleared."]
    #[inline(always)]
    pub fn gc_or_start(&self) -> GcOrStartR {
        GcOrStartR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit indicates whether software performs a General Call or START BYTE command."]
    #[inline(always)]
    pub fn special(&self) -> SpecialR {
        SpecialR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit controls whether the i2c starts its transfers in 7-bit or 10-bit addressing mode when acting as a master."]
    #[inline(always)]
    pub fn ic_10bitaddr_master(&self) -> Ic10bitaddrMasterR {
        Ic10bitaddrMasterR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:9 - This is the target address for any master transaction. When transmitting a General Call, these bits are ignored. To generate a START BYTE, the CPU needs to write only once into these bits. If the ic_tar and ic_sar are the same, loopback exists but the FIFOs are shared between master and slave, so full loopback is not feasible. Only one direction loopback mode is supported (simplex), not duplex. A master cannot transmit to itself; it can transmit to only a slave."]
    #[inline(always)]
    #[must_use]
    pub fn ic_tar(&mut self) -> IcTarW<IcTarSpec> {
        IcTarW::new(self, 0)
    }
    #[doc = "Bit 10 - If bit 11 (SPECIAL) of this Register is set to 1, then this bit indicates whether a General Call or START byte command is to be performed by the I2C or General Call Address after issuing a General Call, only writes may be performed. Attempting to issue a read command results in setting bit 6 (TX_ABRT) of the Raw Interrupt_Status register. The I2C remains in General Call mode until the special bit value (bit 11) is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn gc_or_start(&mut self) -> GcOrStartW<IcTarSpec> {
        GcOrStartW::new(self, 10)
    }
    #[doc = "Bit 11 - This bit indicates whether software performs a General Call or START BYTE command."]
    #[inline(always)]
    #[must_use]
    pub fn special(&mut self) -> SpecialW<IcTarSpec> {
        SpecialW::new(self, 11)
    }
    #[doc = "Bit 12 - This bit controls whether the i2c starts its transfers in 7-bit or 10-bit addressing mode when acting as a master."]
    #[inline(always)]
    #[must_use]
    pub fn ic_10bitaddr_master(&mut self) -> Ic10bitaddrMasterW<IcTarSpec> {
        Ic10bitaddrMasterW::new(self, 12)
    }
}
#[doc = "This register can be written to only when the ic_enable register is set to 0. This register is 13 bits wide. All bits can be dynamically updated as long as any set of the following conditions are true, (Enable Register bit 0 is set to 0) or (Enable Register bit 0 is set to 1 AND (I2C is NOT engaged in any Master \\[tx, rx\\]
operation \\[ic_status register mst_activity bit 5 is set to 0\\]) AND (I2C is enabled to operate in Master mode\\[ic_con bit\\[0\\]
is set to one\\]) AND (there are NO entries in the TX FIFO Register \\[IC_STATUS bit \\[2\\]
is set to 1\\])\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_tar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_tar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcTarSpec;
impl crate::RegisterSpec for IcTarSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ic_tar::R`](R) reader structure"]
impl crate::Readable for IcTarSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_tar::W`](W) writer structure"]
impl crate::Writable for IcTarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_tar to value 0x1055"]
impl crate::Resettable for IcTarSpec {
    const RESET_VALUE: u32 = 0x1055;
}
