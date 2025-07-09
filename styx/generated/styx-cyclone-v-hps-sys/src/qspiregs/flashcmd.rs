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
#[doc = "Register `flashcmd` reader"]
pub type R = crate::R<FlashcmdSpec>;
#[doc = "Register `flashcmd` writer"]
pub type W = crate::W<FlashcmdSpec>;
#[doc = "Execute the command.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Execcmd {
    #[doc = "1: `1`"]
    Execute = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Execcmd> for bool {
    #[inline(always)]
    fn from(variant: Execcmd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `execcmd` reader - Execute the command."]
pub type ExeccmdR = crate::BitReader<Execcmd>;
impl ExeccmdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Execcmd {
        match self.bits {
            true => Execcmd::Execute,
            false => Execcmd::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_execute(&self) -> bool {
        *self == Execcmd::Execute
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Execcmd::Noaction
    }
}
#[doc = "Field `execcmd` writer - Execute the command."]
pub type ExeccmdW<'a, REG> = crate::BitWriter<'a, REG, Execcmd>;
impl<'a, REG> ExeccmdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn execute(self) -> &'a mut crate::W<REG> {
        self.variant(Execcmd::Execute)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(Execcmd::Noaction)
    }
}
#[doc = "Command execution in progress.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmdexecstat {
    #[doc = "1: `1`"]
    Executestat = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Cmdexecstat> for bool {
    #[inline(always)]
    fn from(variant: Cmdexecstat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cmdexecstat` reader - Command execution in progress."]
pub type CmdexecstatR = crate::BitReader<Cmdexecstat>;
impl CmdexecstatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cmdexecstat {
        match self.bits {
            true => Cmdexecstat::Executestat,
            false => Cmdexecstat::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_executestat(&self) -> bool {
        *self == Cmdexecstat::Executestat
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Cmdexecstat::Noaction
    }
}
#[doc = "Field `cmdexecstat` writer - Command execution in progress."]
pub type CmdexecstatW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `numdummybytes` reader - Set to the number of dummy bytes required This should be setup before triggering the command via the execute field of this register."]
pub type NumdummybytesR = crate::FieldReader;
#[doc = "Field `numdummybytes` writer - Set to the number of dummy bytes required This should be setup before triggering the command via the execute field of this register."]
pub type NumdummybytesW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Up to 8 Data bytes may be written using this command.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Numwrdatabytes {
    #[doc = "0: `0`"]
    Wrbyte1 = 0,
    #[doc = "1: `1`"]
    Wrbyte2 = 1,
    #[doc = "2: `10`"]
    Wrbyte3 = 2,
    #[doc = "3: `11`"]
    Wrbyte4 = 3,
    #[doc = "4: `100`"]
    Wrbyte5 = 4,
    #[doc = "5: `101`"]
    Wrbyte6 = 5,
    #[doc = "6: `110`"]
    Wrbyte7 = 6,
    #[doc = "7: `111`"]
    Wrbyte8 = 7,
}
impl From<Numwrdatabytes> for u8 {
    #[inline(always)]
    fn from(variant: Numwrdatabytes) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Numwrdatabytes {
    type Ux = u8;
}
#[doc = "Field `numwrdatabytes` reader - Up to 8 Data bytes may be written using this command."]
pub type NumwrdatabytesR = crate::FieldReader<Numwrdatabytes>;
impl NumwrdatabytesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Numwrdatabytes {
        match self.bits {
            0 => Numwrdatabytes::Wrbyte1,
            1 => Numwrdatabytes::Wrbyte2,
            2 => Numwrdatabytes::Wrbyte3,
            3 => Numwrdatabytes::Wrbyte4,
            4 => Numwrdatabytes::Wrbyte5,
            5 => Numwrdatabytes::Wrbyte6,
            6 => Numwrdatabytes::Wrbyte7,
            7 => Numwrdatabytes::Wrbyte8,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_wrbyte1(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_wrbyte2(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_wrbyte3(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte3
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_wrbyte4(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte4
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_wrbyte5(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte5
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_wrbyte6(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte6
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_wrbyte7(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte7
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_wrbyte8(&self) -> bool {
        *self == Numwrdatabytes::Wrbyte8
    }
}
#[doc = "Field `numwrdatabytes` writer - Up to 8 Data bytes may be written using this command."]
pub type NumwrdatabytesW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Numwrdatabytes>;
impl<'a, REG> NumwrdatabytesW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn wrbyte1(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn wrbyte2(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn wrbyte3(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte3)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn wrbyte4(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte4)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn wrbyte5(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte5)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn wrbyte6(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte6)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn wrbyte7(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte7)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn wrbyte8(self) -> &'a mut crate::W<REG> {
        self.variant(Numwrdatabytes::Wrbyte8)
    }
}
#[doc = "Set to 1 if the command specified in the command opcode field requires write data bytes to be sent to the device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enwrdata {
    #[doc = "1: `1`"]
    Wrdatabytes = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Enwrdata> for bool {
    #[inline(always)]
    fn from(variant: Enwrdata) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enwrdata` reader - Set to 1 if the command specified in the command opcode field requires write data bytes to be sent to the device."]
pub type EnwrdataR = crate::BitReader<Enwrdata>;
impl EnwrdataR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enwrdata {
        match self.bits {
            true => Enwrdata::Wrdatabytes,
            false => Enwrdata::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_wrdatabytes(&self) -> bool {
        *self == Enwrdata::Wrdatabytes
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Enwrdata::Noaction
    }
}
#[doc = "Field `enwrdata` writer - Set to 1 if the command specified in the command opcode field requires write data bytes to be sent to the device."]
pub type EnwrdataW<'a, REG> = crate::BitWriter<'a, REG, Enwrdata>;
impl<'a, REG> EnwrdataW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn wrdatabytes(self) -> &'a mut crate::W<REG> {
        self.variant(Enwrdata::Wrdatabytes)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(Enwrdata::Noaction)
    }
}
#[doc = "Set to the number of address bytes required (the address itself is programmed in the FLASH COMMAND ADDRESS REGISTERS). This should be setup before triggering the command via bit 0 of this register. 2'b00 : 1 address byte 2'b01 : 2 address bytes 2'b10 : 3 address bytes 2'b11 : 4 address bytes\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Numaddrbytes {
    #[doc = "0: `0`"]
    Addrbyte1 = 0,
    #[doc = "1: `1`"]
    Addrbyte2 = 1,
    #[doc = "2: `10`"]
    Addrbyte3 = 2,
    #[doc = "3: `11`"]
    Addrbyte4 = 3,
}
impl From<Numaddrbytes> for u8 {
    #[inline(always)]
    fn from(variant: Numaddrbytes) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Numaddrbytes {
    type Ux = u8;
}
#[doc = "Field `numaddrbytes` reader - Set to the number of address bytes required (the address itself is programmed in the FLASH COMMAND ADDRESS REGISTERS). This should be setup before triggering the command via bit 0 of this register. 2'b00 : 1 address byte 2'b01 : 2 address bytes 2'b10 : 3 address bytes 2'b11 : 4 address bytes"]
pub type NumaddrbytesR = crate::FieldReader<Numaddrbytes>;
impl NumaddrbytesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Numaddrbytes {
        match self.bits {
            0 => Numaddrbytes::Addrbyte1,
            1 => Numaddrbytes::Addrbyte2,
            2 => Numaddrbytes::Addrbyte3,
            3 => Numaddrbytes::Addrbyte4,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_addrbyte1(&self) -> bool {
        *self == Numaddrbytes::Addrbyte1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_addrbyte2(&self) -> bool {
        *self == Numaddrbytes::Addrbyte2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_addrbyte3(&self) -> bool {
        *self == Numaddrbytes::Addrbyte3
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_addrbyte4(&self) -> bool {
        *self == Numaddrbytes::Addrbyte4
    }
}
#[doc = "Field `numaddrbytes` writer - Set to the number of address bytes required (the address itself is programmed in the FLASH COMMAND ADDRESS REGISTERS). This should be setup before triggering the command via bit 0 of this register. 2'b00 : 1 address byte 2'b01 : 2 address bytes 2'b10 : 3 address bytes 2'b11 : 4 address bytes"]
pub type NumaddrbytesW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Numaddrbytes>;
impl<'a, REG> NumaddrbytesW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn addrbyte1(self) -> &'a mut crate::W<REG> {
        self.variant(Numaddrbytes::Addrbyte1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn addrbyte2(self) -> &'a mut crate::W<REG> {
        self.variant(Numaddrbytes::Addrbyte2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn addrbyte3(self) -> &'a mut crate::W<REG> {
        self.variant(Numaddrbytes::Addrbyte3)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn addrbyte4(self) -> &'a mut crate::W<REG> {
        self.variant(Numaddrbytes::Addrbyte4)
    }
}
#[doc = "Set to 1 to ensure the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enmodebit {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Enmodebit> for bool {
    #[inline(always)]
    fn from(variant: Enmodebit) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enmodebit` reader - Set to 1 to ensure the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
pub type EnmodebitR = crate::BitReader<Enmodebit>;
impl EnmodebitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enmodebit {
        match self.bits {
            true => Enmodebit::Enabled,
            false => Enmodebit::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Enmodebit::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Enmodebit::Disabled
    }
}
#[doc = "Field `enmodebit` writer - Set to 1 to ensure the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
pub type EnmodebitW<'a, REG> = crate::BitWriter<'a, REG, Enmodebit>;
impl<'a, REG> EnmodebitW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Enmodebit::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Enmodebit::Disabled)
    }
}
#[doc = "If enabled, the command specified in bits 31:24 requires an address. This should be setup before triggering the command via writing a 1 to the execute field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encmdaddr {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Encmdaddr> for bool {
    #[inline(always)]
    fn from(variant: Encmdaddr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `encmdaddr` reader - If enabled, the command specified in bits 31:24 requires an address. This should be setup before triggering the command via writing a 1 to the execute field."]
pub type EncmdaddrR = crate::BitReader<Encmdaddr>;
impl EncmdaddrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Encmdaddr {
        match self.bits {
            true => Encmdaddr::Enabled,
            false => Encmdaddr::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Encmdaddr::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Encmdaddr::Disabled
    }
}
#[doc = "Field `encmdaddr` writer - If enabled, the command specified in bits 31:24 requires an address. This should be setup before triggering the command via writing a 1 to the execute field."]
pub type EncmdaddrW<'a, REG> = crate::BitWriter<'a, REG, Encmdaddr>;
impl<'a, REG> EncmdaddrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Encmdaddr::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Encmdaddr::Disabled)
    }
}
#[doc = "Up to 8 data bytes may be read using this command. Set to 0 for 1 byte and 7 for 8 bytes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Numrddatabytes {
    #[doc = "0: `0`"]
    Rdbyte1 = 0,
    #[doc = "1: `1`"]
    Rdbyte2 = 1,
    #[doc = "2: `10`"]
    Rdbyte3 = 2,
    #[doc = "3: `11`"]
    Rdbyte4 = 3,
    #[doc = "4: `100`"]
    Rdbyte5 = 4,
    #[doc = "5: `101`"]
    Rdbyte6 = 5,
    #[doc = "6: `110`"]
    Rdbyte7 = 6,
    #[doc = "7: `111`"]
    Rdbyte8 = 7,
}
impl From<Numrddatabytes> for u8 {
    #[inline(always)]
    fn from(variant: Numrddatabytes) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Numrddatabytes {
    type Ux = u8;
}
#[doc = "Field `numrddatabytes` reader - Up to 8 data bytes may be read using this command. Set to 0 for 1 byte and 7 for 8 bytes."]
pub type NumrddatabytesR = crate::FieldReader<Numrddatabytes>;
impl NumrddatabytesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Numrddatabytes {
        match self.bits {
            0 => Numrddatabytes::Rdbyte1,
            1 => Numrddatabytes::Rdbyte2,
            2 => Numrddatabytes::Rdbyte3,
            3 => Numrddatabytes::Rdbyte4,
            4 => Numrddatabytes::Rdbyte5,
            5 => Numrddatabytes::Rdbyte6,
            6 => Numrddatabytes::Rdbyte7,
            7 => Numrddatabytes::Rdbyte8,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rdbyte1(&self) -> bool {
        *self == Numrddatabytes::Rdbyte1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rdbyte2(&self) -> bool {
        *self == Numrddatabytes::Rdbyte2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rdbyte3(&self) -> bool {
        *self == Numrddatabytes::Rdbyte3
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_rdbyte4(&self) -> bool {
        *self == Numrddatabytes::Rdbyte4
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_rdbyte5(&self) -> bool {
        *self == Numrddatabytes::Rdbyte5
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_rdbyte6(&self) -> bool {
        *self == Numrddatabytes::Rdbyte6
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_rdbyte7(&self) -> bool {
        *self == Numrddatabytes::Rdbyte7
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_rdbyte8(&self) -> bool {
        *self == Numrddatabytes::Rdbyte8
    }
}
#[doc = "Field `numrddatabytes` writer - Up to 8 data bytes may be read using this command. Set to 0 for 1 byte and 7 for 8 bytes."]
pub type NumrddatabytesW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Numrddatabytes>;
impl<'a, REG> NumrddatabytesW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rdbyte1(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rdbyte2(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn rdbyte3(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte3)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn rdbyte4(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte4)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn rdbyte5(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte5)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn rdbyte6(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte6)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn rdbyte7(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte7)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn rdbyte8(self) -> &'a mut crate::W<REG> {
        self.variant(Numrddatabytes::Rdbyte8)
    }
}
#[doc = "If enabled, the command specified in the command opcode field (bits 31:24) requires read data bytes to be received from the device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enrddata {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Enrddata> for bool {
    #[inline(always)]
    fn from(variant: Enrddata) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enrddata` reader - If enabled, the command specified in the command opcode field (bits 31:24) requires read data bytes to be received from the device."]
pub type EnrddataR = crate::BitReader<Enrddata>;
impl EnrddataR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enrddata {
        match self.bits {
            true => Enrddata::Enable,
            false => Enrddata::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Enrddata::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Enrddata::Noaction
    }
}
#[doc = "Field `enrddata` writer - If enabled, the command specified in the command opcode field (bits 31:24) requires read data bytes to be received from the device."]
pub type EnrddataW<'a, REG> = crate::BitWriter<'a, REG, Enrddata>;
impl<'a, REG> EnrddataW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Enrddata::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(Enrddata::Noaction)
    }
}
#[doc = "Field `cmdopcode` reader - The command opcode field should be setup before triggering the command. For example, 0x20 maps to SubSector Erase. Writeing to the execute field (bit 0) of this register launches the command. NOTE : Using this approach to issue commands to the device will make use of the instruction type of the device instruction configuration register. If this field is set to 2'b00, then the command opcode, command address, command dummy bytes and command data will all be transferred in a serial fashion. If this field is set to 2'b01, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0 and DQ1 pins. If this field is set to 2'b10, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0, DQ1, DQ2 and DQ3 pins."]
pub type CmdopcodeR = crate::FieldReader;
#[doc = "Field `cmdopcode` writer - The command opcode field should be setup before triggering the command. For example, 0x20 maps to SubSector Erase. Writeing to the execute field (bit 0) of this register launches the command. NOTE : Using this approach to issue commands to the device will make use of the instruction type of the device instruction configuration register. If this field is set to 2'b00, then the command opcode, command address, command dummy bytes and command data will all be transferred in a serial fashion. If this field is set to 2'b01, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0 and DQ1 pins. If this field is set to 2'b10, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0, DQ1, DQ2 and DQ3 pins."]
pub type CmdopcodeW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bit 0 - Execute the command."]
    #[inline(always)]
    pub fn execcmd(&self) -> ExeccmdR {
        ExeccmdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Command execution in progress."]
    #[inline(always)]
    pub fn cmdexecstat(&self) -> CmdexecstatR {
        CmdexecstatR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 7:11 - Set to the number of dummy bytes required This should be setup before triggering the command via the execute field of this register."]
    #[inline(always)]
    pub fn numdummybytes(&self) -> NumdummybytesR {
        NumdummybytesR::new(((self.bits >> 7) & 0x1f) as u8)
    }
    #[doc = "Bits 12:14 - Up to 8 Data bytes may be written using this command."]
    #[inline(always)]
    pub fn numwrdatabytes(&self) -> NumwrdatabytesR {
        NumwrdatabytesR::new(((self.bits >> 12) & 7) as u8)
    }
    #[doc = "Bit 15 - Set to 1 if the command specified in the command opcode field requires write data bytes to be sent to the device."]
    #[inline(always)]
    pub fn enwrdata(&self) -> EnwrdataR {
        EnwrdataR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:17 - Set to the number of address bytes required (the address itself is programmed in the FLASH COMMAND ADDRESS REGISTERS). This should be setup before triggering the command via bit 0 of this register. 2'b00 : 1 address byte 2'b01 : 2 address bytes 2'b10 : 3 address bytes 2'b11 : 4 address bytes"]
    #[inline(always)]
    pub fn numaddrbytes(&self) -> NumaddrbytesR {
        NumaddrbytesR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 18 - Set to 1 to ensure the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
    #[inline(always)]
    pub fn enmodebit(&self) -> EnmodebitR {
        EnmodebitR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - If enabled, the command specified in bits 31:24 requires an address. This should be setup before triggering the command via writing a 1 to the execute field."]
    #[inline(always)]
    pub fn encmdaddr(&self) -> EncmdaddrR {
        EncmdaddrR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bits 20:22 - Up to 8 data bytes may be read using this command. Set to 0 for 1 byte and 7 for 8 bytes."]
    #[inline(always)]
    pub fn numrddatabytes(&self) -> NumrddatabytesR {
        NumrddatabytesR::new(((self.bits >> 20) & 7) as u8)
    }
    #[doc = "Bit 23 - If enabled, the command specified in the command opcode field (bits 31:24) requires read data bytes to be received from the device."]
    #[inline(always)]
    pub fn enrddata(&self) -> EnrddataR {
        EnrddataR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:31 - The command opcode field should be setup before triggering the command. For example, 0x20 maps to SubSector Erase. Writeing to the execute field (bit 0) of this register launches the command. NOTE : Using this approach to issue commands to the device will make use of the instruction type of the device instruction configuration register. If this field is set to 2'b00, then the command opcode, command address, command dummy bytes and command data will all be transferred in a serial fashion. If this field is set to 2'b01, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0 and DQ1 pins. If this field is set to 2'b10, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0, DQ1, DQ2 and DQ3 pins."]
    #[inline(always)]
    pub fn cmdopcode(&self) -> CmdopcodeR {
        CmdopcodeR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Execute the command."]
    #[inline(always)]
    #[must_use]
    pub fn execcmd(&mut self) -> ExeccmdW<FlashcmdSpec> {
        ExeccmdW::new(self, 0)
    }
    #[doc = "Bit 1 - Command execution in progress."]
    #[inline(always)]
    #[must_use]
    pub fn cmdexecstat(&mut self) -> CmdexecstatW<FlashcmdSpec> {
        CmdexecstatW::new(self, 1)
    }
    #[doc = "Bits 7:11 - Set to the number of dummy bytes required This should be setup before triggering the command via the execute field of this register."]
    #[inline(always)]
    #[must_use]
    pub fn numdummybytes(&mut self) -> NumdummybytesW<FlashcmdSpec> {
        NumdummybytesW::new(self, 7)
    }
    #[doc = "Bits 12:14 - Up to 8 Data bytes may be written using this command."]
    #[inline(always)]
    #[must_use]
    pub fn numwrdatabytes(&mut self) -> NumwrdatabytesW<FlashcmdSpec> {
        NumwrdatabytesW::new(self, 12)
    }
    #[doc = "Bit 15 - Set to 1 if the command specified in the command opcode field requires write data bytes to be sent to the device."]
    #[inline(always)]
    #[must_use]
    pub fn enwrdata(&mut self) -> EnwrdataW<FlashcmdSpec> {
        EnwrdataW::new(self, 15)
    }
    #[doc = "Bits 16:17 - Set to the number of address bytes required (the address itself is programmed in the FLASH COMMAND ADDRESS REGISTERS). This should be setup before triggering the command via bit 0 of this register. 2'b00 : 1 address byte 2'b01 : 2 address bytes 2'b10 : 3 address bytes 2'b11 : 4 address bytes"]
    #[inline(always)]
    #[must_use]
    pub fn numaddrbytes(&mut self) -> NumaddrbytesW<FlashcmdSpec> {
        NumaddrbytesW::new(self, 16)
    }
    #[doc = "Bit 18 - Set to 1 to ensure the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
    #[inline(always)]
    #[must_use]
    pub fn enmodebit(&mut self) -> EnmodebitW<FlashcmdSpec> {
        EnmodebitW::new(self, 18)
    }
    #[doc = "Bit 19 - If enabled, the command specified in bits 31:24 requires an address. This should be setup before triggering the command via writing a 1 to the execute field."]
    #[inline(always)]
    #[must_use]
    pub fn encmdaddr(&mut self) -> EncmdaddrW<FlashcmdSpec> {
        EncmdaddrW::new(self, 19)
    }
    #[doc = "Bits 20:22 - Up to 8 data bytes may be read using this command. Set to 0 for 1 byte and 7 for 8 bytes."]
    #[inline(always)]
    #[must_use]
    pub fn numrddatabytes(&mut self) -> NumrddatabytesW<FlashcmdSpec> {
        NumrddatabytesW::new(self, 20)
    }
    #[doc = "Bit 23 - If enabled, the command specified in the command opcode field (bits 31:24) requires read data bytes to be received from the device."]
    #[inline(always)]
    #[must_use]
    pub fn enrddata(&mut self) -> EnrddataW<FlashcmdSpec> {
        EnrddataW::new(self, 23)
    }
    #[doc = "Bits 24:31 - The command opcode field should be setup before triggering the command. For example, 0x20 maps to SubSector Erase. Writeing to the execute field (bit 0) of this register launches the command. NOTE : Using this approach to issue commands to the device will make use of the instruction type of the device instruction configuration register. If this field is set to 2'b00, then the command opcode, command address, command dummy bytes and command data will all be transferred in a serial fashion. If this field is set to 2'b01, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0 and DQ1 pins. If this field is set to 2'b10, then the command opcode, command address, command dummy bytes and command data will all be transferred in parallel using DQ0, DQ1, DQ2 and DQ3 pins."]
    #[inline(always)]
    #[must_use]
    pub fn cmdopcode(&mut self) -> CmdopcodeW<FlashcmdSpec> {
        CmdopcodeW::new(self, 24)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FlashcmdSpec;
impl crate::RegisterSpec for FlashcmdSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`flashcmd::R`](R) reader structure"]
impl crate::Readable for FlashcmdSpec {}
#[doc = "`write(|w| ..)` method takes [`flashcmd::W`](W) writer structure"]
impl crate::Writable for FlashcmdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets flashcmd to value 0"]
impl crate::Resettable for FlashcmdSpec {
    const RESET_VALUE: u32 = 0;
}
