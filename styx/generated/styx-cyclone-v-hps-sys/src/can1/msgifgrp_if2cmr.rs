// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msgifgrp_IF2CMR` reader"]
pub type R = crate::R<MsgifgrpIf2cmrSpec>;
#[doc = "Register `msgifgrp_IF2CMR` writer"]
pub type W = crate::W<MsgifgrpIf2cmrSpec>;
#[doc = "Field `MONum` reader - 0x01-0x80 Valid Message Number, the Message Object in the Message RAM is selected for data transfer (up to 128 MsgObj). 0x00 Not a valid Message Number, interpreted as 0x80. 0x81-0xFF Not a valid Message Number, interpreted as 0x01-0x7F. Note: When an invalid Message Number is written to IFxCMR.MONum which is higher than the last Message Object number, a modulo addressing will occur.When e.g. accessing Message Object 33 in a CAN module with 32 Message Objects only, the Message Object 1 will be accessed instead."]
pub type MonumR = crate::FieldReader;
#[doc = "Field `MONum` writer - 0x01-0x80 Valid Message Number, the Message Object in the Message RAM is selected for data transfer (up to 128 MsgObj). 0x00 Not a valid Message Number, interpreted as 0x80. 0x81-0xFF Not a valid Message Number, interpreted as 0x01-0x7F. Note: When an invalid Message Number is written to IFxCMR.MONum which is higher than the last Message Object number, a modulo addressing will occur.When e.g. accessing Message Object 33 in a CAN module with 32 Message Objects only, the Message Object 1 will be accessed instead."]
pub type MonumW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Automatic Increment of Message Object Number The behavior of the Message Object Number increment depends on the Transfer Direction, IFxCMR.WR1RD0. * Read: The first transfer will be initiated (Busy Bit will set) at write of IFxCMR.MONum. The Message Object Number will be incremented and the next Message Object will be transferred from Message Object RAM to Interface Registers after a read access of Data-Byte 7. * Write: The first as well as each other transfer will be started after write access to Data- Byte7. The Message Object Number will be incremented after successful transfer from the Interface Registers to the Message Object RAM. Always after successful transfer the Busy Bit will be reset. In combination with DMAactive the port CAN_IFxDMA is set, too. Note: If the direction is configured as Read a write access to Data-Byte 7 will not start any transfer, as well as if the direction is configured as Write a read access to Data-Byte 7 will not start any transfer. At transfer direction Read each read of Data-Byte 7 will start a transfer until IFxCMR.AutoInc is reset. To aware of resetting a NewDat bit of the following message object, the application has to reset IFxCMR.AutoInc before reading the Data-Byte 7 of the last message object which will be read.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoInc {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<AutoInc> for bool {
    #[inline(always)]
    fn from(variant: AutoInc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `AutoInc` reader - Automatic Increment of Message Object Number The behavior of the Message Object Number increment depends on the Transfer Direction, IFxCMR.WR1RD0. * Read: The first transfer will be initiated (Busy Bit will set) at write of IFxCMR.MONum. The Message Object Number will be incremented and the next Message Object will be transferred from Message Object RAM to Interface Registers after a read access of Data-Byte 7. * Write: The first as well as each other transfer will be started after write access to Data- Byte7. The Message Object Number will be incremented after successful transfer from the Interface Registers to the Message Object RAM. Always after successful transfer the Busy Bit will be reset. In combination with DMAactive the port CAN_IFxDMA is set, too. Note: If the direction is configured as Read a write access to Data-Byte 7 will not start any transfer, as well as if the direction is configured as Write a read access to Data-Byte 7 will not start any transfer. At transfer direction Read each read of Data-Byte 7 will start a transfer until IFxCMR.AutoInc is reset. To aware of resetting a NewDat bit of the following message object, the application has to reset IFxCMR.AutoInc before reading the Data-Byte 7 of the last message object which will be read."]
pub type AutoIncR = crate::BitReader<AutoInc>;
impl AutoIncR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> AutoInc {
        match self.bits {
            false => AutoInc::Disabled,
            true => AutoInc::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == AutoInc::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == AutoInc::Enabled
    }
}
#[doc = "Field `AutoInc` writer - Automatic Increment of Message Object Number The behavior of the Message Object Number increment depends on the Transfer Direction, IFxCMR.WR1RD0. * Read: The first transfer will be initiated (Busy Bit will set) at write of IFxCMR.MONum. The Message Object Number will be incremented and the next Message Object will be transferred from Message Object RAM to Interface Registers after a read access of Data-Byte 7. * Write: The first as well as each other transfer will be started after write access to Data- Byte7. The Message Object Number will be incremented after successful transfer from the Interface Registers to the Message Object RAM. Always after successful transfer the Busy Bit will be reset. In combination with DMAactive the port CAN_IFxDMA is set, too. Note: If the direction is configured as Read a write access to Data-Byte 7 will not start any transfer, as well as if the direction is configured as Write a read access to Data-Byte 7 will not start any transfer. At transfer direction Read each read of Data-Byte 7 will start a transfer until IFxCMR.AutoInc is reset. To aware of resetting a NewDat bit of the following message object, the application has to reset IFxCMR.AutoInc before reading the Data-Byte 7 of the last message object which will be read."]
pub type AutoIncW<'a, REG> = crate::BitWriter<'a, REG, AutoInc>;
impl<'a, REG> AutoIncW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(AutoInc::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(AutoInc::Enabled)
    }
}
#[doc = "Activation of DMA feature for subsequent internal IFx Register Set\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmaactive {
    #[doc = "0: `0`"]
    Passive = 0,
    #[doc = "1: `1`"]
    Initiated = 1,
}
impl From<Dmaactive> for bool {
    #[inline(always)]
    fn from(variant: Dmaactive) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `DMAactive` reader - Activation of DMA feature for subsequent internal IFx Register Set"]
pub type DmaactiveR = crate::BitReader<Dmaactive>;
impl DmaactiveR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dmaactive {
        match self.bits {
            false => Dmaactive::Passive,
            true => Dmaactive::Initiated,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_passive(&self) -> bool {
        *self == Dmaactive::Passive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_initiated(&self) -> bool {
        *self == Dmaactive::Initiated
    }
}
#[doc = "Field `DMAactive` writer - Activation of DMA feature for subsequent internal IFx Register Set"]
pub type DmaactiveW<'a, REG> = crate::BitWriter<'a, REG, Dmaactive>;
impl<'a, REG> DmaactiveW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn passive(self) -> &'a mut crate::W<REG> {
        self.variant(Dmaactive::Passive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn initiated(self) -> &'a mut crate::W<REG> {
        self.variant(Dmaactive::Initiated)
    }
}
#[doc = "Busy Flag\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Busy {
    #[doc = "0: `0`"]
    Done = 0,
    #[doc = "1: `1`"]
    Writing = 1,
}
impl From<Busy> for bool {
    #[inline(always)]
    fn from(variant: Busy) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Busy` reader - Busy Flag"]
pub type BusyR = crate::BitReader<Busy>;
impl BusyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Busy {
        match self.bits {
            false => Busy::Done,
            true => Busy::Writing,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_done(&self) -> bool {
        *self == Busy::Done
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_writing(&self) -> bool {
        *self == Busy::Writing
    }
}
#[doc = "Field `Busy` writer - Busy Flag"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DataB` reader - Write Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to Message Object. Read Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to IFxDB. Note: The speed of the message transfer does not depend on how many bytes are transferred."]
pub type DataBR = crate::BitReader;
#[doc = "Field `DataB` writer - Write Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to Message Object. Read Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to IFxDB. Note: The speed of the message transfer does not depend on how many bytes are transferred."]
pub type DataBW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DataA` reader - Write Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to Message Object. Read Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to IFxDA."]
pub type DataAR = crate::BitReader;
#[doc = "Field `DataA` writer - Write Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to Message Object. Read Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to IFxDA."]
pub type DataAW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TxRqstNewDat` reader - Write Direction: 0= TxRqst and NewDat bit will be handled according IFxMCTR.NewDat bit and IFxMCTR.TxRqst bit. 1= set TxRqst and NewDat in Message Object to one Note: If a CAN transmission is requested by setting IFxCMR.TxRqst/NewDat, the TxRqst and NewDat bits in the Message Object will be set to one independently of the values in IFxMCTR. Read Direction: 0= NewDat bit remains unchanged. 1= clear NewDat bit in the Message Object. Note: A read access to a Message Object can be combined with the reset of the control bits IntPnd and NewDat. The values of these bits transferred to the IFxMCTR always reflect the status before resetting them."]
pub type TxRqstNewDatR = crate::BitReader;
#[doc = "Field `TxRqstNewDat` writer - Write Direction: 0= TxRqst and NewDat bit will be handled according IFxMCTR.NewDat bit and IFxMCTR.TxRqst bit. 1= set TxRqst and NewDat in Message Object to one Note: If a CAN transmission is requested by setting IFxCMR.TxRqst/NewDat, the TxRqst and NewDat bits in the Message Object will be set to one independently of the values in IFxMCTR. Read Direction: 0= NewDat bit remains unchanged. 1= clear NewDat bit in the Message Object. Note: A read access to a Message Object can be combined with the reset of the control bits IntPnd and NewDat. The values of these bits transferred to the IFxMCTR always reflect the status before resetting them."]
pub type TxRqstNewDatW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ClrIntPnd` reader - Write Direction: Has no influence to Message Object at write transfer. Note: When writing to a Message Object, this bit is ignored and copying of IntPnd flag from IFx Control Register to Message RAM could only be controlled by IFxMTR.IntPnd bit. Read Direction: 0= IntPnd bit remains unchanged. 1= clear IntPnd bit in the Message Object."]
pub type ClrIntPndR = crate::BitReader;
#[doc = "Field `ClrIntPnd` writer - Write Direction: Has no influence to Message Object at write transfer. Note: When writing to a Message Object, this bit is ignored and copying of IntPnd flag from IFx Control Register to Message RAM could only be controlled by IFxMTR.IntPnd bit. Read Direction: 0= IntPnd bit remains unchanged. 1= clear IntPnd bit in the Message Object."]
pub type ClrIntPndW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `Control` reader - Write Direction: 0= Control Bits unchanged. 1= transfer Control Bits to Message Object. Note: If IFxCMR.TxRqst/NewDat bit is set, bits IFxMCTR.TxRqst and IFxMCTR.NewDat will be ignored. Read Direction: 0= Control Bits unchanged. 1= transfer Control Bits to IFxMCTR Register."]
pub type ControlR = crate::BitReader;
#[doc = "Field `Control` writer - Write Direction: 0= Control Bits unchanged. 1= transfer Control Bits to Message Object. Note: If IFxCMR.TxRqst/NewDat bit is set, bits IFxMCTR.TxRqst and IFxMCTR.NewDat will be ignored. Read Direction: 0= Control Bits unchanged. 1= transfer Control Bits to IFxMCTR Register."]
pub type ControlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `Arb` reader - Write Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to Message Object. Read Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to IFxARB Register."]
pub type ArbR = crate::BitReader;
#[doc = "Field `Arb` writer - Write Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to Message Object. Read Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to IFxARB Register."]
pub type ArbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `Mask` reader - Write Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to Message Object. Read Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to IFxMSK Register."]
pub type MaskR = crate::BitReader;
#[doc = "Field `Mask` writer - Write Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to Message Object. Read Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to IFxMSK Register."]
pub type MaskW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Write / Read Transfer\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wr1rd0 {
    #[doc = "0: `0`"]
    Read = 0,
    #[doc = "1: `1`"]
    Write = 1,
}
impl From<Wr1rd0> for bool {
    #[inline(always)]
    fn from(variant: Wr1rd0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `WR1RD0` reader - Write / Read Transfer"]
pub type Wr1rd0R = crate::BitReader<Wr1rd0>;
impl Wr1rd0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wr1rd0 {
        match self.bits {
            false => Wr1rd0::Read,
            true => Wr1rd0::Write,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_read(&self) -> bool {
        *self == Wr1rd0::Read
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_write(&self) -> bool {
        *self == Wr1rd0::Write
    }
}
#[doc = "Field `WR1RD0` writer - Write / Read Transfer"]
pub type Wr1rd0W<'a, REG> = crate::BitWriter<'a, REG, Wr1rd0>;
impl<'a, REG> Wr1rd0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn read(self) -> &'a mut crate::W<REG> {
        self.variant(Wr1rd0::Read)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn write(self) -> &'a mut crate::W<REG> {
        self.variant(Wr1rd0::Write)
    }
}
#[doc = "Clear the AutoInc bit without starting a transfer\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClrAutoInc {
    #[doc = "0: `0`"]
    NoClear = 0,
    #[doc = "1: `1`"]
    Clear = 1,
}
impl From<ClrAutoInc> for bool {
    #[inline(always)]
    fn from(variant: ClrAutoInc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ClrAutoInc` reader - Clear the AutoInc bit without starting a transfer"]
pub type ClrAutoIncR = crate::BitReader<ClrAutoInc>;
impl ClrAutoIncR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ClrAutoInc {
        match self.bits {
            false => ClrAutoInc::NoClear,
            true => ClrAutoInc::Clear,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_clear(&self) -> bool {
        *self == ClrAutoInc::NoClear
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clear(&self) -> bool {
        *self == ClrAutoInc::Clear
    }
}
#[doc = "Field `ClrAutoInc` writer - Clear the AutoInc bit without starting a transfer"]
pub type ClrAutoIncW<'a, REG> = crate::BitWriter<'a, REG, ClrAutoInc>;
impl<'a, REG> ClrAutoIncW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_clear(self) -> &'a mut crate::W<REG> {
        self.variant(ClrAutoInc::NoClear)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clear(self) -> &'a mut crate::W<REG> {
        self.variant(ClrAutoInc::Clear)
    }
}
impl R {
    #[doc = "Bits 0:7 - 0x01-0x80 Valid Message Number, the Message Object in the Message RAM is selected for data transfer (up to 128 MsgObj). 0x00 Not a valid Message Number, interpreted as 0x80. 0x81-0xFF Not a valid Message Number, interpreted as 0x01-0x7F. Note: When an invalid Message Number is written to IFxCMR.MONum which is higher than the last Message Object number, a modulo addressing will occur.When e.g. accessing Message Object 33 in a CAN module with 32 Message Objects only, the Message Object 1 will be accessed instead."]
    #[inline(always)]
    pub fn monum(&self) -> MonumR {
        MonumR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 13 - Automatic Increment of Message Object Number The behavior of the Message Object Number increment depends on the Transfer Direction, IFxCMR.WR1RD0. * Read: The first transfer will be initiated (Busy Bit will set) at write of IFxCMR.MONum. The Message Object Number will be incremented and the next Message Object will be transferred from Message Object RAM to Interface Registers after a read access of Data-Byte 7. * Write: The first as well as each other transfer will be started after write access to Data- Byte7. The Message Object Number will be incremented after successful transfer from the Interface Registers to the Message Object RAM. Always after successful transfer the Busy Bit will be reset. In combination with DMAactive the port CAN_IFxDMA is set, too. Note: If the direction is configured as Read a write access to Data-Byte 7 will not start any transfer, as well as if the direction is configured as Write a read access to Data-Byte 7 will not start any transfer. At transfer direction Read each read of Data-Byte 7 will start a transfer until IFxCMR.AutoInc is reset. To aware of resetting a NewDat bit of the following message object, the application has to reset IFxCMR.AutoInc before reading the Data-Byte 7 of the last message object which will be read."]
    #[inline(always)]
    pub fn auto_inc(&self) -> AutoIncR {
        AutoIncR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Activation of DMA feature for subsequent internal IFx Register Set"]
    #[inline(always)]
    pub fn dmaactive(&self) -> DmaactiveR {
        DmaactiveR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Busy Flag"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Write Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to Message Object. Read Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to IFxDB. Note: The speed of the message transfer does not depend on how many bytes are transferred."]
    #[inline(always)]
    pub fn data_b(&self) -> DataBR {
        DataBR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Write Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to Message Object. Read Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to IFxDA."]
    #[inline(always)]
    pub fn data_a(&self) -> DataAR {
        DataAR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Write Direction: 0= TxRqst and NewDat bit will be handled according IFxMCTR.NewDat bit and IFxMCTR.TxRqst bit. 1= set TxRqst and NewDat in Message Object to one Note: If a CAN transmission is requested by setting IFxCMR.TxRqst/NewDat, the TxRqst and NewDat bits in the Message Object will be set to one independently of the values in IFxMCTR. Read Direction: 0= NewDat bit remains unchanged. 1= clear NewDat bit in the Message Object. Note: A read access to a Message Object can be combined with the reset of the control bits IntPnd and NewDat. The values of these bits transferred to the IFxMCTR always reflect the status before resetting them."]
    #[inline(always)]
    pub fn tx_rqst_new_dat(&self) -> TxRqstNewDatR {
        TxRqstNewDatR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Write Direction: Has no influence to Message Object at write transfer. Note: When writing to a Message Object, this bit is ignored and copying of IntPnd flag from IFx Control Register to Message RAM could only be controlled by IFxMTR.IntPnd bit. Read Direction: 0= IntPnd bit remains unchanged. 1= clear IntPnd bit in the Message Object."]
    #[inline(always)]
    pub fn clr_int_pnd(&self) -> ClrIntPndR {
        ClrIntPndR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Write Direction: 0= Control Bits unchanged. 1= transfer Control Bits to Message Object. Note: If IFxCMR.TxRqst/NewDat bit is set, bits IFxMCTR.TxRqst and IFxMCTR.NewDat will be ignored. Read Direction: 0= Control Bits unchanged. 1= transfer Control Bits to IFxMCTR Register."]
    #[inline(always)]
    pub fn control(&self) -> ControlR {
        ControlR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Write Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to Message Object. Read Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to IFxARB Register."]
    #[inline(always)]
    pub fn arb(&self) -> ArbR {
        ArbR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Write Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to Message Object. Read Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to IFxMSK Register."]
    #[inline(always)]
    pub fn mask(&self) -> MaskR {
        MaskR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Write / Read Transfer"]
    #[inline(always)]
    pub fn wr1rd0(&self) -> Wr1rd0R {
        Wr1rd0R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 29 - Clear the AutoInc bit without starting a transfer"]
    #[inline(always)]
    pub fn clr_auto_inc(&self) -> ClrAutoIncR {
        ClrAutoIncR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - 0x01-0x80 Valid Message Number, the Message Object in the Message RAM is selected for data transfer (up to 128 MsgObj). 0x00 Not a valid Message Number, interpreted as 0x80. 0x81-0xFF Not a valid Message Number, interpreted as 0x01-0x7F. Note: When an invalid Message Number is written to IFxCMR.MONum which is higher than the last Message Object number, a modulo addressing will occur.When e.g. accessing Message Object 33 in a CAN module with 32 Message Objects only, the Message Object 1 will be accessed instead."]
    #[inline(always)]
    #[must_use]
    pub fn monum(&mut self) -> MonumW<MsgifgrpIf2cmrSpec> {
        MonumW::new(self, 0)
    }
    #[doc = "Bit 13 - Automatic Increment of Message Object Number The behavior of the Message Object Number increment depends on the Transfer Direction, IFxCMR.WR1RD0. * Read: The first transfer will be initiated (Busy Bit will set) at write of IFxCMR.MONum. The Message Object Number will be incremented and the next Message Object will be transferred from Message Object RAM to Interface Registers after a read access of Data-Byte 7. * Write: The first as well as each other transfer will be started after write access to Data- Byte7. The Message Object Number will be incremented after successful transfer from the Interface Registers to the Message Object RAM. Always after successful transfer the Busy Bit will be reset. In combination with DMAactive the port CAN_IFxDMA is set, too. Note: If the direction is configured as Read a write access to Data-Byte 7 will not start any transfer, as well as if the direction is configured as Write a read access to Data-Byte 7 will not start any transfer. At transfer direction Read each read of Data-Byte 7 will start a transfer until IFxCMR.AutoInc is reset. To aware of resetting a NewDat bit of the following message object, the application has to reset IFxCMR.AutoInc before reading the Data-Byte 7 of the last message object which will be read."]
    #[inline(always)]
    #[must_use]
    pub fn auto_inc(&mut self) -> AutoIncW<MsgifgrpIf2cmrSpec> {
        AutoIncW::new(self, 13)
    }
    #[doc = "Bit 14 - Activation of DMA feature for subsequent internal IFx Register Set"]
    #[inline(always)]
    #[must_use]
    pub fn dmaactive(&mut self) -> DmaactiveW<MsgifgrpIf2cmrSpec> {
        DmaactiveW::new(self, 14)
    }
    #[doc = "Bit 15 - Busy Flag"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<MsgifgrpIf2cmrSpec> {
        BusyW::new(self, 15)
    }
    #[doc = "Bit 16 - Write Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to Message Object. Read Direction: 0= Data Bytes 4-7 unchanged. 1= transfer Data Bytes 4-7 to IFxDB. Note: The speed of the message transfer does not depend on how many bytes are transferred."]
    #[inline(always)]
    #[must_use]
    pub fn data_b(&mut self) -> DataBW<MsgifgrpIf2cmrSpec> {
        DataBW::new(self, 16)
    }
    #[doc = "Bit 17 - Write Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to Message Object. Read Direction: 0= Data Bytes 0-3 unchanged. 1= transfer Data Bytes 0-3 to IFxDA."]
    #[inline(always)]
    #[must_use]
    pub fn data_a(&mut self) -> DataAW<MsgifgrpIf2cmrSpec> {
        DataAW::new(self, 17)
    }
    #[doc = "Bit 18 - Write Direction: 0= TxRqst and NewDat bit will be handled according IFxMCTR.NewDat bit and IFxMCTR.TxRqst bit. 1= set TxRqst and NewDat in Message Object to one Note: If a CAN transmission is requested by setting IFxCMR.TxRqst/NewDat, the TxRqst and NewDat bits in the Message Object will be set to one independently of the values in IFxMCTR. Read Direction: 0= NewDat bit remains unchanged. 1= clear NewDat bit in the Message Object. Note: A read access to a Message Object can be combined with the reset of the control bits IntPnd and NewDat. The values of these bits transferred to the IFxMCTR always reflect the status before resetting them."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_new_dat(&mut self) -> TxRqstNewDatW<MsgifgrpIf2cmrSpec> {
        TxRqstNewDatW::new(self, 18)
    }
    #[doc = "Bit 19 - Write Direction: Has no influence to Message Object at write transfer. Note: When writing to a Message Object, this bit is ignored and copying of IntPnd flag from IFx Control Register to Message RAM could only be controlled by IFxMTR.IntPnd bit. Read Direction: 0= IntPnd bit remains unchanged. 1= clear IntPnd bit in the Message Object."]
    #[inline(always)]
    #[must_use]
    pub fn clr_int_pnd(&mut self) -> ClrIntPndW<MsgifgrpIf2cmrSpec> {
        ClrIntPndW::new(self, 19)
    }
    #[doc = "Bit 20 - Write Direction: 0= Control Bits unchanged. 1= transfer Control Bits to Message Object. Note: If IFxCMR.TxRqst/NewDat bit is set, bits IFxMCTR.TxRqst and IFxMCTR.NewDat will be ignored. Read Direction: 0= Control Bits unchanged. 1= transfer Control Bits to IFxMCTR Register."]
    #[inline(always)]
    #[must_use]
    pub fn control(&mut self) -> ControlW<MsgifgrpIf2cmrSpec> {
        ControlW::new(self, 20)
    }
    #[doc = "Bit 21 - Write Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to Message Object. Read Direction: 0= Arbitration bits unchanged. 1= transfer Identifier + Dir + Xtd + MsgVal to IFxARB Register."]
    #[inline(always)]
    #[must_use]
    pub fn arb(&mut self) -> ArbW<MsgifgrpIf2cmrSpec> {
        ArbW::new(self, 21)
    }
    #[doc = "Bit 22 - Write Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to Message Object. Read Direction: 0= Mask bits unchanged. 1= transfer Identifier Mask + MDir + MXtd to IFxMSK Register."]
    #[inline(always)]
    #[must_use]
    pub fn mask(&mut self) -> MaskW<MsgifgrpIf2cmrSpec> {
        MaskW::new(self, 22)
    }
    #[doc = "Bit 23 - Write / Read Transfer"]
    #[inline(always)]
    #[must_use]
    pub fn wr1rd0(&mut self) -> Wr1rd0W<MsgifgrpIf2cmrSpec> {
        Wr1rd0W::new(self, 23)
    }
    #[doc = "Bit 29 - Clear the AutoInc bit without starting a transfer"]
    #[inline(always)]
    #[must_use]
    pub fn clr_auto_inc(&mut self) -> ClrAutoIncW<MsgifgrpIf2cmrSpec> {
        ClrAutoIncW::new(self, 29)
    }
}
#[doc = "The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2cmr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2cmr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsgifgrpIf2cmrSpec;
impl crate::RegisterSpec for MsgifgrpIf2cmrSpec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`msgifgrp_if2cmr::R`](R) reader structure"]
impl crate::Readable for MsgifgrpIf2cmrSpec {}
#[doc = "`write(|w| ..)` method takes [`msgifgrp_if2cmr::W`](W) writer structure"]
impl crate::Writable for MsgifgrpIf2cmrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets msgifgrp_IF2CMR to value 0x01"]
impl crate::Resettable for MsgifgrpIf2cmrSpec {
    const RESET_VALUE: u32 = 0x01;
}
