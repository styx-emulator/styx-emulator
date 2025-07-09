// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `stat` reader"]
pub type R = crate::R<StatSpec>;
#[doc = "Register `stat` writer"]
pub type W = crate::W<StatSpec>;
#[doc = "Specifies the value of the nTRST signal driven to the FPGA JTAG only. The FPGA JTAG scan-chain must be enabled via the EN register to drive the value specified in this field. The nTRST signal is driven with the inverted value of this field.The nTRST signal is active low so, when this bit is set to 1, FPGA JTAG is reset. The name of this field in ARM documentation is TRST_OUT.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trst {
    #[doc = "0: `0`"]
    DontResetFpgaJtag = 0,
    #[doc = "1: `1`"]
    ResetFpgaJtag = 1,
}
impl From<Trst> for bool {
    #[inline(always)]
    fn from(variant: Trst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `trst` reader - Specifies the value of the nTRST signal driven to the FPGA JTAG only. The FPGA JTAG scan-chain must be enabled via the EN register to drive the value specified in this field. The nTRST signal is driven with the inverted value of this field.The nTRST signal is active low so, when this bit is set to 1, FPGA JTAG is reset. The name of this field in ARM documentation is TRST_OUT."]
pub type TrstR = crate::BitReader<Trst>;
impl TrstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Trst {
        match self.bits {
            false => Trst::DontResetFpgaJtag,
            true => Trst::ResetFpgaJtag,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dont_reset_fpga_jtag(&self) -> bool {
        *self == Trst::DontResetFpgaJtag
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_reset_fpga_jtag(&self) -> bool {
        *self == Trst::ResetFpgaJtag
    }
}
#[doc = "Field `trst` writer - Specifies the value of the nTRST signal driven to the FPGA JTAG only. The FPGA JTAG scan-chain must be enabled via the EN register to drive the value specified in this field. The nTRST signal is driven with the inverted value of this field.The nTRST signal is active low so, when this bit is set to 1, FPGA JTAG is reset. The name of this field in ARM documentation is TRST_OUT."]
pub type TrstW<'a, REG> = crate::BitWriter<'a, REG, Trst>;
impl<'a, REG> TrstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn dont_reset_fpga_jtag(self) -> &'a mut crate::W<REG> {
        self.variant(Trst::DontResetFpgaJtag)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset_fpga_jtag(self) -> &'a mut crate::W<REG> {
        self.variant(Trst::ResetFpgaJtag)
    }
}
#[doc = "Field `ignore` reader - Ignore this field. Its value is undefined (may be 0 or 1). The name of this field in ARM documentation is PORTCONNECTED."]
pub type IgnoreR = crate::BitReader;
#[doc = "Field `ignore` writer - Ignore this field. Its value is undefined (may be 0 or 1). The name of this field in ARM documentation is PORTCONNECTED."]
pub type IgnoreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rfifocnt` reader - Response FIFO outstanding byte count. Returns the number of bytes of response data available in the Response FIFO."]
pub type RfifocntR = crate::FieldReader;
#[doc = "Field `rfifocnt` writer - Response FIFO outstanding byte count. Returns the number of bytes of response data available in the Response FIFO."]
pub type RfifocntW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `wfifocnt` reader - Command FIFO outstanding byte count. Returns the number of command bytes held in the Command FIFO that have yet to be processed by the Scan-Chain Engine."]
pub type WfifocntR = crate::FieldReader;
#[doc = "Field `wfifocnt` writer - Command FIFO outstanding byte count. Returns the number of command bytes held in the Command FIFO that have yet to be processed by the Scan-Chain Engine."]
pub type WfifocntW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Indicates if the Scan-Chain Engine is processing commands from the Command FIFO or not. The Scan-Chain Engine is only guaranteed to be inactive if both the ACTIVE and WFIFOCNT fields are zero. The name of this field in ARM documentation is SERACTV.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Active {
    #[doc = "0: `0`"]
    PossiblyInactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Active> for bool {
    #[inline(always)]
    fn from(variant: Active) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `active` reader - Indicates if the Scan-Chain Engine is processing commands from the Command FIFO or not. The Scan-Chain Engine is only guaranteed to be inactive if both the ACTIVE and WFIFOCNT fields are zero. The name of this field in ARM documentation is SERACTV."]
pub type ActiveR = crate::BitReader<Active>;
impl ActiveR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Active {
        match self.bits {
            false => Active::PossiblyInactive,
            true => Active::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_possibly_inactive(&self) -> bool {
        *self == Active::PossiblyInactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Active::Active
    }
}
#[doc = "Field `active` writer - Indicates if the Scan-Chain Engine is processing commands from the Command FIFO or not. The Scan-Chain Engine is only guaranteed to be inactive if both the ACTIVE and WFIFOCNT fields are zero. The name of this field in ARM documentation is SERACTV."]
pub type ActiveW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - Specifies the value of the nTRST signal driven to the FPGA JTAG only. The FPGA JTAG scan-chain must be enabled via the EN register to drive the value specified in this field. The nTRST signal is driven with the inverted value of this field.The nTRST signal is active low so, when this bit is set to 1, FPGA JTAG is reset. The name of this field in ARM documentation is TRST_OUT."]
    #[inline(always)]
    pub fn trst(&self) -> TrstR {
        TrstR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Ignore this field. Its value is undefined (may be 0 or 1). The name of this field in ARM documentation is PORTCONNECTED."]
    #[inline(always)]
    pub fn ignore(&self) -> IgnoreR {
        IgnoreR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 24:26 - Response FIFO outstanding byte count. Returns the number of bytes of response data available in the Response FIFO."]
    #[inline(always)]
    pub fn rfifocnt(&self) -> RfifocntR {
        RfifocntR::new(((self.bits >> 24) & 7) as u8)
    }
    #[doc = "Bits 28:30 - Command FIFO outstanding byte count. Returns the number of command bytes held in the Command FIFO that have yet to be processed by the Scan-Chain Engine."]
    #[inline(always)]
    pub fn wfifocnt(&self) -> WfifocntR {
        WfifocntR::new(((self.bits >> 28) & 7) as u8)
    }
    #[doc = "Bit 31 - Indicates if the Scan-Chain Engine is processing commands from the Command FIFO or not. The Scan-Chain Engine is only guaranteed to be inactive if both the ACTIVE and WFIFOCNT fields are zero. The name of this field in ARM documentation is SERACTV."]
    #[inline(always)]
    pub fn active(&self) -> ActiveR {
        ActiveR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - Specifies the value of the nTRST signal driven to the FPGA JTAG only. The FPGA JTAG scan-chain must be enabled via the EN register to drive the value specified in this field. The nTRST signal is driven with the inverted value of this field.The nTRST signal is active low so, when this bit is set to 1, FPGA JTAG is reset. The name of this field in ARM documentation is TRST_OUT."]
    #[inline(always)]
    #[must_use]
    pub fn trst(&mut self) -> TrstW<StatSpec> {
        TrstW::new(self, 1)
    }
    #[doc = "Bit 3 - Ignore this field. Its value is undefined (may be 0 or 1). The name of this field in ARM documentation is PORTCONNECTED."]
    #[inline(always)]
    #[must_use]
    pub fn ignore(&mut self) -> IgnoreW<StatSpec> {
        IgnoreW::new(self, 3)
    }
    #[doc = "Bits 24:26 - Response FIFO outstanding byte count. Returns the number of bytes of response data available in the Response FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rfifocnt(&mut self) -> RfifocntW<StatSpec> {
        RfifocntW::new(self, 24)
    }
    #[doc = "Bits 28:30 - Command FIFO outstanding byte count. Returns the number of command bytes held in the Command FIFO that have yet to be processed by the Scan-Chain Engine."]
    #[inline(always)]
    #[must_use]
    pub fn wfifocnt(&mut self) -> WfifocntW<StatSpec> {
        WfifocntW::new(self, 28)
    }
    #[doc = "Bit 31 - Indicates if the Scan-Chain Engine is processing commands from the Command FIFO or not. The Scan-Chain Engine is only guaranteed to be inactive if both the ACTIVE and WFIFOCNT fields are zero. The name of this field in ARM documentation is SERACTV."]
    #[inline(always)]
    #[must_use]
    pub fn active(&mut self) -> ActiveW<StatSpec> {
        ActiveW::new(self, 31)
    }
}
#[doc = "Consist of control bit and status information.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stat::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatSpec;
impl crate::RegisterSpec for StatSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`stat::R`](R) reader structure"]
impl crate::Readable for StatSpec {}
#[doc = "`write(|w| ..)` method takes [`stat::W`](W) writer structure"]
impl crate::Writable for StatSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets stat to value 0"]
impl crate::Resettable for StatSpec {
    const RESET_VALUE: u32 = 0;
}
