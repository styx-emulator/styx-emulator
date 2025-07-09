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
#[doc = "Register `idsts` reader"]
pub type R = crate::R<IdstsSpec>;
#[doc = "Register `idsts` writer"]
pub type W = crate::W<IdstsSpec>;
#[doc = "Indicates that data transmission is finished for a descriptor.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ti {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Ti> for bool {
    #[inline(always)]
    fn from(variant: Ti) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ti` reader - Indicates that data transmission is finished for a descriptor."]
pub type TiR = crate::BitReader<Ti>;
impl TiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ti {
        match self.bits {
            true => Ti::Clr,
            false => Ti::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Ti::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Ti::Noclr
    }
}
#[doc = "Field `ti` writer - Indicates that data transmission is finished for a descriptor."]
pub type TiW<'a, REG> = crate::BitWriter1C<'a, REG, Ti>;
impl<'a, REG> TiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ti::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ti::Noclr)
    }
}
#[doc = "Indicates the completion of data reception for a descriptor\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ri {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Ri> for bool {
    #[inline(always)]
    fn from(variant: Ri) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ri` reader - Indicates the completion of data reception for a descriptor"]
pub type RiR = crate::BitReader<Ri>;
impl RiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ri {
        match self.bits {
            true => Ri::Clr,
            false => Ri::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Ri::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Ri::Noclr
    }
}
#[doc = "Field `ri` writer - Indicates the completion of data reception for a descriptor"]
pub type RiW<'a, REG> = crate::BitWriter1C<'a, REG, Ri>;
impl<'a, REG> RiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ri::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ri::Noclr)
    }
}
#[doc = "Indicates that a Bus Error occurred (IDSTS\\[12:10\\]). When setthe DMA disables all its bus accesses.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fbe {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Fbe> for bool {
    #[inline(always)]
    fn from(variant: Fbe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fbe` reader - Indicates that a Bus Error occurred (IDSTS\\[12:10\\]). When setthe DMA disables all its bus accesses."]
pub type FbeR = crate::BitReader<Fbe>;
impl FbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fbe {
        match self.bits {
            true => Fbe::Clr,
            false => Fbe::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Fbe::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Fbe::Noclr
    }
}
#[doc = "Field `fbe` writer - Indicates that a Bus Error occurred (IDSTS\\[12:10\\]). When setthe DMA disables all its bus accesses."]
pub type FbeW<'a, REG> = crate::BitWriter1C<'a, REG, Fbe>;
impl<'a, REG> FbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Fbe::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Fbe::Noclr)
    }
}
#[doc = "This status bit is set when the descriptor is unavailable due to OWN bit = 0 (DES0\\[31\\]
=0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Du {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Du> for bool {
    #[inline(always)]
    fn from(variant: Du) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `du` reader - This status bit is set when the descriptor is unavailable due to OWN bit = 0 (DES0\\[31\\]
=0)."]
pub type DuR = crate::BitReader<Du>;
impl DuR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Du {
        match self.bits {
            true => Du::Clr,
            false => Du::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Du::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Du::Noclr
    }
}
#[doc = "Field `du` writer - This status bit is set when the descriptor is unavailable due to OWN bit = 0 (DES0\\[31\\]
=0)."]
pub type DuW<'a, REG> = crate::BitWriter1C<'a, REG, Du>;
impl<'a, REG> DuW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Du::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Du::Noclr)
    }
}
#[doc = "Indicates the status of the transaction to/from the card; also present in RINTSTS. Indicates the logical OR of the following bits: EBE - End Bit Error RTO - Response Timeout/Boot Ack Timeout RCRC - Response CRC SBE - Start Bit Error DRTO - Data Read Timeout/BDS timeout DCRC - Data CRC for Receive RE - Response Error\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ces {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Ces> for bool {
    #[inline(always)]
    fn from(variant: Ces) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ces` reader - Indicates the status of the transaction to/from the card; also present in RINTSTS. Indicates the logical OR of the following bits: EBE - End Bit Error RTO - Response Timeout/Boot Ack Timeout RCRC - Response CRC SBE - Start Bit Error DRTO - Data Read Timeout/BDS timeout DCRC - Data CRC for Receive RE - Response Error"]
pub type CesR = crate::BitReader<Ces>;
impl CesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ces {
        match self.bits {
            true => Ces::Clr,
            false => Ces::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Ces::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Ces::Noclr
    }
}
#[doc = "Field `ces` writer - Indicates the status of the transaction to/from the card; also present in RINTSTS. Indicates the logical OR of the following bits: EBE - End Bit Error RTO - Response Timeout/Boot Ack Timeout RCRC - Response CRC SBE - Start Bit Error DRTO - Data Read Timeout/BDS timeout DCRC - Data CRC for Receive RE - Response Error"]
pub type CesW<'a, REG> = crate::BitWriter1C<'a, REG, Ces>;
impl<'a, REG> CesW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ces::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ces::Noclr)
    }
}
#[doc = "Logical OR of the following: IDSTS\\[0\\]
- Transmit Interrupt IDSTS\\[1\\]
- Receive Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes NIS to be set is cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nis {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Nis> for bool {
    #[inline(always)]
    fn from(variant: Nis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nis` reader - Logical OR of the following: IDSTS\\[0\\]
- Transmit Interrupt IDSTS\\[1\\]
- Receive Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes NIS to be set is cleared."]
pub type NisR = crate::BitReader<Nis>;
impl NisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nis {
        match self.bits {
            true => Nis::Clr,
            false => Nis::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Nis::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Nis::Noclr
    }
}
#[doc = "Field `nis` writer - Logical OR of the following: IDSTS\\[0\\]
- Transmit Interrupt IDSTS\\[1\\]
- Receive Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes NIS to be set is cleared."]
pub type NisW<'a, REG> = crate::BitWriter1C<'a, REG, Nis>;
impl<'a, REG> NisW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Nis::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Nis::Noclr)
    }
}
#[doc = "Logical OR of the following: IDSTS\\[2\\]
- Fatal Bus Interrupt IDSTS\\[4\\]
- DU bit Interrupt IDSTS\\[5\\]
- Card Error Summary Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes AIS to be set is cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ais {
    #[doc = "1: `1`"]
    Clr = 1,
    #[doc = "0: `0`"]
    Noclr = 0,
}
impl From<Ais> for bool {
    #[inline(always)]
    fn from(variant: Ais) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ais` reader - Logical OR of the following: IDSTS\\[2\\]
- Fatal Bus Interrupt IDSTS\\[4\\]
- DU bit Interrupt IDSTS\\[5\\]
- Card Error Summary Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes AIS to be set is cleared."]
pub type AisR = crate::BitReader<Ais>;
impl AisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ais {
        match self.bits {
            true => Ais::Clr,
            false => Ais::Noclr,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clr(&self) -> bool {
        *self == Ais::Clr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noclr(&self) -> bool {
        *self == Ais::Noclr
    }
}
#[doc = "Field `ais` writer - Logical OR of the following: IDSTS\\[2\\]
- Fatal Bus Interrupt IDSTS\\[4\\]
- DU bit Interrupt IDSTS\\[5\\]
- Card Error Summary Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes AIS to be set is cleared."]
pub type AisW<'a, REG> = crate::BitWriter1C<'a, REG, Ais>;
impl<'a, REG> AisW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ais::Clr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ais::Noclr)
    }
}
#[doc = "Indicates the type of error that caused a Bus Error. Valid only with Fatal Bus Error bit (IDSTS\\[2\\]) set. This field does not generate an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Eb {
    #[doc = "1: `1`"]
    Hostarbttx = 1,
    #[doc = "2: `10`"]
    Hostarbrx = 2,
}
impl From<Eb> for u8 {
    #[inline(always)]
    fn from(variant: Eb) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Eb {
    type Ux = u8;
}
#[doc = "Field `eb` reader - Indicates the type of error that caused a Bus Error. Valid only with Fatal Bus Error bit (IDSTS\\[2\\]) set. This field does not generate an interrupt."]
pub type EbR = crate::FieldReader<Eb>;
impl EbR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Eb> {
        match self.bits {
            1 => Some(Eb::Hostarbttx),
            2 => Some(Eb::Hostarbrx),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_hostarbttx(&self) -> bool {
        *self == Eb::Hostarbttx
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_hostarbrx(&self) -> bool {
        *self == Eb::Hostarbrx
    }
}
#[doc = "Field `eb` writer - Indicates the type of error that caused a Bus Error. Valid only with Fatal Bus Error bit (IDSTS\\[2\\]) set. This field does not generate an interrupt."]
pub type EbW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "DMAC FSM present state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fsm {
    #[doc = "0: `0`"]
    Dmaidle = 0,
    #[doc = "1: `1`"]
    Dmasuspend = 1,
    #[doc = "2: `10`"]
    Descrd = 2,
    #[doc = "3: `11`"]
    Descchk = 3,
    #[doc = "4: `100`"]
    Dmardreqwait = 4,
    #[doc = "5: `101`"]
    Dmawrreqwait = 5,
    #[doc = "6: `110`"]
    Dmard = 6,
    #[doc = "7: `111`"]
    Dmawr = 7,
    #[doc = "8: `1000`"]
    Decclose = 8,
}
impl From<Fsm> for u8 {
    #[inline(always)]
    fn from(variant: Fsm) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Fsm {
    type Ux = u8;
}
#[doc = "Field `fsm` reader - DMAC FSM present state."]
pub type FsmR = crate::FieldReader<Fsm>;
impl FsmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Fsm> {
        match self.bits {
            0 => Some(Fsm::Dmaidle),
            1 => Some(Fsm::Dmasuspend),
            2 => Some(Fsm::Descrd),
            3 => Some(Fsm::Descchk),
            4 => Some(Fsm::Dmardreqwait),
            5 => Some(Fsm::Dmawrreqwait),
            6 => Some(Fsm::Dmard),
            7 => Some(Fsm::Dmawr),
            8 => Some(Fsm::Decclose),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dmaidle(&self) -> bool {
        *self == Fsm::Dmaidle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dmasuspend(&self) -> bool {
        *self == Fsm::Dmasuspend
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_descrd(&self) -> bool {
        *self == Fsm::Descrd
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_descchk(&self) -> bool {
        *self == Fsm::Descchk
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_dmardreqwait(&self) -> bool {
        *self == Fsm::Dmardreqwait
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_dmawrreqwait(&self) -> bool {
        *self == Fsm::Dmawrreqwait
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_dmard(&self) -> bool {
        *self == Fsm::Dmard
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_dmawr(&self) -> bool {
        *self == Fsm::Dmawr
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_decclose(&self) -> bool {
        *self == Fsm::Decclose
    }
}
#[doc = "Field `fsm` writer - DMAC FSM present state."]
pub type FsmW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bit 0 - Indicates that data transmission is finished for a descriptor."]
    #[inline(always)]
    pub fn ti(&self) -> TiR {
        TiR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Indicates the completion of data reception for a descriptor"]
    #[inline(always)]
    pub fn ri(&self) -> RiR {
        RiR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Indicates that a Bus Error occurred (IDSTS\\[12:10\\]). When setthe DMA disables all its bus accesses."]
    #[inline(always)]
    pub fn fbe(&self) -> FbeR {
        FbeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - This status bit is set when the descriptor is unavailable due to OWN bit = 0 (DES0\\[31\\]
=0)."]
    #[inline(always)]
    pub fn du(&self) -> DuR {
        DuR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Indicates the status of the transaction to/from the card; also present in RINTSTS. Indicates the logical OR of the following bits: EBE - End Bit Error RTO - Response Timeout/Boot Ack Timeout RCRC - Response CRC SBE - Start Bit Error DRTO - Data Read Timeout/BDS timeout DCRC - Data CRC for Receive RE - Response Error"]
    #[inline(always)]
    pub fn ces(&self) -> CesR {
        CesR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - Logical OR of the following: IDSTS\\[0\\]
- Transmit Interrupt IDSTS\\[1\\]
- Receive Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes NIS to be set is cleared."]
    #[inline(always)]
    pub fn nis(&self) -> NisR {
        NisR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Logical OR of the following: IDSTS\\[2\\]
- Fatal Bus Interrupt IDSTS\\[4\\]
- DU bit Interrupt IDSTS\\[5\\]
- Card Error Summary Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes AIS to be set is cleared."]
    #[inline(always)]
    pub fn ais(&self) -> AisR {
        AisR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:12 - Indicates the type of error that caused a Bus Error. Valid only with Fatal Bus Error bit (IDSTS\\[2\\]) set. This field does not generate an interrupt."]
    #[inline(always)]
    pub fn eb(&self) -> EbR {
        EbR::new(((self.bits >> 10) & 7) as u8)
    }
    #[doc = "Bits 13:16 - DMAC FSM present state."]
    #[inline(always)]
    pub fn fsm(&self) -> FsmR {
        FsmR::new(((self.bits >> 13) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Indicates that data transmission is finished for a descriptor."]
    #[inline(always)]
    #[must_use]
    pub fn ti(&mut self) -> TiW<IdstsSpec> {
        TiW::new(self, 0)
    }
    #[doc = "Bit 1 - Indicates the completion of data reception for a descriptor"]
    #[inline(always)]
    #[must_use]
    pub fn ri(&mut self) -> RiW<IdstsSpec> {
        RiW::new(self, 1)
    }
    #[doc = "Bit 2 - Indicates that a Bus Error occurred (IDSTS\\[12:10\\]). When setthe DMA disables all its bus accesses."]
    #[inline(always)]
    #[must_use]
    pub fn fbe(&mut self) -> FbeW<IdstsSpec> {
        FbeW::new(self, 2)
    }
    #[doc = "Bit 4 - This status bit is set when the descriptor is unavailable due to OWN bit = 0 (DES0\\[31\\]
=0)."]
    #[inline(always)]
    #[must_use]
    pub fn du(&mut self) -> DuW<IdstsSpec> {
        DuW::new(self, 4)
    }
    #[doc = "Bit 5 - Indicates the status of the transaction to/from the card; also present in RINTSTS. Indicates the logical OR of the following bits: EBE - End Bit Error RTO - Response Timeout/Boot Ack Timeout RCRC - Response CRC SBE - Start Bit Error DRTO - Data Read Timeout/BDS timeout DCRC - Data CRC for Receive RE - Response Error"]
    #[inline(always)]
    #[must_use]
    pub fn ces(&mut self) -> CesW<IdstsSpec> {
        CesW::new(self, 5)
    }
    #[doc = "Bit 8 - Logical OR of the following: IDSTS\\[0\\]
- Transmit Interrupt IDSTS\\[1\\]
- Receive Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes NIS to be set is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn nis(&mut self) -> NisW<IdstsSpec> {
        NisW::new(self, 8)
    }
    #[doc = "Bit 9 - Logical OR of the following: IDSTS\\[2\\]
- Fatal Bus Interrupt IDSTS\\[4\\]
- DU bit Interrupt IDSTS\\[5\\]
- Card Error Summary Interrupt Only unmasked bits affect this bit. This is a sticky bit and must be cleared each time a corresponding bit that causes AIS to be set is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn ais(&mut self) -> AisW<IdstsSpec> {
        AisW::new(self, 9)
    }
    #[doc = "Bits 10:12 - Indicates the type of error that caused a Bus Error. Valid only with Fatal Bus Error bit (IDSTS\\[2\\]) set. This field does not generate an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn eb(&mut self) -> EbW<IdstsSpec> {
        EbW::new(self, 10)
    }
    #[doc = "Bits 13:16 - DMAC FSM present state."]
    #[inline(always)]
    #[must_use]
    pub fn fsm(&mut self) -> FsmW<IdstsSpec> {
        FsmW::new(self, 13)
    }
}
#[doc = "Sets Internal DMAC Status Fields\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idsts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`idsts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdstsSpec;
impl crate::RegisterSpec for IdstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`idsts::R`](R) reader structure"]
impl crate::Readable for IdstsSpec {}
#[doc = "`write(|w| ..)` method takes [`idsts::W`](W) writer structure"]
impl crate::Writable for IdstsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x0337;
}
#[doc = "`reset()` method sets idsts to value 0"]
impl crate::Resettable for IdstsSpec {
    const RESET_VALUE: u32 = 0;
}
