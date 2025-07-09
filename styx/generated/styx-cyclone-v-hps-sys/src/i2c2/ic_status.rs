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
#[doc = "Register `ic_status` reader"]
pub type R = crate::R<IcStatusSpec>;
#[doc = "Register `ic_status` writer"]
pub type W = crate::W<IcStatusSpec>;
#[doc = "Field `activity` reader - I2C Activity."]
pub type ActivityR = crate::BitReader;
#[doc = "Field `activity` writer - I2C Activity."]
pub type ActivityW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmit Fifo Full\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tfnf {
    #[doc = "0: `0`"]
    Full = 0,
    #[doc = "1: `1`"]
    Notfull = 1,
}
impl From<Tfnf> for bool {
    #[inline(always)]
    fn from(variant: Tfnf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tfnf` reader - Transmit Fifo Full"]
pub type TfnfR = crate::BitReader<Tfnf>;
impl TfnfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tfnf {
        match self.bits {
            false => Tfnf::Full,
            true => Tfnf::Notfull,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Tfnf::Full
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Tfnf::Notfull
    }
}
#[doc = "Field `tfnf` writer - Transmit Fifo Full"]
pub type TfnfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmit FIFO Empty.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tfe {
    #[doc = "0: `0`"]
    Notempty = 0,
    #[doc = "1: `1`"]
    Empty = 1,
}
impl From<Tfe> for bool {
    #[inline(always)]
    fn from(variant: Tfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tfe` reader - Transmit FIFO Empty."]
pub type TfeR = crate::BitReader<Tfe>;
impl TfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tfe {
        match self.bits {
            false => Tfe::Notempty,
            true => Tfe::Empty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notempty(&self) -> bool {
        *self == Tfe::Notempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Tfe::Empty
    }
}
#[doc = "Field `tfe` writer - Transmit FIFO Empty."]
pub type TfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Receive FIFO Not Empty.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rfne {
    #[doc = "0: `0`"]
    Empty = 0,
    #[doc = "1: `1`"]
    Notempty = 1,
}
impl From<Rfne> for bool {
    #[inline(always)]
    fn from(variant: Rfne) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rfne` reader - Receive FIFO Not Empty."]
pub type RfneR = crate::BitReader<Rfne>;
impl RfneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rfne {
        match self.bits {
            false => Rfne::Empty,
            true => Rfne::Notempty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Rfne::Empty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notempty(&self) -> bool {
        *self == Rfne::Notempty
    }
}
#[doc = "Field `rfne` writer - Receive FIFO Not Empty."]
pub type RfneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Receive FIFO Completely Full.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rff {
    #[doc = "0: `0`"]
    Notfull = 0,
    #[doc = "1: `1`"]
    Full = 1,
}
impl From<Rff> for bool {
    #[inline(always)]
    fn from(variant: Rff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rff` reader - Receive FIFO Completely Full."]
pub type RffR = crate::BitReader<Rff>;
impl RffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rff {
        match self.bits {
            false => Rff::Notfull,
            true => Rff::Full,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Rff::Notfull
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Rff::Full
    }
}
#[doc = "Field `rff` writer - Receive FIFO Completely Full."]
pub type RffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When the Master Finite State Machine (FSM) is not in the IDLE state, this bit is set. Note:IC_STATUS\\[0\\]-that is, ACTIVITY bit-is the OR of SLV_ACTIVITY and MST_ACTIVITY bits.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MstActivity {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    Notidle = 1,
}
impl From<MstActivity> for bool {
    #[inline(always)]
    fn from(variant: MstActivity) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mst_activity` reader - When the Master Finite State Machine (FSM) is not in the IDLE state, this bit is set. Note:IC_STATUS\\[0\\]-that is, ACTIVITY bit-is the OR of SLV_ACTIVITY and MST_ACTIVITY bits."]
pub type MstActivityR = crate::BitReader<MstActivity>;
impl MstActivityR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MstActivity {
        match self.bits {
            false => MstActivity::Idle,
            true => MstActivity::Notidle,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == MstActivity::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notidle(&self) -> bool {
        *self == MstActivity::Notidle
    }
}
#[doc = "Field `mst_activity` writer - When the Master Finite State Machine (FSM) is not in the IDLE state, this bit is set. Note:IC_STATUS\\[0\\]-that is, ACTIVITY bit-is the OR of SLV_ACTIVITY and MST_ACTIVITY bits."]
pub type MstActivityW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Slave FSM Activity Status. When the Slave Finite State Machine (FSM) is not in the IDLE state, this bit is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlvActivity {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    Notidle = 1,
}
impl From<SlvActivity> for bool {
    #[inline(always)]
    fn from(variant: SlvActivity) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `slv_activity` reader - Slave FSM Activity Status. When the Slave Finite State Machine (FSM) is not in the IDLE state, this bit is set."]
pub type SlvActivityR = crate::BitReader<SlvActivity>;
impl SlvActivityR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SlvActivity {
        match self.bits {
            false => SlvActivity::Idle,
            true => SlvActivity::Notidle,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == SlvActivity::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notidle(&self) -> bool {
        *self == SlvActivity::Notidle
    }
}
#[doc = "Field `slv_activity` writer - Slave FSM Activity Status. When the Slave Finite State Machine (FSM) is not in the IDLE state, this bit is set."]
pub type SlvActivityW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - I2C Activity."]
    #[inline(always)]
    pub fn activity(&self) -> ActivityR {
        ActivityR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Transmit Fifo Full"]
    #[inline(always)]
    pub fn tfnf(&self) -> TfnfR {
        TfnfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transmit FIFO Empty."]
    #[inline(always)]
    pub fn tfe(&self) -> TfeR {
        TfeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Receive FIFO Not Empty."]
    #[inline(always)]
    pub fn rfne(&self) -> RfneR {
        RfneR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Receive FIFO Completely Full."]
    #[inline(always)]
    pub fn rff(&self) -> RffR {
        RffR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When the Master Finite State Machine (FSM) is not in the IDLE state, this bit is set. Note:IC_STATUS\\[0\\]-that is, ACTIVITY bit-is the OR of SLV_ACTIVITY and MST_ACTIVITY bits."]
    #[inline(always)]
    pub fn mst_activity(&self) -> MstActivityR {
        MstActivityR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Slave FSM Activity Status. When the Slave Finite State Machine (FSM) is not in the IDLE state, this bit is set."]
    #[inline(always)]
    pub fn slv_activity(&self) -> SlvActivityR {
        SlvActivityR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - I2C Activity."]
    #[inline(always)]
    #[must_use]
    pub fn activity(&mut self) -> ActivityW<IcStatusSpec> {
        ActivityW::new(self, 0)
    }
    #[doc = "Bit 1 - Transmit Fifo Full"]
    #[inline(always)]
    #[must_use]
    pub fn tfnf(&mut self) -> TfnfW<IcStatusSpec> {
        TfnfW::new(self, 1)
    }
    #[doc = "Bit 2 - Transmit FIFO Empty."]
    #[inline(always)]
    #[must_use]
    pub fn tfe(&mut self) -> TfeW<IcStatusSpec> {
        TfeW::new(self, 2)
    }
    #[doc = "Bit 3 - Receive FIFO Not Empty."]
    #[inline(always)]
    #[must_use]
    pub fn rfne(&mut self) -> RfneW<IcStatusSpec> {
        RfneW::new(self, 3)
    }
    #[doc = "Bit 4 - Receive FIFO Completely Full."]
    #[inline(always)]
    #[must_use]
    pub fn rff(&mut self) -> RffW<IcStatusSpec> {
        RffW::new(self, 4)
    }
    #[doc = "Bit 5 - When the Master Finite State Machine (FSM) is not in the IDLE state, this bit is set. Note:IC_STATUS\\[0\\]-that is, ACTIVITY bit-is the OR of SLV_ACTIVITY and MST_ACTIVITY bits."]
    #[inline(always)]
    #[must_use]
    pub fn mst_activity(&mut self) -> MstActivityW<IcStatusSpec> {
        MstActivityW::new(self, 5)
    }
    #[doc = "Bit 6 - Slave FSM Activity Status. When the Slave Finite State Machine (FSM) is not in the IDLE state, this bit is set."]
    #[inline(always)]
    #[must_use]
    pub fn slv_activity(&mut self) -> SlvActivityW<IcStatusSpec> {
        SlvActivityW::new(self, 6)
    }
}
#[doc = "This is a read-only register used to indicate the current transfer status and FIFO status. The status register may be read at any time. None of the bits in this register request an interrupt.When the I2C is disabled by writing 0 in bit 0 of the ic_enable register: - Bits 1 and 2 are set to 1 - Bits 3 and 4 are set to 0 When the master or slave state machines goes to idle - Bits 5 and 6 are set to 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcStatusSpec;
impl crate::RegisterSpec for IcStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`ic_status::R`](R) reader structure"]
impl crate::Readable for IcStatusSpec {}
#[doc = "`reset()` method sets ic_status to value 0x06"]
impl crate::Resettable for IcStatusSpec {
    const RESET_VALUE: u32 = 0x06;
}
