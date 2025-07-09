// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `indrd` reader"]
pub type R = crate::R<IndrdSpec>;
#[doc = "Register `indrd` writer"]
pub type W = crate::W<IndrdSpec>;
#[doc = "When this bit is enabled, it will trigger an indirect read operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect read operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Start> for bool {
    #[inline(always)]
    fn from(variant: Start) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `start` reader - When this bit is enabled, it will trigger an indirect read operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect read operation."]
pub type StartR = crate::BitReader<Start>;
impl StartR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Start {
        match self.bits {
            true => Start::Enabled,
            false => Start::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Start::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Start::Disabled
    }
}
#[doc = "Field `start` writer - When this bit is enabled, it will trigger an indirect read operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect read operation."]
pub type StartW<'a, REG> = crate::BitWriter<'a, REG, Start>;
impl<'a, REG> StartW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Start::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Start::Disabled)
    }
}
#[doc = "This bit will cancel all ongoing indirect read operations.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancel {
    #[doc = "1: `1`"]
    Cancel = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Cancel> for bool {
    #[inline(always)]
    fn from(variant: Cancel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cancel` reader - This bit will cancel all ongoing indirect read operations."]
pub type CancelR = crate::BitReader<Cancel>;
impl CancelR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cancel {
        match self.bits {
            true => Cancel::Cancel,
            false => Cancel::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cancel(&self) -> bool {
        *self == Cancel::Cancel
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Cancel::Noaction
    }
}
#[doc = "Field `cancel` writer - This bit will cancel all ongoing indirect read operations."]
pub type CancelW<'a, REG> = crate::BitWriter<'a, REG, Cancel>;
impl<'a, REG> CancelW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cancel(self) -> &'a mut crate::W<REG> {
        self.variant(Cancel::Cancel)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(Cancel::Noaction)
    }
}
#[doc = "Indirect read operation in progress (status)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RdStatus {
    #[doc = "1: `1`"]
    Readop = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<RdStatus> for bool {
    #[inline(always)]
    fn from(variant: RdStatus) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rd_status` reader - Indirect read operation in progress (status)"]
pub type RdStatusR = crate::BitReader<RdStatus>;
impl RdStatusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> RdStatus {
        match self.bits {
            true => RdStatus::Readop,
            false => RdStatus::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_readop(&self) -> bool {
        *self == RdStatus::Readop
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == RdStatus::Noaction
    }
}
#[doc = "Field `rd_status` writer - Indirect read operation in progress (status)"]
pub type RdStatusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "SRAM full and unable to immediately complete an indirect operation. Write a 1 to this field to clear it. ; indirect operation (status)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SramFull {
    #[doc = "1: `1`"]
    Sramfull = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<SramFull> for bool {
    #[inline(always)]
    fn from(variant: SramFull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sram_full` reader - SRAM full and unable to immediately complete an indirect operation. Write a 1 to this field to clear it. ; indirect operation (status)"]
pub type SramFullR = crate::BitReader<SramFull>;
impl SramFullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SramFull {
        match self.bits {
            true => SramFull::Sramfull,
            false => SramFull::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sramfull(&self) -> bool {
        *self == SramFull::Sramfull
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == SramFull::Noaction
    }
}
#[doc = "Field `sram_full` writer - SRAM full and unable to immediately complete an indirect operation. Write a 1 to this field to clear it. ; indirect operation (status)"]
pub type SramFullW<'a, REG> = crate::BitWriter1C<'a, REG, SramFull>;
impl<'a, REG> SramFullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn sramfull(self) -> &'a mut crate::W<REG> {
        self.variant(SramFull::Sramfull)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(SramFull::Noaction)
    }
}
#[doc = "Two indirect read operations have been queued\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RdQueued {
    #[doc = "1: `1`"]
    Quindirectrd = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<RdQueued> for bool {
    #[inline(always)]
    fn from(variant: RdQueued) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rd_queued` reader - Two indirect read operations have been queued"]
pub type RdQueuedR = crate::BitReader<RdQueued>;
impl RdQueuedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> RdQueued {
        match self.bits {
            true => RdQueued::Quindirectrd,
            false => RdQueued::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_quindirectrd(&self) -> bool {
        *self == RdQueued::Quindirectrd
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == RdQueued::Noaction
    }
}
#[doc = "Field `rd_queued` writer - Two indirect read operations have been queued"]
pub type RdQueuedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndOpsDoneStatus {
    #[doc = "1: `1`"]
    Indcomp = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<IndOpsDoneStatus> for bool {
    #[inline(always)]
    fn from(variant: IndOpsDoneStatus) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ind_ops_done_status` reader - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
pub type IndOpsDoneStatusR = crate::BitReader<IndOpsDoneStatus>;
impl IndOpsDoneStatusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IndOpsDoneStatus {
        match self.bits {
            true => IndOpsDoneStatus::Indcomp,
            false => IndOpsDoneStatus::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_indcomp(&self) -> bool {
        *self == IndOpsDoneStatus::Indcomp
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == IndOpsDoneStatus::Noaction
    }
}
#[doc = "Field `ind_ops_done_status` writer - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
pub type IndOpsDoneStatusW<'a, REG> = crate::BitWriter1C<'a, REG, IndOpsDoneStatus>;
impl<'a, REG> IndOpsDoneStatusW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn indcomp(self) -> &'a mut crate::W<REG> {
        self.variant(IndOpsDoneStatus::Indcomp)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(IndOpsDoneStatus::Noaction)
    }
}
#[doc = "Field `num_ind_ops_done` reader - This field contains the number of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
pub type NumIndOpsDoneR = crate::FieldReader;
#[doc = "Field `num_ind_ops_done` writer - This field contains the number of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
pub type NumIndOpsDoneW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - When this bit is enabled, it will trigger an indirect read operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect read operation."]
    #[inline(always)]
    pub fn start(&self) -> StartR {
        StartR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit will cancel all ongoing indirect read operations."]
    #[inline(always)]
    pub fn cancel(&self) -> CancelR {
        CancelR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Indirect read operation in progress (status)"]
    #[inline(always)]
    pub fn rd_status(&self) -> RdStatusR {
        RdStatusR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - SRAM full and unable to immediately complete an indirect operation. Write a 1 to this field to clear it. ; indirect operation (status)"]
    #[inline(always)]
    pub fn sram_full(&self) -> SramFullR {
        SramFullR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Two indirect read operations have been queued"]
    #[inline(always)]
    pub fn rd_queued(&self) -> RdQueuedR {
        RdQueuedR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
    #[inline(always)]
    pub fn ind_ops_done_status(&self) -> IndOpsDoneStatusR {
        IndOpsDoneStatusR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:7 - This field contains the number of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
    #[inline(always)]
    pub fn num_ind_ops_done(&self) -> NumIndOpsDoneR {
        NumIndOpsDoneR::new(((self.bits >> 6) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is enabled, it will trigger an indirect read operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect read operation."]
    #[inline(always)]
    #[must_use]
    pub fn start(&mut self) -> StartW<IndrdSpec> {
        StartW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit will cancel all ongoing indirect read operations."]
    #[inline(always)]
    #[must_use]
    pub fn cancel(&mut self) -> CancelW<IndrdSpec> {
        CancelW::new(self, 1)
    }
    #[doc = "Bit 2 - Indirect read operation in progress (status)"]
    #[inline(always)]
    #[must_use]
    pub fn rd_status(&mut self) -> RdStatusW<IndrdSpec> {
        RdStatusW::new(self, 2)
    }
    #[doc = "Bit 3 - SRAM full and unable to immediately complete an indirect operation. Write a 1 to this field to clear it. ; indirect operation (status)"]
    #[inline(always)]
    #[must_use]
    pub fn sram_full(&mut self) -> SramFullW<IndrdSpec> {
        SramFullW::new(self, 3)
    }
    #[doc = "Bit 4 - Two indirect read operations have been queued"]
    #[inline(always)]
    #[must_use]
    pub fn rd_queued(&mut self) -> RdQueuedW<IndrdSpec> {
        RdQueuedW::new(self, 4)
    }
    #[doc = "Bit 5 - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn ind_ops_done_status(&mut self) -> IndOpsDoneStatusW<IndrdSpec> {
        IndOpsDoneStatusW::new(self, 5)
    }
    #[doc = "Bits 6:7 - This field contains the number of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
    #[inline(always)]
    #[must_use]
    pub fn num_ind_ops_done(&mut self) -> NumIndOpsDoneW<IndrdSpec> {
        NumIndOpsDoneW::new(self, 6)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndrdSpec;
impl crate::RegisterSpec for IndrdSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`indrd::R`](R) reader structure"]
impl crate::Readable for IndrdSpec {}
#[doc = "`write(|w| ..)` method takes [`indrd::W`](W) writer structure"]
impl crate::Writable for IndrdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x28;
}
#[doc = "`reset()` method sets indrd to value 0"]
impl crate::Resettable for IndrdSpec {
    const RESET_VALUE: u32 = 0;
}
