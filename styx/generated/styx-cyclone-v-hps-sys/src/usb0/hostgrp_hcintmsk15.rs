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
#[doc = "Register `hostgrp_hcintmsk15` reader"]
pub type R = crate::R<HostgrpHcintmsk15Spec>;
#[doc = "Register `hostgrp_hcintmsk15` writer"]
pub type W = crate::W<HostgrpHcintmsk15Spec>;
#[doc = "Transfer complete.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xfercomplmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Xfercomplmsk> for bool {
    #[inline(always)]
    fn from(variant: Xfercomplmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xfercomplmsk` reader - Transfer complete."]
pub type XfercomplmskR = crate::BitReader<Xfercomplmsk>;
impl XfercomplmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xfercomplmsk {
        match self.bits {
            false => Xfercomplmsk::Mask,
            true => Xfercomplmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Xfercomplmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Xfercomplmsk::Nomask
    }
}
#[doc = "Field `xfercomplmsk` writer - Transfer complete."]
pub type XfercomplmskW<'a, REG> = crate::BitWriter<'a, REG, Xfercomplmsk>;
impl<'a, REG> XfercomplmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Xfercomplmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Xfercomplmsk::Nomask)
    }
}
#[doc = "Channel Halted.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chhltdmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Chhltdmsk> for bool {
    #[inline(always)]
    fn from(variant: Chhltdmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chhltdmsk` reader - Channel Halted."]
pub type ChhltdmskR = crate::BitReader<Chhltdmsk>;
impl ChhltdmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chhltdmsk {
        match self.bits {
            false => Chhltdmsk::Mask,
            true => Chhltdmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Chhltdmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Chhltdmsk::Nomask
    }
}
#[doc = "Field `chhltdmsk` writer - Channel Halted."]
pub type ChhltdmskW<'a, REG> = crate::BitWriter<'a, REG, Chhltdmsk>;
impl<'a, REG> ChhltdmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Chhltdmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Chhltdmsk::Nomask)
    }
}
#[doc = "In scatter/gather DMA mode for host, interrupts will not be generated due to the corresponding bits set in HCINTn.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ahberrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ahberrmsk> for bool {
    #[inline(always)]
    fn from(variant: Ahberrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ahberrmsk` reader - In scatter/gather DMA mode for host, interrupts will not be generated due to the corresponding bits set in HCINTn."]
pub type AhberrmskR = crate::BitReader<Ahberrmsk>;
impl AhberrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ahberrmsk {
        match self.bits {
            false => Ahberrmsk::Mask,
            true => Ahberrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ahberrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ahberrmsk::Nomask
    }
}
#[doc = "Field `ahberrmsk` writer - In scatter/gather DMA mode for host, interrupts will not be generated due to the corresponding bits set in HCINTn."]
pub type AhberrmskW<'a, REG> = crate::BitWriter<'a, REG, Ahberrmsk>;
impl<'a, REG> AhberrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Ahberrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Ahberrmsk::Nomask)
    }
}
#[doc = "This bit is valid only when Scatter/Gather DMA mode is enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bnaintrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Bnaintrmsk> for bool {
    #[inline(always)]
    fn from(variant: Bnaintrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bnaintrmsk` reader - This bit is valid only when Scatter/Gather DMA mode is enabled."]
pub type BnaintrmskR = crate::BitReader<Bnaintrmsk>;
impl BnaintrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bnaintrmsk {
        match self.bits {
            false => Bnaintrmsk::Mask,
            true => Bnaintrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Bnaintrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Bnaintrmsk::Nomask
    }
}
#[doc = "Field `bnaintrmsk` writer - This bit is valid only when Scatter/Gather DMA mode is enabled."]
pub type BnaintrmskW<'a, REG> = crate::BitWriter<'a, REG, Bnaintrmsk>;
impl<'a, REG> BnaintrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Bnaintrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Bnaintrmsk::Nomask)
    }
}
#[doc = "This bit is valid only when Scatter/Gather DMA mode is enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrmLstRollintrmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<FrmLstRollintrmsk> for bool {
    #[inline(always)]
    fn from(variant: FrmLstRollintrmsk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `frm_lst_rollintrmsk` reader - This bit is valid only when Scatter/Gather DMA mode is enabled."]
pub type FrmLstRollintrmskR = crate::BitReader<FrmLstRollintrmsk>;
impl FrmLstRollintrmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> FrmLstRollintrmsk {
        match self.bits {
            false => FrmLstRollintrmsk::Mask,
            true => FrmLstRollintrmsk::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == FrmLstRollintrmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == FrmLstRollintrmsk::Nomask
    }
}
#[doc = "Field `frm_lst_rollintrmsk` writer - This bit is valid only when Scatter/Gather DMA mode is enabled."]
pub type FrmLstRollintrmskW<'a, REG> = crate::BitWriter<'a, REG, FrmLstRollintrmsk>;
impl<'a, REG> FrmLstRollintrmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(FrmLstRollintrmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(FrmLstRollintrmsk::Nomask)
    }
}
impl R {
    #[doc = "Bit 0 - Transfer complete."]
    #[inline(always)]
    pub fn xfercomplmsk(&self) -> XfercomplmskR {
        XfercomplmskR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Channel Halted."]
    #[inline(always)]
    pub fn chhltdmsk(&self) -> ChhltdmskR {
        ChhltdmskR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - In scatter/gather DMA mode for host, interrupts will not be generated due to the corresponding bits set in HCINTn."]
    #[inline(always)]
    pub fn ahberrmsk(&self) -> AhberrmskR {
        AhberrmskR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit is valid only when Scatter/Gather DMA mode is enabled."]
    #[inline(always)]
    pub fn bnaintrmsk(&self) -> BnaintrmskR {
        BnaintrmskR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 13 - This bit is valid only when Scatter/Gather DMA mode is enabled."]
    #[inline(always)]
    pub fn frm_lst_rollintrmsk(&self) -> FrmLstRollintrmskR {
        FrmLstRollintrmskR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer complete."]
    #[inline(always)]
    #[must_use]
    pub fn xfercomplmsk(&mut self) -> XfercomplmskW<HostgrpHcintmsk15Spec> {
        XfercomplmskW::new(self, 0)
    }
    #[doc = "Bit 1 - Channel Halted."]
    #[inline(always)]
    #[must_use]
    pub fn chhltdmsk(&mut self) -> ChhltdmskW<HostgrpHcintmsk15Spec> {
        ChhltdmskW::new(self, 1)
    }
    #[doc = "Bit 2 - In scatter/gather DMA mode for host, interrupts will not be generated due to the corresponding bits set in HCINTn."]
    #[inline(always)]
    #[must_use]
    pub fn ahberrmsk(&mut self) -> AhberrmskW<HostgrpHcintmsk15Spec> {
        AhberrmskW::new(self, 2)
    }
    #[doc = "Bit 11 - This bit is valid only when Scatter/Gather DMA mode is enabled."]
    #[inline(always)]
    #[must_use]
    pub fn bnaintrmsk(&mut self) -> BnaintrmskW<HostgrpHcintmsk15Spec> {
        BnaintrmskW::new(self, 11)
    }
    #[doc = "Bit 13 - This bit is valid only when Scatter/Gather DMA mode is enabled."]
    #[inline(always)]
    #[must_use]
    pub fn frm_lst_rollintrmsk(&mut self) -> FrmLstRollintrmskW<HostgrpHcintmsk15Spec> {
        FrmLstRollintrmskW::new(self, 13)
    }
}
#[doc = "This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk15::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk15::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcintmsk15Spec;
impl crate::RegisterSpec for HostgrpHcintmsk15Spec {
    type Ux = u32;
    const OFFSET: u64 = 1772u64;
}
#[doc = "`read()` method returns [`hostgrp_hcintmsk15::R`](R) reader structure"]
impl crate::Readable for HostgrpHcintmsk15Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcintmsk15::W`](W) writer structure"]
impl crate::Writable for HostgrpHcintmsk15Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcintmsk15 to value 0"]
impl crate::Resettable for HostgrpHcintmsk15Spec {
    const RESET_VALUE: u32 = 0;
}
