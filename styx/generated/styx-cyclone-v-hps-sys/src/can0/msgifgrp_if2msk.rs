// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msgifgrp_IF2MSK` reader"]
pub type R = crate::R<MsgifgrpIf2mskSpec>;
#[doc = "Register `msgifgrp_IF2MSK` writer"]
pub type W = crate::W<MsgifgrpIf2mskSpec>;
#[doc = "Field `Msk` reader - 0 = The corresponding bit in the identifier of the message object cannot inhibit the match in the acceptance filtering. 1 = The corresponding identifier bit is used for acceptance filtering."]
pub type MskR = crate::FieldReader<u32>;
#[doc = "Field `Msk` writer - 0 = The corresponding bit in the identifier of the message object cannot inhibit the match in the acceptance filtering. 1 = The corresponding identifier bit is used for acceptance filtering."]
pub type MskW<'a, REG> = crate::FieldWriter<'a, REG, 29, u32>;
#[doc = "\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mdir {
    #[doc = "0: `0`"]
    NoAcceptEffect = 0,
    #[doc = "1: `1`"]
    AcceptEffect = 1,
}
impl From<Mdir> for bool {
    #[inline(always)]
    fn from(variant: Mdir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MDir` reader - "]
pub type MdirR = crate::BitReader<Mdir>;
impl MdirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mdir {
        match self.bits {
            false => Mdir::NoAcceptEffect,
            true => Mdir::AcceptEffect,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_accept_effect(&self) -> bool {
        *self == Mdir::NoAcceptEffect
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_accept_effect(&self) -> bool {
        *self == Mdir::AcceptEffect
    }
}
#[doc = "Field `MDir` writer - "]
pub type MdirW<'a, REG> = crate::BitWriter<'a, REG, Mdir>;
impl<'a, REG> MdirW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_accept_effect(self) -> &'a mut crate::W<REG> {
        self.variant(Mdir::NoAcceptEffect)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn accept_effect(self) -> &'a mut crate::W<REG> {
        self.variant(Mdir::AcceptEffect)
    }
}
#[doc = "When 11-bit (standard) Identifiers are used for a Message Object, the identifiers of received Data Frames are written into bits ID28 to ID18. For acceptance filtering, only these bits together with mask bits Msk28 to Msk18 are considered.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mxtd {
    #[doc = "0: `0`"]
    NoAcceptEffect = 0,
    #[doc = "1: `1`"]
    AcceptEffect = 1,
}
impl From<Mxtd> for bool {
    #[inline(always)]
    fn from(variant: Mxtd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MXtd` reader - When 11-bit (standard) Identifiers are used for a Message Object, the identifiers of received Data Frames are written into bits ID28 to ID18. For acceptance filtering, only these bits together with mask bits Msk28 to Msk18 are considered."]
pub type MxtdR = crate::BitReader<Mxtd>;
impl MxtdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mxtd {
        match self.bits {
            false => Mxtd::NoAcceptEffect,
            true => Mxtd::AcceptEffect,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_accept_effect(&self) -> bool {
        *self == Mxtd::NoAcceptEffect
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_accept_effect(&self) -> bool {
        *self == Mxtd::AcceptEffect
    }
}
#[doc = "Field `MXtd` writer - When 11-bit (standard) Identifiers are used for a Message Object, the identifiers of received Data Frames are written into bits ID28 to ID18. For acceptance filtering, only these bits together with mask bits Msk28 to Msk18 are considered."]
pub type MxtdW<'a, REG> = crate::BitWriter<'a, REG, Mxtd>;
impl<'a, REG> MxtdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_accept_effect(self) -> &'a mut crate::W<REG> {
        self.variant(Mxtd::NoAcceptEffect)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn accept_effect(self) -> &'a mut crate::W<REG> {
        self.variant(Mxtd::AcceptEffect)
    }
}
impl R {
    #[doc = "Bits 0:28 - 0 = The corresponding bit in the identifier of the message object cannot inhibit the match in the acceptance filtering. 1 = The corresponding identifier bit is used for acceptance filtering."]
    #[inline(always)]
    pub fn msk(&self) -> MskR {
        MskR::new(self.bits & 0x1fff_ffff)
    }
    #[doc = "Bit 30"]
    #[inline(always)]
    pub fn mdir(&self) -> MdirR {
        MdirR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - When 11-bit (standard) Identifiers are used for a Message Object, the identifiers of received Data Frames are written into bits ID28 to ID18. For acceptance filtering, only these bits together with mask bits Msk28 to Msk18 are considered."]
    #[inline(always)]
    pub fn mxtd(&self) -> MxtdR {
        MxtdR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:28 - 0 = The corresponding bit in the identifier of the message object cannot inhibit the match in the acceptance filtering. 1 = The corresponding identifier bit is used for acceptance filtering."]
    #[inline(always)]
    #[must_use]
    pub fn msk(&mut self) -> MskW<MsgifgrpIf2mskSpec> {
        MskW::new(self, 0)
    }
    #[doc = "Bit 30"]
    #[inline(always)]
    #[must_use]
    pub fn mdir(&mut self) -> MdirW<MsgifgrpIf2mskSpec> {
        MdirW::new(self, 30)
    }
    #[doc = "Bit 31 - When 11-bit (standard) Identifiers are used for a Message Object, the identifiers of received Data Frames are written into bits ID28 to ID18. For acceptance filtering, only these bits together with mask bits Msk28 to Msk18 are considered."]
    #[inline(always)]
    #[must_use]
    pub fn mxtd(&mut self) -> MxtdW<MsgifgrpIf2mskSpec> {
        MxtdW::new(self, 31)
    }
}
#[doc = "The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2msk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2msk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsgifgrpIf2mskSpec;
impl crate::RegisterSpec for MsgifgrpIf2mskSpec {
    type Ux = u32;
    const OFFSET: u64 = 292u64;
}
#[doc = "`read()` method returns [`msgifgrp_if2msk::R`](R) reader structure"]
impl crate::Readable for MsgifgrpIf2mskSpec {}
#[doc = "`write(|w| ..)` method takes [`msgifgrp_if2msk::W`](W) writer structure"]
impl crate::Writable for MsgifgrpIf2mskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets msgifgrp_IF2MSK to value 0xffff_ffff"]
impl crate::Resettable for MsgifgrpIf2mskSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
