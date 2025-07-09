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
#[doc = "Register `indwr` reader"]
pub type R = crate::R<IndwrSpec>;
#[doc = "Register `indwr` writer"]
pub type W = crate::W<IndwrSpec>;
#[doc = "Writing a 1 to this bit will trigger an indirect write operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect write operation.\n\nValue on reset: 0"]
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
#[doc = "Field `start` reader - Writing a 1 to this bit will trigger an indirect write operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect write operation."]
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
#[doc = "Field `start` writer - Writing a 1 to this bit will trigger an indirect write operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect write operation."]
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
#[doc = "Writing a 1 to this bit will cancel all ongoing indirect write operations.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancel {
    #[doc = "1: `1`"]
    Canceindwr = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Cancel> for bool {
    #[inline(always)]
    fn from(variant: Cancel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cancel` reader - Writing a 1 to this bit will cancel all ongoing indirect write operations."]
pub type CancelR = crate::BitReader<Cancel>;
impl CancelR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cancel {
        match self.bits {
            true => Cancel::Canceindwr,
            false => Cancel::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_canceindwr(&self) -> bool {
        *self == Cancel::Canceindwr
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Cancel::Noaction
    }
}
#[doc = "Field `cancel` writer - Writing a 1 to this bit will cancel all ongoing indirect write operations."]
pub type CancelW<'a, REG> = crate::BitWriter<'a, REG, Cancel>;
impl<'a, REG> CancelW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn canceindwr(self) -> &'a mut crate::W<REG> {
        self.variant(Cancel::Canceindwr)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(Cancel::Noaction)
    }
}
#[doc = "Indirect write operation in progress (status)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdstat {
    #[doc = "1: `1`"]
    Indwrstat = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Rdstat> for bool {
    #[inline(always)]
    fn from(variant: Rdstat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rdstat` reader - Indirect write operation in progress (status)"]
pub type RdstatR = crate::BitReader<Rdstat>;
impl RdstatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rdstat {
        match self.bits {
            true => Rdstat::Indwrstat,
            false => Rdstat::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_indwrstat(&self) -> bool {
        *self == Rdstat::Indwrstat
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Rdstat::Noaction
    }
}
#[doc = "Field `rdstat` writer - Indirect write operation in progress (status)"]
pub type RdstatW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sramfull` reader - "]
pub type SramfullR = crate::BitReader;
#[doc = "Field `sramfull` writer - "]
pub type SramfullW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Two indirect write operations have been queued\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdqueued {
    #[doc = "1: `1`"]
    Indwrop = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Rdqueued> for bool {
    #[inline(always)]
    fn from(variant: Rdqueued) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rdqueued` reader - Two indirect write operations have been queued"]
pub type RdqueuedR = crate::BitReader<Rdqueued>;
impl RdqueuedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rdqueued {
        match self.bits {
            true => Rdqueued::Indwrop,
            false => Rdqueued::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_indwrop(&self) -> bool {
        *self == Rdqueued::Indwrop
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Rdqueued::Noaction
    }
}
#[doc = "Field `rdqueued` writer - Two indirect write operations have been queued"]
pub type RdqueuedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inddone {
    #[doc = "1: `1`"]
    Indcompst = 1,
    #[doc = "0: `0`"]
    Noaction = 0,
}
impl From<Inddone> for bool {
    #[inline(always)]
    fn from(variant: Inddone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inddone` reader - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
pub type InddoneR = crate::BitReader<Inddone>;
impl InddoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inddone {
        match self.bits {
            true => Inddone::Indcompst,
            false => Inddone::Noaction,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_indcompst(&self) -> bool {
        *self == Inddone::Indcompst
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noaction(&self) -> bool {
        *self == Inddone::Noaction
    }
}
#[doc = "Field `inddone` writer - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
pub type InddoneW<'a, REG> = crate::BitWriter1C<'a, REG, Inddone>;
impl<'a, REG> InddoneW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn indcompst(self) -> &'a mut crate::W<REG> {
        self.variant(Inddone::Indcompst)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noaction(self) -> &'a mut crate::W<REG> {
        self.variant(Inddone::Noaction)
    }
}
#[doc = "Field `indcnt` reader - This field contains the count of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
pub type IndcntR = crate::FieldReader;
#[doc = "Field `indcnt` writer - This field contains the count of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
pub type IndcntW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Writing a 1 to this bit will trigger an indirect write operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect write operation."]
    #[inline(always)]
    pub fn start(&self) -> StartR {
        StartR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Writing a 1 to this bit will cancel all ongoing indirect write operations."]
    #[inline(always)]
    pub fn cancel(&self) -> CancelR {
        CancelR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Indirect write operation in progress (status)"]
    #[inline(always)]
    pub fn rdstat(&self) -> RdstatR {
        RdstatR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    pub fn sramfull(&self) -> SramfullR {
        SramfullR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Two indirect write operations have been queued"]
    #[inline(always)]
    pub fn rdqueued(&self) -> RdqueuedR {
        RdqueuedR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
    #[inline(always)]
    pub fn inddone(&self) -> InddoneR {
        InddoneR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:7 - This field contains the count of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
    #[inline(always)]
    pub fn indcnt(&self) -> IndcntR {
        IndcntR::new(((self.bits >> 6) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Writing a 1 to this bit will trigger an indirect write operation. The assumption is that the indirect start address and the indirect number of bytes register is setup before triggering the indirect write operation."]
    #[inline(always)]
    #[must_use]
    pub fn start(&mut self) -> StartW<IndwrSpec> {
        StartW::new(self, 0)
    }
    #[doc = "Bit 1 - Writing a 1 to this bit will cancel all ongoing indirect write operations."]
    #[inline(always)]
    #[must_use]
    pub fn cancel(&mut self) -> CancelW<IndwrSpec> {
        CancelW::new(self, 1)
    }
    #[doc = "Bit 2 - Indirect write operation in progress (status)"]
    #[inline(always)]
    #[must_use]
    pub fn rdstat(&mut self) -> RdstatW<IndwrSpec> {
        RdstatW::new(self, 2)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    #[must_use]
    pub fn sramfull(&mut self) -> SramfullW<IndwrSpec> {
        SramfullW::new(self, 3)
    }
    #[doc = "Bit 4 - Two indirect write operations have been queued"]
    #[inline(always)]
    #[must_use]
    pub fn rdqueued(&mut self) -> RdqueuedW<IndwrSpec> {
        RdqueuedW::new(self, 4)
    }
    #[doc = "Bit 5 - This field is set to 1 when an indirect operation has completed. Write a 1 to this field to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn inddone(&mut self) -> InddoneW<IndwrSpec> {
        InddoneW::new(self, 5)
    }
    #[doc = "Bits 6:7 - This field contains the count of indirect operations which have been completed. This is used in conjunction with the indirect completion status field (bit 5)."]
    #[inline(always)]
    #[must_use]
    pub fn indcnt(&mut self) -> IndcntW<IndwrSpec> {
        IndcntW::new(self, 6)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indwr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indwr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndwrSpec;
impl crate::RegisterSpec for IndwrSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`indwr::R`](R) reader structure"]
impl crate::Readable for IndwrSpec {}
#[doc = "`write(|w| ..)` method takes [`indwr::W`](W) writer structure"]
impl crate::Writable for IndwrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x20;
}
#[doc = "`reset()` method sets indwr to value 0"]
impl crate::Resettable for IndwrSpec {
    const RESET_VALUE: u32 = 0;
}
