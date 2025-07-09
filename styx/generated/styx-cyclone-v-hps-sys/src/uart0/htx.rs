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
#[doc = "Register `htx` reader"]
pub type R = crate::R<HtxSpec>;
#[doc = "Register `htx` writer"]
pub type W = crate::W<HtxSpec>;
#[doc = "This register is use to halt transmissions for testing, so that the transmit FIFO can be filled by the master when FIFO's are enabled. Note, if FIFO's are not enabled, the setting of the halt Tx register will have no effect on operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Htx {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Htx> for bool {
    #[inline(always)]
    fn from(variant: Htx) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `htx` reader - This register is use to halt transmissions for testing, so that the transmit FIFO can be filled by the master when FIFO's are enabled. Note, if FIFO's are not enabled, the setting of the halt Tx register will have no effect on operation."]
pub type HtxR = crate::BitReader<Htx>;
impl HtxR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Htx {
        match self.bits {
            false => Htx::Disabled,
            true => Htx::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Htx::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Htx::Enabled
    }
}
#[doc = "Field `htx` writer - This register is use to halt transmissions for testing, so that the transmit FIFO can be filled by the master when FIFO's are enabled. Note, if FIFO's are not enabled, the setting of the halt Tx register will have no effect on operation."]
pub type HtxW<'a, REG> = crate::BitWriter<'a, REG, Htx>;
impl<'a, REG> HtxW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Htx::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Htx::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This register is use to halt transmissions for testing, so that the transmit FIFO can be filled by the master when FIFO's are enabled. Note, if FIFO's are not enabled, the setting of the halt Tx register will have no effect on operation."]
    #[inline(always)]
    pub fn htx(&self) -> HtxR {
        HtxR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register is use to halt transmissions for testing, so that the transmit FIFO can be filled by the master when FIFO's are enabled. Note, if FIFO's are not enabled, the setting of the halt Tx register will have no effect on operation."]
    #[inline(always)]
    #[must_use]
    pub fn htx(&mut self) -> HtxW<HtxSpec> {
        HtxW::new(self, 0)
    }
}
#[doc = "Used to halt transmission for testing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`htx::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`htx::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HtxSpec;
impl crate::RegisterSpec for HtxSpec {
    type Ux = u32;
    const OFFSET: u64 = 164u64;
}
#[doc = "`read()` method returns [`htx::R`](R) reader structure"]
impl crate::Readable for HtxSpec {}
#[doc = "`write(|w| ..)` method takes [`htx::W`](W) writer structure"]
impl crate::Writable for HtxSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets htx to value 0"]
impl crate::Resettable for HtxSpec {
    const RESET_VALUE: u32 = 0;
}
