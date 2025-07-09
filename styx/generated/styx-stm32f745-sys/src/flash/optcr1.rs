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
#[doc = "Register `OPTCR1` reader"]
pub type R = crate::R<Optcr1Spec>;
#[doc = "Register `OPTCR1` writer"]
pub type W = crate::W<Optcr1Spec>;
#[doc = "Field `BOOT_ADD0` reader - Boot base address when Boot pin =0"]
pub type BootAdd0R = crate::FieldReader<u16>;
#[doc = "Field `BOOT_ADD0` writer - Boot base address when Boot pin =0"]
pub type BootAdd0W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `BOOT_ADD1` reader - Boot base address when Boot pin =1"]
pub type BootAdd1R = crate::FieldReader<u16>;
#[doc = "Field `BOOT_ADD1` writer - Boot base address when Boot pin =1"]
pub type BootAdd1W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Boot base address when Boot pin =0"]
    #[inline(always)]
    pub fn boot_add0(&self) -> BootAdd0R {
        BootAdd0R::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - Boot base address when Boot pin =1"]
    #[inline(always)]
    pub fn boot_add1(&self) -> BootAdd1R {
        BootAdd1R::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Boot base address when Boot pin =0"]
    #[inline(always)]
    #[must_use]
    pub fn boot_add0(&mut self) -> BootAdd0W<Optcr1Spec> {
        BootAdd0W::new(self, 0)
    }
    #[doc = "Bits 16:31 - Boot base address when Boot pin =1"]
    #[inline(always)]
    #[must_use]
    pub fn boot_add1(&mut self) -> BootAdd1W<Optcr1Spec> {
        BootAdd1W::new(self, 16)
    }
}
#[doc = "Flash option control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`optcr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`optcr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Optcr1Spec;
impl crate::RegisterSpec for Optcr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`optcr1::R`](R) reader structure"]
impl crate::Readable for Optcr1Spec {}
#[doc = "`write(|w| ..)` method takes [`optcr1::W`](W) writer structure"]
impl crate::Writable for Optcr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OPTCR1 to value 0x0fff_0000"]
impl crate::Resettable for Optcr1Spec {
    const RESET_VALUE: u32 = 0x0fff_0000;
}
