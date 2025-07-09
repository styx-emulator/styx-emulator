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
#[doc = "Register `nandgrp_bootstrap` reader"]
pub type R = crate::R<NandgrpBootstrapSpec>;
#[doc = "Register `nandgrp_bootstrap` writer"]
pub type W = crate::W<NandgrpBootstrapSpec>;
#[doc = "Field `noinit` reader - If 1, inhibits NAND Flash Controller from performing initialization when coming out of reset. Instead, software must program all registers pertaining to device parameters like page size, width, etc."]
pub type NoinitR = crate::BitReader;
#[doc = "Field `noinit` writer - If 1, inhibits NAND Flash Controller from performing initialization when coming out of reset. Instead, software must program all registers pertaining to device parameters like page size, width, etc."]
pub type NoinitW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `page512` reader - If 1, NAND device has a 512 byte page size."]
pub type Page512R = crate::BitReader;
#[doc = "Field `page512` writer - If 1, NAND device has a 512 byte page size."]
pub type Page512W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `noloadb0p0` reader - If 1, inhibits NAND Flash Controller from loading page 0 of block 0 of the NAND device as part of the initialization procedure."]
pub type Noloadb0p0R = crate::BitReader;
#[doc = "Field `noloadb0p0` writer - If 1, inhibits NAND Flash Controller from loading page 0 of block 0 of the NAND device as part of the initialization procedure."]
pub type Noloadb0p0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tworowaddr` reader - If 1, NAND device requires only 2 row address cycles instead of the normal 3 row address cycles."]
pub type TworowaddrR = crate::BitReader;
#[doc = "Field `tworowaddr` writer - If 1, NAND device requires only 2 row address cycles instead of the normal 3 row address cycles."]
pub type TworowaddrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - If 1, inhibits NAND Flash Controller from performing initialization when coming out of reset. Instead, software must program all registers pertaining to device parameters like page size, width, etc."]
    #[inline(always)]
    pub fn noinit(&self) -> NoinitR {
        NoinitR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - If 1, NAND device has a 512 byte page size."]
    #[inline(always)]
    pub fn page512(&self) -> Page512R {
        Page512R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - If 1, inhibits NAND Flash Controller from loading page 0 of block 0 of the NAND device as part of the initialization procedure."]
    #[inline(always)]
    pub fn noloadb0p0(&self) -> Noloadb0p0R {
        Noloadb0p0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - If 1, NAND device requires only 2 row address cycles instead of the normal 3 row address cycles."]
    #[inline(always)]
    pub fn tworowaddr(&self) -> TworowaddrR {
        TworowaddrR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - If 1, inhibits NAND Flash Controller from performing initialization when coming out of reset. Instead, software must program all registers pertaining to device parameters like page size, width, etc."]
    #[inline(always)]
    #[must_use]
    pub fn noinit(&mut self) -> NoinitW<NandgrpBootstrapSpec> {
        NoinitW::new(self, 0)
    }
    #[doc = "Bit 1 - If 1, NAND device has a 512 byte page size."]
    #[inline(always)]
    #[must_use]
    pub fn page512(&mut self) -> Page512W<NandgrpBootstrapSpec> {
        Page512W::new(self, 1)
    }
    #[doc = "Bit 2 - If 1, inhibits NAND Flash Controller from loading page 0 of block 0 of the NAND device as part of the initialization procedure."]
    #[inline(always)]
    #[must_use]
    pub fn noloadb0p0(&mut self) -> Noloadb0p0W<NandgrpBootstrapSpec> {
        Noloadb0p0W::new(self, 2)
    }
    #[doc = "Bit 3 - If 1, NAND device requires only 2 row address cycles instead of the normal 3 row address cycles."]
    #[inline(always)]
    #[must_use]
    pub fn tworowaddr(&mut self) -> TworowaddrW<NandgrpBootstrapSpec> {
        TworowaddrW::new(self, 3)
    }
}
#[doc = "Bootstrap fields sampled by NAND Flash Controller when released from reset. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`nandgrp_bootstrap::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`nandgrp_bootstrap::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct NandgrpBootstrapSpec;
impl crate::RegisterSpec for NandgrpBootstrapSpec {
    type Ux = u32;
    const OFFSET: u64 = 272u64;
}
#[doc = "`read()` method returns [`nandgrp_bootstrap::R`](R) reader structure"]
impl crate::Readable for NandgrpBootstrapSpec {}
#[doc = "`write(|w| ..)` method takes [`nandgrp_bootstrap::W`](W) writer structure"]
impl crate::Writable for NandgrpBootstrapSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets nandgrp_bootstrap to value 0"]
impl crate::Resettable for NandgrpBootstrapSpec {
    const RESET_VALUE: u32 = 0;
}
