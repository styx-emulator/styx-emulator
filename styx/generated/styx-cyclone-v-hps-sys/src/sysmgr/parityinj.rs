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
#[doc = "Register `parityinj` reader"]
pub type R = crate::R<ParityinjSpec>;
#[doc = "Register `parityinj` writer"]
pub type W = crate::W<ParityinjSpec>;
#[doc = "Field `dcdata_0` reader - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Dcdata0R = crate::BitReader;
#[doc = "Field `dcdata_0` writer - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Dcdata0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dcdata_1` reader - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Dcdata1R = crate::BitReader;
#[doc = "Field `dcdata_1` writer - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Dcdata1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dctag_0` reader - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Dctag0R = crate::BitReader;
#[doc = "Field `dctag_0` writer - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Dctag0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dctag_1` reader - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Dctag1R = crate::BitReader;
#[doc = "Field `dctag_1` writer - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Dctag1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dcouter_0` reader - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
pub type Dcouter0R = crate::BitReader;
#[doc = "Field `dcouter_0` writer - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
pub type Dcouter0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dcouter_1` reader - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
pub type Dcouter1R = crate::BitReader;
#[doc = "Field `dcouter_1` writer - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
pub type Dcouter1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `maintlb_0` reader - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
pub type Maintlb0R = crate::BitReader;
#[doc = "Field `maintlb_0` writer - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
pub type Maintlb0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `maintlb_1` reader - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
pub type Maintlb1R = crate::BitReader;
#[doc = "Field `maintlb_1` writer - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
pub type Maintlb1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `icdata_0` reader - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Icdata0R = crate::BitReader;
#[doc = "Field `icdata_0` writer - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Icdata0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `icdata_1` reader - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Icdata1R = crate::BitReader;
#[doc = "Field `icdata_1` writer - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
pub type Icdata1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ictag_0` reader - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Ictag0R = crate::BitReader;
#[doc = "Field `ictag_0` writer - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Ictag0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ictag_1` reader - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Ictag1R = crate::BitReader;
#[doc = "Field `ictag_1` writer - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
pub type Ictag1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ghb_0` reader - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
pub type Ghb0R = crate::BitReader;
#[doc = "Field `ghb_0` writer - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
pub type Ghb0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ghb_1` reader - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
pub type Ghb1R = crate::BitReader;
#[doc = "Field `ghb_1` writer - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
pub type Ghb1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `btac_0` reader - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
pub type Btac0R = crate::BitReader;
#[doc = "Field `btac_0` writer - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
pub type Btac0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `btac_1` reader - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
pub type Btac1R = crate::BitReader;
#[doc = "Field `btac_1` writer - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
pub type Btac1W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn dcdata_0(&self) -> Dcdata0R {
        Dcdata0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn dcdata_1(&self) -> Dcdata1R {
        Dcdata1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn dctag_0(&self) -> Dctag0R {
        Dctag0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn dctag_1(&self) -> Dctag1R {
        Dctag1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn dcouter_0(&self) -> Dcouter0R {
        Dcouter0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn dcouter_1(&self) -> Dcouter1R {
        Dcouter1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn maintlb_0(&self) -> Maintlb0R {
        Maintlb0R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn maintlb_1(&self) -> Maintlb1R {
        Maintlb1R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn icdata_0(&self) -> Icdata0R {
        Icdata0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn icdata_1(&self) -> Icdata1R {
        Icdata1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn ictag_0(&self) -> Ictag0R {
        Ictag0R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn ictag_1(&self) -> Ictag1R {
        Ictag1R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn ghb_0(&self) -> Ghb0R {
        Ghb0R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn ghb_1(&self) -> Ghb1R {
        Ghb1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn btac_0(&self) -> Btac0R {
        Btac0R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    pub fn btac_1(&self) -> Btac1R {
        Btac1R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn dcdata_0(&mut self) -> Dcdata0W<ParityinjSpec> {
        Dcdata0W::new(self, 0)
    }
    #[doc = "Bit 1 - If 1, injecting parity error to Data Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn dcdata_1(&mut self) -> Dcdata1W<ParityinjSpec> {
        Dcdata1W::new(self, 1)
    }
    #[doc = "Bit 2 - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn dctag_0(&mut self) -> Dctag0W<ParityinjSpec> {
        Dctag0W::new(self, 2)
    }
    #[doc = "Bit 3 - If 1, injecting parity error to Data Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn dctag_1(&mut self) -> Dctag1W<ParityinjSpec> {
        Dctag1W::new(self, 3)
    }
    #[doc = "Bit 4 - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn dcouter_0(&mut self) -> Dcouter0W<ParityinjSpec> {
        Dcouter0W::new(self, 4)
    }
    #[doc = "Bit 5 - If 1, injecting parity error to Data Cache Outer RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn dcouter_1(&mut self) -> Dcouter1W<ParityinjSpec> {
        Dcouter1W::new(self, 5)
    }
    #[doc = "Bit 6 - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn maintlb_0(&mut self) -> Maintlb0W<ParityinjSpec> {
        Maintlb0W::new(self, 6)
    }
    #[doc = "Bit 7 - If 1, injecting parity error to Main TLB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn maintlb_1(&mut self) -> Maintlb1W<ParityinjSpec> {
        Maintlb1W::new(self, 7)
    }
    #[doc = "Bit 8 - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn icdata_0(&mut self) -> Icdata0W<ParityinjSpec> {
        Icdata0W::new(self, 8)
    }
    #[doc = "Bit 9 - If 1, injecting parity error to Instruction Cache Data RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn icdata_1(&mut self) -> Icdata1W<ParityinjSpec> {
        Icdata1W::new(self, 9)
    }
    #[doc = "Bit 10 - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn ictag_0(&mut self) -> Ictag0W<ParityinjSpec> {
        Ictag0W::new(self, 10)
    }
    #[doc = "Bit 11 - If 1, injecting parity error to Instruction Cache Tag RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn ictag_1(&mut self) -> Ictag1W<ParityinjSpec> {
        Ictag1W::new(self, 11)
    }
    #[doc = "Bit 12 - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn ghb_0(&mut self) -> Ghb0W<ParityinjSpec> {
        Ghb0W::new(self, 12)
    }
    #[doc = "Bit 13 - If 1, injecting parity error to GHB RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn ghb_1(&mut self) -> Ghb1W<ParityinjSpec> {
        Ghb1W::new(self, 13)
    }
    #[doc = "Bit 14 - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn btac_0(&mut self) -> Btac0W<ParityinjSpec> {
        Btac0W::new(self, 14)
    }
    #[doc = "Bit 15 - If 1, injecting parity error to BTAC RAM.The field array index corresponds to the CPU index."]
    #[inline(always)]
    #[must_use]
    pub fn btac_1(&mut self) -> Btac1W<ParityinjSpec> {
        Btac1W::new(self, 15)
    }
}
#[doc = "Inject parity failures into the parity-protected RAMs in the MPU. Allows software to test the parity failure interrupt handler. The field array index corresponds to the CPU index. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`parityinj::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`parityinj::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParityinjSpec;
impl crate::RegisterSpec for ParityinjSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`parityinj::R`](R) reader structure"]
impl crate::Readable for ParityinjSpec {}
#[doc = "`write(|w| ..)` method takes [`parityinj::W`](W) writer structure"]
impl crate::Writable for ParityinjSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets parityinj to value 0"]
impl crate::Resettable for ParityinjSpec {
    const RESET_VALUE: u32 = 0;
}
