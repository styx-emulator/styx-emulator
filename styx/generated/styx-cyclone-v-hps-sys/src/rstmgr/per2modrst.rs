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
#[doc = "Register `per2modrst` reader"]
pub type R = crate::R<Per2modrstSpec>;
#[doc = "Register `per2modrst` writer"]
pub type W = crate::W<Per2modrstSpec>;
#[doc = "Field `dmaif0` reader - Resets DMA channel 0 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif0R = crate::BitReader;
#[doc = "Field `dmaif0` writer - Resets DMA channel 0 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif1` reader - Resets DMA channel 1 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif1R = crate::BitReader;
#[doc = "Field `dmaif1` writer - Resets DMA channel 1 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif2` reader - Resets DMA channel 2 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif2R = crate::BitReader;
#[doc = "Field `dmaif2` writer - Resets DMA channel 2 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif3` reader - Resets DMA channel 3 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif3R = crate::BitReader;
#[doc = "Field `dmaif3` writer - Resets DMA channel 3 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif4` reader - Resets DMA channel 4 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif4R = crate::BitReader;
#[doc = "Field `dmaif4` writer - Resets DMA channel 4 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif5` reader - Resets DMA channel 5 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif5R = crate::BitReader;
#[doc = "Field `dmaif5` writer - Resets DMA channel 5 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif6` reader - Resets DMA channel 6 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif6R = crate::BitReader;
#[doc = "Field `dmaif6` writer - Resets DMA channel 6 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dmaif7` reader - Resets DMA channel 7 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif7R = crate::BitReader;
#[doc = "Field `dmaif7` writer - Resets DMA channel 7 interface adapter between FPGA Fabric and HPS DMA Controller"]
pub type Dmaif7W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Resets DMA channel 0 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif0(&self) -> Dmaif0R {
        Dmaif0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Resets DMA channel 1 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif1(&self) -> Dmaif1R {
        Dmaif1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Resets DMA channel 2 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif2(&self) -> Dmaif2R {
        Dmaif2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Resets DMA channel 3 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif3(&self) -> Dmaif3R {
        Dmaif3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Resets DMA channel 4 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif4(&self) -> Dmaif4R {
        Dmaif4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Resets DMA channel 5 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif5(&self) -> Dmaif5R {
        Dmaif5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Resets DMA channel 6 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif6(&self) -> Dmaif6R {
        Dmaif6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Resets DMA channel 7 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    pub fn dmaif7(&self) -> Dmaif7R {
        Dmaif7R::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Resets DMA channel 0 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif0(&mut self) -> Dmaif0W<Per2modrstSpec> {
        Dmaif0W::new(self, 0)
    }
    #[doc = "Bit 1 - Resets DMA channel 1 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif1(&mut self) -> Dmaif1W<Per2modrstSpec> {
        Dmaif1W::new(self, 1)
    }
    #[doc = "Bit 2 - Resets DMA channel 2 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif2(&mut self) -> Dmaif2W<Per2modrstSpec> {
        Dmaif2W::new(self, 2)
    }
    #[doc = "Bit 3 - Resets DMA channel 3 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif3(&mut self) -> Dmaif3W<Per2modrstSpec> {
        Dmaif3W::new(self, 3)
    }
    #[doc = "Bit 4 - Resets DMA channel 4 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif4(&mut self) -> Dmaif4W<Per2modrstSpec> {
        Dmaif4W::new(self, 4)
    }
    #[doc = "Bit 5 - Resets DMA channel 5 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif5(&mut self) -> Dmaif5W<Per2modrstSpec> {
        Dmaif5W::new(self, 5)
    }
    #[doc = "Bit 6 - Resets DMA channel 6 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif6(&mut self) -> Dmaif6W<Per2modrstSpec> {
        Dmaif6W::new(self, 6)
    }
    #[doc = "Bit 7 - Resets DMA channel 7 interface adapter between FPGA Fabric and HPS DMA Controller"]
    #[inline(always)]
    #[must_use]
    pub fn dmaif7(&mut self) -> Dmaif7W<Per2modrstSpec> {
        Dmaif7W::new(self, 7)
    }
}
#[doc = "The PER2MODRST register is used by software to trigger module resets (individual module reset signals). Software explicitly asserts and de-asserts module reset signals by writing bits in the appropriate *MODRST register. It is up to software to ensure module reset signals are asserted for the appropriate length of time and are de-asserted in the correct order. It is also up to software to not assert a module reset signal that would prevent software from de-asserting the module reset signal. For example, software should not assert the module reset to the CPU executing the software. Software writes a bit to 1 to assert the module reset signal and to 0 to de-assert the module reset signal. All fields are reset by a cold reset.All fields are also reset by a warm reset if not masked by the corresponding PERWARMMASK field. The reset value of all fields is 1. This holds the corresponding module in reset until software is ready to release the module from reset by writing 0 to its field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`per2modrst::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`per2modrst::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Per2modrstSpec;
impl crate::RegisterSpec for Per2modrstSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`per2modrst::R`](R) reader structure"]
impl crate::Readable for Per2modrstSpec {}
#[doc = "`write(|w| ..)` method takes [`per2modrst::W`](W) writer structure"]
impl crate::Writable for Per2modrstSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets per2modrst to value 0xff"]
impl crate::Resettable for Per2modrstSpec {
    const RESET_VALUE: u32 = 0xff;
}
