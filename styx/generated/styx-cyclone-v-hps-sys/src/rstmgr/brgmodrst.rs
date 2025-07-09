// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `brgmodrst` reader"]
pub type R = crate::R<BrgmodrstSpec>;
#[doc = "Register `brgmodrst` writer"]
pub type W = crate::W<BrgmodrstSpec>;
#[doc = "Field `hps2fpga` reader - Resets HPS2FPGA Bridge"]
pub type Hps2fpgaR = crate::BitReader;
#[doc = "Field `hps2fpga` writer - Resets HPS2FPGA Bridge"]
pub type Hps2fpgaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `lwhps2fpga` reader - Resets LWHPS2FPGA Bridge"]
pub type Lwhps2fpgaR = crate::BitReader;
#[doc = "Field `lwhps2fpga` writer - Resets LWHPS2FPGA Bridge"]
pub type Lwhps2fpgaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpga2hps` reader - Resets FPGA2HPS Bridge"]
pub type Fpga2hpsR = crate::BitReader;
#[doc = "Field `fpga2hps` writer - Resets FPGA2HPS Bridge"]
pub type Fpga2hpsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Resets HPS2FPGA Bridge"]
    #[inline(always)]
    pub fn hps2fpga(&self) -> Hps2fpgaR {
        Hps2fpgaR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Resets LWHPS2FPGA Bridge"]
    #[inline(always)]
    pub fn lwhps2fpga(&self) -> Lwhps2fpgaR {
        Lwhps2fpgaR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Resets FPGA2HPS Bridge"]
    #[inline(always)]
    pub fn fpga2hps(&self) -> Fpga2hpsR {
        Fpga2hpsR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Resets HPS2FPGA Bridge"]
    #[inline(always)]
    #[must_use]
    pub fn hps2fpga(&mut self) -> Hps2fpgaW<BrgmodrstSpec> {
        Hps2fpgaW::new(self, 0)
    }
    #[doc = "Bit 1 - Resets LWHPS2FPGA Bridge"]
    #[inline(always)]
    #[must_use]
    pub fn lwhps2fpga(&mut self) -> Lwhps2fpgaW<BrgmodrstSpec> {
        Lwhps2fpgaW::new(self, 1)
    }
    #[doc = "Bit 2 - Resets FPGA2HPS Bridge"]
    #[inline(always)]
    #[must_use]
    pub fn fpga2hps(&mut self) -> Fpga2hpsW<BrgmodrstSpec> {
        Fpga2hpsW::new(self, 2)
    }
}
#[doc = "The BRGMODRST register is used by software to trigger module resets (individual module reset signals). Software explicitly asserts and de-asserts module reset signals by writing bits in the appropriate *MODRST register. It is up to software to ensure module reset signals are asserted for the appropriate length of time and are de-asserted in the correct order. It is also up to software to not assert a module reset signal that would prevent software from de-asserting the module reset signal. For example, software should not assert the module reset to the CPU executing the software. Software writes a bit to 1 to assert the module reset signal and to 0 to de-assert the module reset signal. All fields are reset by a cold reset.All fields are also reset by a warm reset if not masked by the corresponding BRGWARMMASK field. The reset value of all fields is 1. This holds the corresponding module in reset until software is ready to release the module from reset by writing 0 to its field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`brgmodrst::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`brgmodrst::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BrgmodrstSpec;
impl crate::RegisterSpec for BrgmodrstSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`brgmodrst::R`](R) reader structure"]
impl crate::Readable for BrgmodrstSpec {}
#[doc = "`write(|w| ..)` method takes [`brgmodrst::W`](W) writer structure"]
impl crate::Writable for BrgmodrstSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets brgmodrst to value 0x07"]
impl crate::Resettable for BrgmodrstSpec {
    const RESET_VALUE: u32 = 0x07;
}
