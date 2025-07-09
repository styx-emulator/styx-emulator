// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_SPIM0USEFPGA` reader"]
pub type R = crate::R<PinmuxgrpSpim0usefpgaSpec>;
#[doc = "Register `pinmuxgrp_SPIM0USEFPGA` writer"]
pub type W = crate::W<PinmuxgrpSpim0usefpgaSpec>;
#[doc = "Field `sel` reader - Select connection for SPIM0. 0 : SPIM0 uses HPS Pins. 1 : SPIM0 uses the FPGA Inteface."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select connection for SPIM0. 0 : SPIM0 uses HPS Pins. 1 : SPIM0 uses the FPGA Inteface."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select connection for SPIM0. 0 : SPIM0 uses HPS Pins. 1 : SPIM0 uses the FPGA Inteface."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select connection for SPIM0. 0 : SPIM0 uses HPS Pins. 1 : SPIM0 uses the FPGA Inteface."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpSpim0usefpgaSpec> {
        SelW::new(self, 0)
    }
}
#[doc = "Selection between HPS Pins and FPGA Interface for SPIM0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_spim0usefpga::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_spim0usefpga::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpSpim0usefpgaSpec;
impl crate::RegisterSpec for PinmuxgrpSpim0usefpgaSpec {
    type Ux = u32;
    const OFFSET: u64 = 1848u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_spim0usefpga::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpSpim0usefpgaSpec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_spim0usefpga::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpSpim0usefpgaSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_SPIM0USEFPGA to value 0"]
impl crate::Resettable for PinmuxgrpSpim0usefpgaSpec {
    const RESET_VALUE: u32 = 0;
}
