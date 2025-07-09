// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_RGMII0USEFPGA` reader"]
pub type R = crate::R<PinmuxgrpRgmii0usefpgaSpec>;
#[doc = "Register `pinmuxgrp_RGMII0USEFPGA` writer"]
pub type W = crate::W<PinmuxgrpRgmii0usefpgaSpec>;
#[doc = "Field `sel` reader - Select connection for RGMII0. 0 : RGMII0 uses HPS Pins. 1 : RGMII0 uses the FPGA Inteface."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select connection for RGMII0. 0 : RGMII0 uses HPS Pins. 1 : RGMII0 uses the FPGA Inteface."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select connection for RGMII0. 0 : RGMII0 uses HPS Pins. 1 : RGMII0 uses the FPGA Inteface."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select connection for RGMII0. 0 : RGMII0 uses HPS Pins. 1 : RGMII0 uses the FPGA Inteface."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpRgmii0usefpgaSpec> {
        SelW::new(self, 0)
    }
}
#[doc = "Selection between HPS Pins and FPGA Interface for RGMII0 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_rgmii0usefpga::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_rgmii0usefpga::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpRgmii0usefpgaSpec;
impl crate::RegisterSpec for PinmuxgrpRgmii0usefpgaSpec {
    type Ux = u32;
    const OFFSET: u64 = 1812u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_rgmii0usefpga::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpRgmii0usefpgaSpec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_rgmii0usefpga::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpRgmii0usefpgaSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_RGMII0USEFPGA to value 0"]
impl crate::Resettable for PinmuxgrpRgmii0usefpgaSpec {
    const RESET_VALUE: u32 = 0;
}
