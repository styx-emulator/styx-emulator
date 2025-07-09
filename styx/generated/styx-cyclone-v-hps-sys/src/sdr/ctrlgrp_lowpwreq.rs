// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_lowpwreq` reader"]
pub type R = crate::R<CtrlgrpLowpwreqSpec>;
#[doc = "Register `ctrlgrp_lowpwreq` writer"]
pub type W = crate::W<CtrlgrpLowpwreqSpec>;
#[doc = "Field `deeppwrdnreq` reader - Write a one to this bit to request a deep power down. This bit should only be written with LPDDR2 DRAMs, DDR3 DRAMs do not support deep power down."]
pub type DeeppwrdnreqR = crate::BitReader;
#[doc = "Field `deeppwrdnreq` writer - Write a one to this bit to request a deep power down. This bit should only be written with LPDDR2 DRAMs, DDR3 DRAMs do not support deep power down."]
pub type DeeppwrdnreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `deeppwrdnmask` reader - Write ones to this register to select which DRAM chip selects will be powered down. Typical usage is to set both of these bits when deeppwrdnreq is set but the controller does support putting a single chip into deep power down and keeping the other chip running."]
pub type DeeppwrdnmaskR = crate::FieldReader;
#[doc = "Field `deeppwrdnmask` writer - Write ones to this register to select which DRAM chip selects will be powered down. Typical usage is to set both of these bits when deeppwrdnreq is set but the controller does support putting a single chip into deep power down and keeping the other chip running."]
pub type DeeppwrdnmaskW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `selfrshreq` reader - Write a one to this bit to request the RAM be put into a self refresh state. This bit is treated as a static value so the RAM will remain in self-refresh as long as this register bit is set to a one. This power down mode can be selected for all DRAMs supported by the controller."]
pub type SelfrshreqR = crate::BitReader;
#[doc = "Field `selfrshreq` writer - Write a one to this bit to request the RAM be put into a self refresh state. This bit is treated as a static value so the RAM will remain in self-refresh as long as this register bit is set to a one. This power down mode can be selected for all DRAMs supported by the controller."]
pub type SelfrshreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `selfrfshmask` reader - Write a one to each bit of this field to have a self refresh request apply to both chips."]
pub type SelfrfshmaskR = crate::FieldReader;
#[doc = "Field `selfrfshmask` writer - Write a one to each bit of this field to have a self refresh request apply to both chips."]
pub type SelfrfshmaskW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Write a one to this bit to request a deep power down. This bit should only be written with LPDDR2 DRAMs, DDR3 DRAMs do not support deep power down."]
    #[inline(always)]
    pub fn deeppwrdnreq(&self) -> DeeppwrdnreqR {
        DeeppwrdnreqR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Write ones to this register to select which DRAM chip selects will be powered down. Typical usage is to set both of these bits when deeppwrdnreq is set but the controller does support putting a single chip into deep power down and keeping the other chip running."]
    #[inline(always)]
    pub fn deeppwrdnmask(&self) -> DeeppwrdnmaskR {
        DeeppwrdnmaskR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 3 - Write a one to this bit to request the RAM be put into a self refresh state. This bit is treated as a static value so the RAM will remain in self-refresh as long as this register bit is set to a one. This power down mode can be selected for all DRAMs supported by the controller."]
    #[inline(always)]
    pub fn selfrshreq(&self) -> SelfrshreqR {
        SelfrshreqR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:5 - Write a one to each bit of this field to have a self refresh request apply to both chips."]
    #[inline(always)]
    pub fn selfrfshmask(&self) -> SelfrfshmaskR {
        SelfrfshmaskR::new(((self.bits >> 4) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Write a one to this bit to request a deep power down. This bit should only be written with LPDDR2 DRAMs, DDR3 DRAMs do not support deep power down."]
    #[inline(always)]
    #[must_use]
    pub fn deeppwrdnreq(&mut self) -> DeeppwrdnreqW<CtrlgrpLowpwreqSpec> {
        DeeppwrdnreqW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Write ones to this register to select which DRAM chip selects will be powered down. Typical usage is to set both of these bits when deeppwrdnreq is set but the controller does support putting a single chip into deep power down and keeping the other chip running."]
    #[inline(always)]
    #[must_use]
    pub fn deeppwrdnmask(&mut self) -> DeeppwrdnmaskW<CtrlgrpLowpwreqSpec> {
        DeeppwrdnmaskW::new(self, 1)
    }
    #[doc = "Bit 3 - Write a one to this bit to request the RAM be put into a self refresh state. This bit is treated as a static value so the RAM will remain in self-refresh as long as this register bit is set to a one. This power down mode can be selected for all DRAMs supported by the controller."]
    #[inline(always)]
    #[must_use]
    pub fn selfrshreq(&mut self) -> SelfrshreqW<CtrlgrpLowpwreqSpec> {
        SelfrshreqW::new(self, 3)
    }
    #[doc = "Bits 4:5 - Write a one to each bit of this field to have a self refresh request apply to both chips."]
    #[inline(always)]
    #[must_use]
    pub fn selfrfshmask(&mut self) -> SelfrfshmaskW<CtrlgrpLowpwreqSpec> {
        SelfrfshmaskW::new(self, 4)
    }
}
#[doc = "This register instructs the controller to put the DRAM into a power down state. Note that some commands are only valid for certain memory types.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwreq::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwreq::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpLowpwreqSpec;
impl crate::RegisterSpec for CtrlgrpLowpwreqSpec {
    type Ux = u32;
    const OFFSET: u64 = 20564u64;
}
#[doc = "`read()` method returns [`ctrlgrp_lowpwreq::R`](R) reader structure"]
impl crate::Readable for CtrlgrpLowpwreqSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_lowpwreq::W`](W) writer structure"]
impl crate::Writable for CtrlgrpLowpwreqSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_lowpwreq to value 0"]
impl crate::Resettable for CtrlgrpLowpwreqSpec {
    const RESET_VALUE: u32 = 0;
}
