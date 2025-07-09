// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_staticcfg` reader"]
pub type R = crate::R<CtrlgrpStaticcfgSpec>;
#[doc = "Register `ctrlgrp_staticcfg` writer"]
pub type W = crate::W<CtrlgrpStaticcfgSpec>;
#[doc = "Field `membl` reader - This field specifies the DRAM burst length. Write the following values to set the a burst length appropriate for the specific DRAM being used. &amp;quot;00&amp;quot; for burst length 2, &amp;quot;01&amp;quot; for burst length 4, &amp;quot;10&amp;quot; for burst length 8. If you set this, you must also set the membl field in the ctrlcfg register."]
pub type MemblR = crate::FieldReader;
#[doc = "Field `membl` writer - This field specifies the DRAM burst length. Write the following values to set the a burst length appropriate for the specific DRAM being used. &amp;quot;00&amp;quot; for burst length 2, &amp;quot;01&amp;quot; for burst length 4, &amp;quot;10&amp;quot; for burst length 8. If you set this, you must also set the membl field in the ctrlcfg register."]
pub type MemblW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `useeccasdata` reader - This field allows the FPGA ports to directly access the extra data bits that are normally used to hold the ECC code. The interface width must be set to 24 or 40 in the dramifwidth register. If you set this, you must clear the eccen field in the ctrlcfg register."]
pub type UseeccasdataR = crate::BitReader;
#[doc = "Field `useeccasdata` writer - This field allows the FPGA ports to directly access the extra data bits that are normally used to hold the ECC code. The interface width must be set to 24 or 40 in the dramifwidth register. If you set this, you must clear the eccen field in the ctrlcfg register."]
pub type UseeccasdataW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `applycfg` reader - Write with this bit set to apply all the settings loaded in SDR registers to the memory interface. This bit is write-only and always returns 0 if read."]
pub type ApplycfgR = crate::BitReader;
#[doc = "Field `applycfg` writer - Write with this bit set to apply all the settings loaded in SDR registers to the memory interface. This bit is write-only and always returns 0 if read."]
pub type ApplycfgW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - This field specifies the DRAM burst length. Write the following values to set the a burst length appropriate for the specific DRAM being used. &amp;quot;00&amp;quot; for burst length 2, &amp;quot;01&amp;quot; for burst length 4, &amp;quot;10&amp;quot; for burst length 8. If you set this, you must also set the membl field in the ctrlcfg register."]
    #[inline(always)]
    pub fn membl(&self) -> MemblR {
        MemblR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - This field allows the FPGA ports to directly access the extra data bits that are normally used to hold the ECC code. The interface width must be set to 24 or 40 in the dramifwidth register. If you set this, you must clear the eccen field in the ctrlcfg register."]
    #[inline(always)]
    pub fn useeccasdata(&self) -> UseeccasdataR {
        UseeccasdataR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Write with this bit set to apply all the settings loaded in SDR registers to the memory interface. This bit is write-only and always returns 0 if read."]
    #[inline(always)]
    pub fn applycfg(&self) -> ApplycfgR {
        ApplycfgR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - This field specifies the DRAM burst length. Write the following values to set the a burst length appropriate for the specific DRAM being used. &amp;quot;00&amp;quot; for burst length 2, &amp;quot;01&amp;quot; for burst length 4, &amp;quot;10&amp;quot; for burst length 8. If you set this, you must also set the membl field in the ctrlcfg register."]
    #[inline(always)]
    #[must_use]
    pub fn membl(&mut self) -> MemblW<CtrlgrpStaticcfgSpec> {
        MemblW::new(self, 0)
    }
    #[doc = "Bit 2 - This field allows the FPGA ports to directly access the extra data bits that are normally used to hold the ECC code. The interface width must be set to 24 or 40 in the dramifwidth register. If you set this, you must clear the eccen field in the ctrlcfg register."]
    #[inline(always)]
    #[must_use]
    pub fn useeccasdata(&mut self) -> UseeccasdataW<CtrlgrpStaticcfgSpec> {
        UseeccasdataW::new(self, 2)
    }
    #[doc = "Bit 3 - Write with this bit set to apply all the settings loaded in SDR registers to the memory interface. This bit is write-only and always returns 0 if read."]
    #[inline(always)]
    #[must_use]
    pub fn applycfg(&mut self) -> ApplycfgW<CtrlgrpStaticcfgSpec> {
        ApplycfgW::new(self, 3)
    }
}
#[doc = "This register controls configuration values which cannot be updated while transactions are flowing. You should write once to this register with the membl and eccen fields set to your desired configuration, and then write to the register again with membl and eccen and the applycfg bit set. The applycfg bit is write only.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_staticcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_staticcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpStaticcfgSpec;
impl crate::RegisterSpec for CtrlgrpStaticcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 20572u64;
}
#[doc = "`read()` method returns [`ctrlgrp_staticcfg::R`](R) reader structure"]
impl crate::Readable for CtrlgrpStaticcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_staticcfg::W`](W) writer structure"]
impl crate::Writable for CtrlgrpStaticcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_staticcfg to value 0"]
impl crate::Resettable for CtrlgrpStaticcfgSpec {
    const RESET_VALUE: u32 = 0;
}
