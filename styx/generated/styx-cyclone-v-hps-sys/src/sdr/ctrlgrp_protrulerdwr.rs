// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_protrulerdwr` reader"]
pub type R = crate::R<CtrlgrpProtrulerdwrSpec>;
#[doc = "Register `ctrlgrp_protrulerdwr` writer"]
pub type W = crate::W<CtrlgrpProtrulerdwrSpec>;
#[doc = "Field `ruleoffset` reader - This field defines which of the 20 rules in the protection table you want to read or write."]
pub type RuleoffsetR = crate::FieldReader;
#[doc = "Field `ruleoffset` writer - This field defines which of the 20 rules in the protection table you want to read or write."]
pub type RuleoffsetW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `writerule` reader - Write to this bit to have the memory_prot_data register to the table at the offset specified by port_offset. Bit automatically clears after a single cycle and the write operation is complete."]
pub type WriteruleR = crate::BitReader;
#[doc = "Field `writerule` writer - Write to this bit to have the memory_prot_data register to the table at the offset specified by port_offset. Bit automatically clears after a single cycle and the write operation is complete."]
pub type WriteruleW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `readrule` reader - Write to this bit to have the memory_prot_data register loaded with the value from the internal protection table at offset. Table value will be loaded before a rdy is returned so read data from the register will be correct for any follow-on reads to the memory_prot_data register."]
pub type ReadruleR = crate::BitReader;
#[doc = "Field `readrule` writer - Write to this bit to have the memory_prot_data register loaded with the value from the internal protection table at offset. Table value will be loaded before a rdy is returned so read data from the register will be correct for any follow-on reads to the memory_prot_data register."]
pub type ReadruleW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - This field defines which of the 20 rules in the protection table you want to read or write."]
    #[inline(always)]
    pub fn ruleoffset(&self) -> RuleoffsetR {
        RuleoffsetR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bit 5 - Write to this bit to have the memory_prot_data register to the table at the offset specified by port_offset. Bit automatically clears after a single cycle and the write operation is complete."]
    #[inline(always)]
    pub fn writerule(&self) -> WriteruleR {
        WriteruleR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Write to this bit to have the memory_prot_data register loaded with the value from the internal protection table at offset. Table value will be loaded before a rdy is returned so read data from the register will be correct for any follow-on reads to the memory_prot_data register."]
    #[inline(always)]
    pub fn readrule(&self) -> ReadruleR {
        ReadruleR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - This field defines which of the 20 rules in the protection table you want to read or write."]
    #[inline(always)]
    #[must_use]
    pub fn ruleoffset(&mut self) -> RuleoffsetW<CtrlgrpProtrulerdwrSpec> {
        RuleoffsetW::new(self, 0)
    }
    #[doc = "Bit 5 - Write to this bit to have the memory_prot_data register to the table at the offset specified by port_offset. Bit automatically clears after a single cycle and the write operation is complete."]
    #[inline(always)]
    #[must_use]
    pub fn writerule(&mut self) -> WriteruleW<CtrlgrpProtrulerdwrSpec> {
        WriteruleW::new(self, 5)
    }
    #[doc = "Bit 6 - Write to this bit to have the memory_prot_data register loaded with the value from the internal protection table at offset. Table value will be loaded before a rdy is returned so read data from the register will be correct for any follow-on reads to the memory_prot_data register."]
    #[inline(always)]
    #[must_use]
    pub fn readrule(&mut self) -> ReadruleW<CtrlgrpProtrulerdwrSpec> {
        ReadruleW::new(self, 6)
    }
}
#[doc = "This register is used to perform read and write operations to the internal protection table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protrulerdwr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protrulerdwr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpProtrulerdwrSpec;
impl crate::RegisterSpec for CtrlgrpProtrulerdwrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20636u64;
}
#[doc = "`read()` method returns [`ctrlgrp_protrulerdwr::R`](R) reader structure"]
impl crate::Readable for CtrlgrpProtrulerdwrSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_protrulerdwr::W`](W) writer structure"]
impl crate::Writable for CtrlgrpProtrulerdwrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_protrulerdwr to value 0"]
impl crate::Resettable for CtrlgrpProtrulerdwrSpec {
    const RESET_VALUE: u32 = 0;
}
