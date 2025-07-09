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
#[doc = "Register `ctrlgrp_protruledata` reader"]
pub type R = crate::R<CtrlgrpProtruledataSpec>;
#[doc = "Register `ctrlgrp_protruledata` writer"]
pub type W = crate::W<CtrlgrpProtruledataSpec>;
#[doc = "Field `security` reader - A value of 2'b00 will make the rule apply to secure transactions. A value of 2'b01 will make the rule apply to non-secure transactions. A value of 2'b10 or 2'b11 will make the rule apply to secure and non-secure transactions."]
pub type SecurityR = crate::FieldReader;
#[doc = "Field `security` writer - A value of 2'b00 will make the rule apply to secure transactions. A value of 2'b01 will make the rule apply to non-secure transactions. A value of 2'b10 or 2'b11 will make the rule apply to secure and non-secure transactions."]
pub type SecurityW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `validrule` reader - Set to bit to a one to make a rule valid, set to a zero to invalidate a rule."]
pub type ValidruleR = crate::BitReader;
#[doc = "Field `validrule` writer - Set to bit to a one to make a rule valid, set to a zero to invalidate a rule."]
pub type ValidruleW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `portmask` reader - Set bit x to a one to have this rule apply to port x, set bit x to a zero to have the rule not apply to a port.&amp;#10;Note that port 0-port 5 are the FPGA fabric ports, port 6 is L3 read, port 7 is CPU read, port 8 is L3 write, port 9 is CPU write."]
pub type PortmaskR = crate::FieldReader<u16>;
#[doc = "Field `portmask` writer - Set bit x to a one to have this rule apply to port x, set bit x to a zero to have the rule not apply to a port.&amp;#10;Note that port 0-port 5 are the FPGA fabric ports, port 6 is L3 read, port 7 is CPU read, port 8 is L3 write, port 9 is CPU write."]
pub type PortmaskW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `ruleresult` reader - Set this bit to a one to force a protection failure, zero to allow the access the succeed"]
pub type RuleresultR = crate::BitReader;
#[doc = "Field `ruleresult` writer - Set this bit to a one to force a protection failure, zero to allow the access the succeed"]
pub type RuleresultW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - A value of 2'b00 will make the rule apply to secure transactions. A value of 2'b01 will make the rule apply to non-secure transactions. A value of 2'b10 or 2'b11 will make the rule apply to secure and non-secure transactions."]
    #[inline(always)]
    pub fn security(&self) -> SecurityR {
        SecurityR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - Set to bit to a one to make a rule valid, set to a zero to invalidate a rule."]
    #[inline(always)]
    pub fn validrule(&self) -> ValidruleR {
        ValidruleR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:12 - Set bit x to a one to have this rule apply to port x, set bit x to a zero to have the rule not apply to a port.&amp;#10;Note that port 0-port 5 are the FPGA fabric ports, port 6 is L3 read, port 7 is CPU read, port 8 is L3 write, port 9 is CPU write."]
    #[inline(always)]
    pub fn portmask(&self) -> PortmaskR {
        PortmaskR::new(((self.bits >> 3) & 0x03ff) as u16)
    }
    #[doc = "Bit 13 - Set this bit to a one to force a protection failure, zero to allow the access the succeed"]
    #[inline(always)]
    pub fn ruleresult(&self) -> RuleresultR {
        RuleresultR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - A value of 2'b00 will make the rule apply to secure transactions. A value of 2'b01 will make the rule apply to non-secure transactions. A value of 2'b10 or 2'b11 will make the rule apply to secure and non-secure transactions."]
    #[inline(always)]
    #[must_use]
    pub fn security(&mut self) -> SecurityW<CtrlgrpProtruledataSpec> {
        SecurityW::new(self, 0)
    }
    #[doc = "Bit 2 - Set to bit to a one to make a rule valid, set to a zero to invalidate a rule."]
    #[inline(always)]
    #[must_use]
    pub fn validrule(&mut self) -> ValidruleW<CtrlgrpProtruledataSpec> {
        ValidruleW::new(self, 2)
    }
    #[doc = "Bits 3:12 - Set bit x to a one to have this rule apply to port x, set bit x to a zero to have the rule not apply to a port.&amp;#10;Note that port 0-port 5 are the FPGA fabric ports, port 6 is L3 read, port 7 is CPU read, port 8 is L3 write, port 9 is CPU write."]
    #[inline(always)]
    #[must_use]
    pub fn portmask(&mut self) -> PortmaskW<CtrlgrpProtruledataSpec> {
        PortmaskW::new(self, 3)
    }
    #[doc = "Bit 13 - Set this bit to a one to force a protection failure, zero to allow the access the succeed"]
    #[inline(always)]
    #[must_use]
    pub fn ruleresult(&mut self) -> RuleresultW<CtrlgrpProtruledataSpec> {
        RuleresultW::new(self, 13)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protruledata::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protruledata::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpProtruledataSpec;
impl crate::RegisterSpec for CtrlgrpProtruledataSpec {
    type Ux = u32;
    const OFFSET: u64 = 20632u64;
}
#[doc = "`read()` method returns [`ctrlgrp_protruledata::R`](R) reader structure"]
impl crate::Readable for CtrlgrpProtruledataSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_protruledata::W`](W) writer structure"]
impl crate::Writable for CtrlgrpProtruledataSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_protruledata to value 0"]
impl crate::Resettable for CtrlgrpProtruledataSpec {
    const RESET_VALUE: u32 = 0;
}
