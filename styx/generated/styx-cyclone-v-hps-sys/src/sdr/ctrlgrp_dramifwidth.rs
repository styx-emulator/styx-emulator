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
#[doc = "Register `ctrlgrp_dramifwidth` reader"]
pub type R = crate::R<CtrlgrpDramifwidthSpec>;
#[doc = "Register `ctrlgrp_dramifwidth` writer"]
pub type W = crate::W<CtrlgrpDramifwidthSpec>;
#[doc = "Field `ifwidth` reader - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
pub type IfwidthR = crate::FieldReader;
#[doc = "Field `ifwidth` writer - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
pub type IfwidthW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
    #[inline(always)]
    pub fn ifwidth(&self) -> IfwidthR {
        IfwidthR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
    #[inline(always)]
    #[must_use]
    pub fn ifwidth(&mut self) -> IfwidthW<CtrlgrpDramifwidthSpec> {
        IfwidthW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramifwidth::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramifwidth::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramifwidthSpec;
impl crate::RegisterSpec for CtrlgrpDramifwidthSpec {
    type Ux = u32;
    const OFFSET: u64 = 20528u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramifwidth::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramifwidthSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramifwidth::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramifwidthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramifwidth to value 0"]
impl crate::Resettable for CtrlgrpDramifwidthSpec {
    const RESET_VALUE: u32 = 0;
}
