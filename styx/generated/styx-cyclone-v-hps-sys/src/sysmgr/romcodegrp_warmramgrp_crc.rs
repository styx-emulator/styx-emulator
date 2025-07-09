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
#[doc = "Register `romcodegrp_warmramgrp_crc` reader"]
pub type R = crate::R<RomcodegrpWarmramgrpCrcSpec>;
#[doc = "Register `romcodegrp_warmramgrp_crc` writer"]
pub type W = crate::W<RomcodegrpWarmramgrpCrcSpec>;
#[doc = "Field `expected` reader - Contains the expected CRC of the region in the On-chip RAM.The Boot ROM code calculates the actual CRC for all bytes in the region specified by the DATA START an LENGTH registers. The contents of the EXECUTION register (after it has been read and modified by the Boot ROM code) is also included in the CRC calculation. The contents of the EXECUTION register is added to the CRC accumulator a byte at a time starting with the least significant byte. If the actual CRC doesn't match the expected CRC value in this register, the Boot ROM won't boot from the On-chip RAM. The CRC is a standard CRC32 with the polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1 There is no reflection of the bits and the initial value of the remainder is 0xFFFFFFFF and the final value is exclusive ORed with 0xFFFFFFFF."]
pub type ExpectedR = crate::FieldReader<u32>;
#[doc = "Field `expected` writer - Contains the expected CRC of the region in the On-chip RAM.The Boot ROM code calculates the actual CRC for all bytes in the region specified by the DATA START an LENGTH registers. The contents of the EXECUTION register (after it has been read and modified by the Boot ROM code) is also included in the CRC calculation. The contents of the EXECUTION register is added to the CRC accumulator a byte at a time starting with the least significant byte. If the actual CRC doesn't match the expected CRC value in this register, the Boot ROM won't boot from the On-chip RAM. The CRC is a standard CRC32 with the polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1 There is no reflection of the bits and the initial value of the remainder is 0xFFFFFFFF and the final value is exclusive ORed with 0xFFFFFFFF."]
pub type ExpectedW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Contains the expected CRC of the region in the On-chip RAM.The Boot ROM code calculates the actual CRC for all bytes in the region specified by the DATA START an LENGTH registers. The contents of the EXECUTION register (after it has been read and modified by the Boot ROM code) is also included in the CRC calculation. The contents of the EXECUTION register is added to the CRC accumulator a byte at a time starting with the least significant byte. If the actual CRC doesn't match the expected CRC value in this register, the Boot ROM won't boot from the On-chip RAM. The CRC is a standard CRC32 with the polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1 There is no reflection of the bits and the initial value of the remainder is 0xFFFFFFFF and the final value is exclusive ORed with 0xFFFFFFFF."]
    #[inline(always)]
    pub fn expected(&self) -> ExpectedR {
        ExpectedR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Contains the expected CRC of the region in the On-chip RAM.The Boot ROM code calculates the actual CRC for all bytes in the region specified by the DATA START an LENGTH registers. The contents of the EXECUTION register (after it has been read and modified by the Boot ROM code) is also included in the CRC calculation. The contents of the EXECUTION register is added to the CRC accumulator a byte at a time starting with the least significant byte. If the actual CRC doesn't match the expected CRC value in this register, the Boot ROM won't boot from the On-chip RAM. The CRC is a standard CRC32 with the polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1 There is no reflection of the bits and the initial value of the remainder is 0xFFFFFFFF and the final value is exclusive ORed with 0xFFFFFFFF."]
    #[inline(always)]
    #[must_use]
    pub fn expected(&mut self) -> ExpectedW<RomcodegrpWarmramgrpCrcSpec> {
        ExpectedW::new(self, 0)
    }
}
#[doc = "Length of region in On-chip RAM for CRC validation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_crc::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_crc::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpWarmramgrpCrcSpec;
impl crate::RegisterSpec for RomcodegrpWarmramgrpCrcSpec {
    type Ux = u32;
    const OFFSET: u64 = 240u64;
}
#[doc = "`read()` method returns [`romcodegrp_warmramgrp_crc::R`](R) reader structure"]
impl crate::Readable for RomcodegrpWarmramgrpCrcSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_warmramgrp_crc::W`](W) writer structure"]
impl crate::Writable for RomcodegrpWarmramgrpCrcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_warmramgrp_crc to value 0xe763_552a"]
impl crate::Resettable for RomcodegrpWarmramgrpCrcSpec {
    const RESET_VALUE: u32 = 0xe763_552a;
}
