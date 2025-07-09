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
#[doc = "Register `mastergrp_ocram_wr_tidemark` reader"]
pub type R = crate::R<MastergrpOcramWrTidemarkSpec>;
#[doc = "Register `mastergrp_ocram_wr_tidemark` writer"]
pub type W = crate::W<MastergrpOcramWrTidemarkSpec>;
#[doc = "Field `level` reader - Stalls the transaction in the write data FIFO until the number of occupied slots in the write data FIFO exceeds the level. Note that the transaction is released before this level is achieved if the network receives the WLAST beat or the write FIFO becomes full."]
pub type LevelR = crate::FieldReader;
#[doc = "Field `level` writer - Stalls the transaction in the write data FIFO until the number of occupied slots in the write data FIFO exceeds the level. Note that the transaction is released before this level is achieved if the network receives the WLAST beat or the write FIFO becomes full."]
pub type LevelW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Stalls the transaction in the write data FIFO until the number of occupied slots in the write data FIFO exceeds the level. Note that the transaction is released before this level is achieved if the network receives the WLAST beat or the write FIFO becomes full."]
    #[inline(always)]
    pub fn level(&self) -> LevelR {
        LevelR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Stalls the transaction in the write data FIFO until the number of occupied slots in the write data FIFO exceeds the level. Note that the transaction is released before this level is achieved if the network receives the WLAST beat or the write FIFO becomes full."]
    #[inline(always)]
    #[must_use]
    pub fn level(&mut self) -> LevelW<MastergrpOcramWrTidemarkSpec> {
        LevelW::new(self, 0)
    }
}
#[doc = "Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_ocram_wr_tidemark::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_ocram_wr_tidemark::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MastergrpOcramWrTidemarkSpec;
impl crate::RegisterSpec for MastergrpOcramWrTidemarkSpec {
    type Ux = u32;
    const OFFSET: u64 = 159808u64;
}
#[doc = "`read()` method returns [`mastergrp_ocram_wr_tidemark::R`](R) reader structure"]
impl crate::Readable for MastergrpOcramWrTidemarkSpec {}
#[doc = "`write(|w| ..)` method takes [`mastergrp_ocram_wr_tidemark::W`](W) writer structure"]
impl crate::Writable for MastergrpOcramWrTidemarkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mastergrp_ocram_wr_tidemark to value 0x04"]
impl crate::Resettable for MastergrpOcramWrTidemarkSpec {
    const RESET_VALUE: u32 = 0x04;
}
