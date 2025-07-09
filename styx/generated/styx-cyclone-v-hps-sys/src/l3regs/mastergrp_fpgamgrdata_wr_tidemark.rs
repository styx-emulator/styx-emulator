// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mastergrp_fpgamgrdata_wr_tidemark` reader"]
pub type R = crate::R<MastergrpFpgamgrdataWrTidemarkSpec>;
#[doc = "Register `mastergrp_fpgamgrdata_wr_tidemark` writer"]
pub type W = crate::W<MastergrpFpgamgrdataWrTidemarkSpec>;
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
    pub fn level(&mut self) -> LevelW<MastergrpFpgamgrdataWrTidemarkSpec> {
        LevelW::new(self, 0)
    }
}
#[doc = "Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_fpgamgrdata_wr_tidemark::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_fpgamgrdata_wr_tidemark::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MastergrpFpgamgrdataWrTidemarkSpec;
impl crate::RegisterSpec for MastergrpFpgamgrdataWrTidemarkSpec {
    type Ux = u32;
    const OFFSET: u64 = 143424u64;
}
#[doc = "`read()` method returns [`mastergrp_fpgamgrdata_wr_tidemark::R`](R) reader structure"]
impl crate::Readable for MastergrpFpgamgrdataWrTidemarkSpec {}
#[doc = "`write(|w| ..)` method takes [`mastergrp_fpgamgrdata_wr_tidemark::W`](W) writer structure"]
impl crate::Writable for MastergrpFpgamgrdataWrTidemarkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mastergrp_fpgamgrdata_wr_tidemark to value 0x04"]
impl crate::Resettable for MastergrpFpgamgrdataWrTidemarkSpec {
    const RESET_VALUE: u32 = 0x04;
}
