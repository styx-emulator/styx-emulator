// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_write_mode` reader"]
pub type R = crate::R<ConfigWriteModeSpec>;
#[doc = "Register `config_write_mode` writer"]
pub type W = crate::W<ConfigWriteModeSpec>;
#[doc = "Field `value` reader - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the pipe write sequence to follow is of a normal write with the following sequence, C80, Address, Data, C10..... \\[*\\]4'h1 - This value informs the controller that the pipe write sequence to follow is of a Cache Program with the following sequence, C80, Address, Data, C15, ....., C80, Address, Data, C10. \\[*\\]4'h2 - This value informs the controller that the pipe write sequence to follow is of a Two/Four Plane Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C10..... \\[*\\]4'h3 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C10..... \\[*\\]4'h4 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C15.....C80, Address, Data, C11, C80, Address, Data, C10. \\[*\\]4'h5 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C15.....C80, Address, Data, C11, C81, Address, Data, C10. \\[*\\]4'h6 - 4'h15 - Reserved. \\[/list\\]
..... indicates that the previous sequence is repeated till the last page."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the pipe write sequence to follow is of a normal write with the following sequence, C80, Address, Data, C10..... \\[*\\]4'h1 - This value informs the controller that the pipe write sequence to follow is of a Cache Program with the following sequence, C80, Address, Data, C15, ....., C80, Address, Data, C10. \\[*\\]4'h2 - This value informs the controller that the pipe write sequence to follow is of a Two/Four Plane Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C10..... \\[*\\]4'h3 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C10..... \\[*\\]4'h4 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C15.....C80, Address, Data, C11, C80, Address, Data, C10. \\[*\\]4'h5 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C15.....C80, Address, Data, C11, C81, Address, Data, C10. \\[*\\]4'h6 - 4'h15 - Reserved. \\[/list\\]
..... indicates that the previous sequence is repeated till the last page."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the pipe write sequence to follow is of a normal write with the following sequence, C80, Address, Data, C10..... \\[*\\]4'h1 - This value informs the controller that the pipe write sequence to follow is of a Cache Program with the following sequence, C80, Address, Data, C15, ....., C80, Address, Data, C10. \\[*\\]4'h2 - This value informs the controller that the pipe write sequence to follow is of a Two/Four Plane Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C10..... \\[*\\]4'h3 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C10..... \\[*\\]4'h4 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C15.....C80, Address, Data, C11, C80, Address, Data, C10. \\[*\\]4'h5 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C15.....C80, Address, Data, C11, C81, Address, Data, C10. \\[*\\]4'h6 - 4'h15 - Reserved. \\[/list\\]
..... indicates that the previous sequence is repeated till the last page."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the pipe write sequence to follow is of a normal write with the following sequence, C80, Address, Data, C10..... \\[*\\]4'h1 - This value informs the controller that the pipe write sequence to follow is of a Cache Program with the following sequence, C80, Address, Data, C15, ....., C80, Address, Data, C10. \\[*\\]4'h2 - This value informs the controller that the pipe write sequence to follow is of a Two/Four Plane Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C10..... \\[*\\]4'h3 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C10..... \\[*\\]4'h4 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C80, Address, Data, C15.....C80, Address, Data, C11, C80, Address, Data, C10. \\[*\\]4'h5 - This value informs the controller that the pipe write sequence to follow is of a 'N' Plane Cache Program with the following sequence, C80, Address, Data, C11, C81, Address, Data, C15.....C80, Address, Data, C11, C81, Address, Data, C10. \\[*\\]4'h6 - 4'h15 - Reserved. \\[/list\\]
..... indicates that the previous sequence is repeated till the last page."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigWriteModeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "The type of write sequence that the controller will follow for pipe write commands.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_write_mode::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_write_mode::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigWriteModeSpec;
impl crate::RegisterSpec for ConfigWriteModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 464u64;
}
#[doc = "`read()` method returns [`config_write_mode::R`](R) reader structure"]
impl crate::Readable for ConfigWriteModeSpec {}
#[doc = "`write(|w| ..)` method takes [`config_write_mode::W`](W) writer structure"]
impl crate::Writable for ConfigWriteModeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_write_mode to value 0"]
impl crate::Resettable for ConfigWriteModeSpec {
    const RESET_VALUE: u32 = 0;
}
