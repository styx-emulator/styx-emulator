// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_lun_status_cmd` reader"]
pub type R = crate::R<DmaLunStatusCmdSpec>;
#[doc = "Register `dma_lun_status_cmd` writer"]
pub type W = crate::W<DmaLunStatusCmdSpec>;
#[doc = "Field `value` reader - list\\]\\[*\\]7:0 - Indicates the command to check the status of the first LUN/Die. \\[*\\]15:8 - Indicates the command to check the status of the other LUN/Die.\\[/list\\]"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - list\\]\\[*\\]7:0 - Indicates the command to check the status of the first LUN/Die. \\[*\\]15:8 - Indicates the command to check the status of the other LUN/Die.\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - list\\]\\[*\\]7:0 - Indicates the command to check the status of the first LUN/Die. \\[*\\]15:8 - Indicates the command to check the status of the other LUN/Die.\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - list\\]\\[*\\]7:0 - Indicates the command to check the status of the first LUN/Die. \\[*\\]15:8 - Indicates the command to check the status of the other LUN/Die.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DmaLunStatusCmdSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Indicates the command to be sent while checking status of the next LUN.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_lun_status_cmd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_lun_status_cmd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaLunStatusCmdSpec;
impl crate::RegisterSpec for DmaLunStatusCmdSpec {
    type Ux = u32;
    const OFFSET: u64 = 1952u64;
}
#[doc = "`read()` method returns [`dma_lun_status_cmd::R`](R) reader structure"]
impl crate::Readable for DmaLunStatusCmdSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_lun_status_cmd::W`](W) writer structure"]
impl crate::Writable for DmaLunStatusCmdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dma_lun_status_cmd to value 0x7878"]
impl crate::Resettable for DmaLunStatusCmdSpec {
    const RESET_VALUE: u32 = 0x7878;
}
