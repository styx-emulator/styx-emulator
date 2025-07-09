// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_persecurity` reader"]
pub type R = crate::R<DmagrpPersecuritySpec>;
#[doc = "Register `dmagrp_persecurity` writer"]
pub type W = crate::W<DmagrpPersecuritySpec>;
#[doc = "Field `nonsecure` reader - If bit index \\[x\\]
is 0, the DMA controller assigns peripheral request interface x to the Secure state. If bit index \\[x\\]
is 1, the DMA controller assigns peripheral request interface x to the Non-secure state. Reset by a cold or warm reset."]
pub type NonsecureR = crate::FieldReader<u32>;
#[doc = "Field `nonsecure` writer - If bit index \\[x\\]
is 0, the DMA controller assigns peripheral request interface x to the Secure state. If bit index \\[x\\]
is 1, the DMA controller assigns peripheral request interface x to the Non-secure state. Reset by a cold or warm reset."]
pub type NonsecureW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - If bit index \\[x\\]
is 0, the DMA controller assigns peripheral request interface x to the Secure state. If bit index \\[x\\]
is 1, the DMA controller assigns peripheral request interface x to the Non-secure state. Reset by a cold or warm reset."]
    #[inline(always)]
    pub fn nonsecure(&self) -> NonsecureR {
        NonsecureR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - If bit index \\[x\\]
is 0, the DMA controller assigns peripheral request interface x to the Secure state. If bit index \\[x\\]
is 1, the DMA controller assigns peripheral request interface x to the Non-secure state. Reset by a cold or warm reset."]
    #[inline(always)]
    #[must_use]
    pub fn nonsecure(&mut self) -> NonsecureW<DmagrpPersecuritySpec> {
        NonsecureW::new(self, 0)
    }
}
#[doc = "Controls the security state of a peripheral request interface. Sampled by the DMA controller when it exits from reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_persecurity::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_persecurity::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpPersecuritySpec;
impl crate::RegisterSpec for DmagrpPersecuritySpec {
    type Ux = u32;
    const OFFSET: u64 = 116u64;
}
#[doc = "`read()` method returns [`dmagrp_persecurity::R`](R) reader structure"]
impl crate::Readable for DmagrpPersecuritySpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_persecurity::W`](W) writer structure"]
impl crate::Writable for DmagrpPersecuritySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_persecurity to value 0"]
impl crate::Resettable for DmagrpPersecuritySpec {
    const RESET_VALUE: u32 = 0;
}
