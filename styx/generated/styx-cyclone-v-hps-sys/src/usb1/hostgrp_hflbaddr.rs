// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `hostgrp_hflbaddr` reader"]
pub type R = crate::R<HostgrpHflbaddrSpec>;
#[doc = "Register `hostgrp_hflbaddr` writer"]
pub type W = crate::W<HostgrpHflbaddrSpec>;
#[doc = "Field `hflbaddr` reader - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
pub type HflbaddrR = crate::FieldReader<u32>;
#[doc = "Field `hflbaddr` writer - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
pub type HflbaddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
    #[inline(always)]
    pub fn hflbaddr(&self) -> HflbaddrR {
        HflbaddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
    #[inline(always)]
    #[must_use]
    pub fn hflbaddr(&mut self) -> HflbaddrW<HostgrpHflbaddrSpec> {
        HflbaddrW::new(self, 0)
    }
}
#[doc = "This Register is valid only for Host mode Scatter-Gather DMA. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hflbaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hflbaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHflbaddrSpec;
impl crate::RegisterSpec for HostgrpHflbaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 1052u64;
}
#[doc = "`read()` method returns [`hostgrp_hflbaddr::R`](R) reader structure"]
impl crate::Readable for HostgrpHflbaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hflbaddr::W`](W) writer structure"]
impl crate::Writable for HostgrpHflbaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hflbaddr to value 0"]
impl crate::Resettable for HostgrpHflbaddrSpec {
    const RESET_VALUE: u32 = 0;
}
