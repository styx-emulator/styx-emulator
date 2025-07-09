// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `romcodegrp_cpu1startaddr` reader"]
pub type R = crate::R<RomcodegrpCpu1startaddrSpec>;
#[doc = "Register `romcodegrp_cpu1startaddr` writer"]
pub type W = crate::W<RomcodegrpCpu1startaddrSpec>;
#[doc = "Field `value` reader - Address for CPU1 to start executing at after coming out of reset."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Address for CPU1 to start executing at after coming out of reset."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Address for CPU1 to start executing at after coming out of reset."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Address for CPU1 to start executing at after coming out of reset."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<RomcodegrpCpu1startaddrSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "When CPU1 is released from reset and the Boot ROM is located at the CPU1 reset exception address (the typical case), the Boot ROM reset handler code reads the address stored in this register and jumps it to hand off execution to user software.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_cpu1startaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_cpu1startaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpCpu1startaddrSpec;
impl crate::RegisterSpec for RomcodegrpCpu1startaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 196u64;
}
#[doc = "`read()` method returns [`romcodegrp_cpu1startaddr::R`](R) reader structure"]
impl crate::Readable for RomcodegrpCpu1startaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_cpu1startaddr::W`](W) writer structure"]
impl crate::Writable for RomcodegrpCpu1startaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_cpu1startaddr to value 0"]
impl crate::Resettable for RomcodegrpCpu1startaddrSpec {
    const RESET_VALUE: u32 = 0;
}
