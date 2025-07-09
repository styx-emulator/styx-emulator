// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_por_reset_count` reader"]
pub type R = crate::R<ConfigPorResetCountSpec>;
#[doc = "Register `config_por_reset_count` writer"]
pub type W = crate::W<ConfigPorResetCountSpec>;
#[doc = "Field `value` reader - The controller waits for this number of cycles before issuing the first RESET command to the device. The number in this register is multiplied internally by 16 in the controller to form the final reset wait count."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - The controller waits for this number of cycles before issuing the first RESET command to the device. The number in this register is multiplied internally by 16 in the controller to form the final reset wait count."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - The controller waits for this number of cycles before issuing the first RESET command to the device. The number in this register is multiplied internally by 16 in the controller to form the final reset wait count."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - The controller waits for this number of cycles before issuing the first RESET command to the device. The number in this register is multiplied internally by 16 in the controller to form the final reset wait count."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigPorResetCountSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "The number of cycles the controller waits after reset to issue the first RESET command to the device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_por_reset_count::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_por_reset_count::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigPorResetCountSpec;
impl crate::RegisterSpec for ConfigPorResetCountSpec {
    type Ux = u32;
    const OFFSET: u64 = 672u64;
}
#[doc = "`read()` method returns [`config_por_reset_count::R`](R) reader structure"]
impl crate::Readable for ConfigPorResetCountSpec {}
#[doc = "`write(|w| ..)` method takes [`config_por_reset_count::W`](W) writer structure"]
impl crate::Writable for ConfigPorResetCountSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_por_reset_count to value 0x013b"]
impl crate::Resettable for ConfigPorResetCountSpec {
    const RESET_VALUE: u32 = 0x013b;
}
