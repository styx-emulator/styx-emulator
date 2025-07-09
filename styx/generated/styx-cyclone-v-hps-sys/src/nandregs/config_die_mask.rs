// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_die_mask` reader"]
pub type R = crate::R<ConfigDieMaskSpec>;
#[doc = "Register `config_die_mask` writer"]
pub type W = crate::W<ConfigDieMaskSpec>;
#[doc = "Field `value` reader - The die_mask register information will be used for devices having address restrictions. For example, in certain Samsung devices, when the first address in a two-plane command is being sent, it is expected that the address is all zeros. But if the NAND device internally has multiple dies stacked, the die information (MSB of final row address) has to be sent. The value programmed in this register will be used to mask the address while sending out the last row address."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - The die_mask register information will be used for devices having address restrictions. For example, in certain Samsung devices, when the first address in a two-plane command is being sent, it is expected that the address is all zeros. But if the NAND device internally has multiple dies stacked, the die information (MSB of final row address) has to be sent. The value programmed in this register will be used to mask the address while sending out the last row address."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - The die_mask register information will be used for devices having address restrictions. For example, in certain Samsung devices, when the first address in a two-plane command is being sent, it is expected that the address is all zeros. But if the NAND device internally has multiple dies stacked, the die information (MSB of final row address) has to be sent. The value programmed in this register will be used to mask the address while sending out the last row address."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - The die_mask register information will be used for devices having address restrictions. For example, in certain Samsung devices, when the first address in a two-plane command is being sent, it is expected that the address is all zeros. But if the NAND device internally has multiple dies stacked, the die information (MSB of final row address) has to be sent. The value programmed in this register will be used to mask the address while sending out the last row address."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigDieMaskSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Indicates the die differentiator in case of NAND devices with stacked dies.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_die_mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_die_mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigDieMaskSpec;
impl crate::RegisterSpec for ConfigDieMaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 608u64;
}
#[doc = "`read()` method returns [`config_die_mask::R`](R) reader structure"]
impl crate::Readable for ConfigDieMaskSpec {}
#[doc = "`write(|w| ..)` method takes [`config_die_mask::W`](W) writer structure"]
impl crate::Writable for ConfigDieMaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_die_mask to value 0"]
impl crate::Resettable for ConfigDieMaskSpec {
    const RESET_VALUE: u32 = 0;
}
