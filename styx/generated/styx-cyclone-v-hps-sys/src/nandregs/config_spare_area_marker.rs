// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_spare_area_marker` reader"]
pub type R = crate::R<ConfigSpareAreaMarkerSpec>;
#[doc = "Register `config_spare_area_marker` writer"]
pub type W = crate::W<ConfigSpareAreaMarkerSpec>;
#[doc = "Field `value` reader - The value that will be written in the spare area skip bytes. This value will be used by controller while in the MAIN mode of data transfer. Only the least-significant 8 bits of the field value are used."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - The value that will be written in the spare area skip bytes. This value will be used by controller while in the MAIN mode of data transfer. Only the least-significant 8 bits of the field value are used."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - The value that will be written in the spare area skip bytes. This value will be used by controller while in the MAIN mode of data transfer. Only the least-significant 8 bits of the field value are used."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - The value that will be written in the spare area skip bytes. This value will be used by controller while in the MAIN mode of data transfer. Only the least-significant 8 bits of the field value are used."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigSpareAreaMarkerSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Spare area marker value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_spare_area_marker::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_spare_area_marker::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigSpareAreaMarkerSpec;
impl crate::RegisterSpec for ConfigSpareAreaMarkerSpec {
    type Ux = u32;
    const OFFSET: u64 = 576u64;
}
#[doc = "`read()` method returns [`config_spare_area_marker::R`](R) reader structure"]
impl crate::Readable for ConfigSpareAreaMarkerSpec {}
#[doc = "`write(|w| ..)` method takes [`config_spare_area_marker::W`](W) writer structure"]
impl crate::Writable for ConfigSpareAreaMarkerSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_spare_area_marker to value 0xffff"]
impl crate::Resettable for ConfigSpareAreaMarkerSpec {
    const RESET_VALUE: u32 = 0xffff;
}
