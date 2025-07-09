// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_number_of_planes` reader"]
pub type R = crate::R<ConfigNumberOfPlanesSpec>;
#[doc = "Register `config_number_of_planes` writer"]
pub type W = crate::W<ConfigNumberOfPlanesSpec>;
#[doc = "Field `value` reader - Controller will read Electronic Signature of devices and populate this field as the number of planes information is present in the signature. For 512B device, this information needs to be programmed by software. Software could also choose to override the populated value. The values in the fields should be as follows\\[list\\]
\\[*\\]3'h0 - Monoplane device \\[*\\]3'h1 - Two plane device \\[*\\]3'h3 - 4 plane device \\[*\\]3'h7 - 8 plane device \\[*\\]All other values - Reserved\\[/list\\]"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Controller will read Electronic Signature of devices and populate this field as the number of planes information is present in the signature. For 512B device, this information needs to be programmed by software. Software could also choose to override the populated value. The values in the fields should be as follows\\[list\\]
\\[*\\]3'h0 - Monoplane device \\[*\\]3'h1 - Two plane device \\[*\\]3'h3 - 4 plane device \\[*\\]3'h7 - 8 plane device \\[*\\]All other values - Reserved\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:2 - Controller will read Electronic Signature of devices and populate this field as the number of planes information is present in the signature. For 512B device, this information needs to be programmed by software. Software could also choose to override the populated value. The values in the fields should be as follows\\[list\\]
\\[*\\]3'h0 - Monoplane device \\[*\\]3'h1 - Two plane device \\[*\\]3'h3 - 4 plane device \\[*\\]3'h7 - 8 plane device \\[*\\]All other values - Reserved\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - Controller will read Electronic Signature of devices and populate this field as the number of planes information is present in the signature. For 512B device, this information needs to be programmed by software. Software could also choose to override the populated value. The values in the fields should be as follows\\[list\\]
\\[*\\]3'h0 - Monoplane device \\[*\\]3'h1 - Two plane device \\[*\\]3'h3 - 4 plane device \\[*\\]3'h7 - 8 plane device \\[*\\]All other values - Reserved\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigNumberOfPlanesSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Number of planes in the device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_number_of_planes::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_number_of_planes::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigNumberOfPlanesSpec;
impl crate::RegisterSpec for ConfigNumberOfPlanesSpec {
    type Ux = u32;
    const OFFSET: u64 = 320u64;
}
#[doc = "`read()` method returns [`config_number_of_planes::R`](R) reader structure"]
impl crate::Readable for ConfigNumberOfPlanesSpec {}
#[doc = "`write(|w| ..)` method takes [`config_number_of_planes::W`](W) writer structure"]
impl crate::Writable for ConfigNumberOfPlanesSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_number_of_planes to value 0"]
impl crate::Resettable for ConfigNumberOfPlanesSpec {
    const RESET_VALUE: u32 = 0;
}
