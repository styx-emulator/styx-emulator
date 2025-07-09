// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_mpweight_mpweight_3_4` reader"]
pub type R = crate::R<CtrlgrpMpweightMpweight3_4Spec>;
#[doc = "Register `ctrlgrp_mpweight_mpweight_3_4` writer"]
pub type W = crate::W<CtrlgrpMpweightMpweight3_4Spec>;
#[doc = "Field `sumofweights_63_46` reader - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
pub type Sumofweights63_46R = crate::FieldReader<u32>;
#[doc = "Field `sumofweights_63_46` writer - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
pub type Sumofweights63_46W<'a, REG> = crate::FieldWriter<'a, REG, 18, u32>;
impl R {
    #[doc = "Bits 0:17 - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
    #[inline(always)]
    pub fn sumofweights_63_46(&self) -> Sumofweights63_46R {
        Sumofweights63_46R::new(self.bits & 0x0003_ffff)
    }
}
impl W {
    #[doc = "Bits 0:17 - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
    #[inline(always)]
    #[must_use]
    pub fn sumofweights_63_46(&mut self) -> Sumofweights63_46W<CtrlgrpMpweightMpweight3_4Spec> {
        Sumofweights63_46W::new(self, 0)
    }
}
#[doc = "This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_3_4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_3_4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpMpweightMpweight3_4Spec;
impl crate::RegisterSpec for CtrlgrpMpweightMpweight3_4Spec {
    type Ux = u32;
    const OFFSET: u64 = 20668u64;
}
#[doc = "`read()` method returns [`ctrlgrp_mpweight_mpweight_3_4::R`](R) reader structure"]
impl crate::Readable for CtrlgrpMpweightMpweight3_4Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_mpweight_mpweight_3_4::W`](W) writer structure"]
impl crate::Writable for CtrlgrpMpweightMpweight3_4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_mpweight_mpweight_3_4 to value 0"]
impl crate::Resettable for CtrlgrpMpweightMpweight3_4Spec {
    const RESET_VALUE: u32 = 0;
}
