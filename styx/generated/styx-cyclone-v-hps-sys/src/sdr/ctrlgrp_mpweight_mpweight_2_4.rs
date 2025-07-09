// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_mpweight_mpweight_2_4` reader"]
pub type R = crate::R<CtrlgrpMpweightMpweight2_4Spec>;
#[doc = "Register `ctrlgrp_mpweight_mpweight_2_4` writer"]
pub type W = crate::W<CtrlgrpMpweightMpweight2_4Spec>;
#[doc = "Field `sumofweights_45_14` reader - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
pub type Sumofweights45_14R = crate::FieldReader<u32>;
#[doc = "Field `sumofweights_45_14` writer - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
pub type Sumofweights45_14W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
    #[inline(always)]
    pub fn sumofweights_45_14(&self) -> Sumofweights45_14R {
        Sumofweights45_14R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
    #[inline(always)]
    #[must_use]
    pub fn sumofweights_45_14(&mut self) -> Sumofweights45_14W<CtrlgrpMpweightMpweight2_4Spec> {
        Sumofweights45_14W::new(self, 0)
    }
}
#[doc = "This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_2_4::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_2_4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpMpweightMpweight2_4Spec;
impl crate::RegisterSpec for CtrlgrpMpweightMpweight2_4Spec {
    type Ux = u32;
    const OFFSET: u64 = 20664u64;
}
#[doc = "`read()` method returns [`ctrlgrp_mpweight_mpweight_2_4::R`](R) reader structure"]
impl crate::Readable for CtrlgrpMpweightMpweight2_4Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_mpweight_mpweight_2_4::W`](W) writer structure"]
impl crate::Writable for CtrlgrpMpweightMpweight2_4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
