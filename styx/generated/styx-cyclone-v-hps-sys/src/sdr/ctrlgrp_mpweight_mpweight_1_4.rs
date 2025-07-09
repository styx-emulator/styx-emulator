// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_mpweight_mpweight_1_4` reader"]
pub type R = crate::R<CtrlgrpMpweightMpweight1_4Spec>;
#[doc = "Register `ctrlgrp_mpweight_mpweight_1_4` writer"]
pub type W = crate::W<CtrlgrpMpweightMpweight1_4Spec>;
#[doc = "Field `staticweight_49_32` reader - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
pub type Staticweight49_32R = crate::FieldReader<u32>;
#[doc = "Field `staticweight_49_32` writer - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
pub type Staticweight49_32W<'a, REG> = crate::FieldWriter<'a, REG, 18, u32>;
#[doc = "Field `sumofweights_13_0` reader - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
pub type Sumofweights13_0R = crate::FieldReader<u16>;
#[doc = "Field `sumofweights_13_0` writer - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
pub type Sumofweights13_0W<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:17 - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
    #[inline(always)]
    pub fn staticweight_49_32(&self) -> Staticweight49_32R {
        Staticweight49_32R::new(self.bits & 0x0003_ffff)
    }
    #[doc = "Bits 18:31 - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
    #[inline(always)]
    pub fn sumofweights_13_0(&self) -> Sumofweights13_0R {
        Sumofweights13_0R::new(((self.bits >> 18) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:17 - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
    #[inline(always)]
    #[must_use]
    pub fn staticweight_49_32(&mut self) -> Staticweight49_32W<CtrlgrpMpweightMpweight1_4Spec> {
        Staticweight49_32W::new(self, 0)
    }
    #[doc = "Bits 18:31 - Set the sum of static weights for particular user priority. This register is used as part of the deficit round robin implementation. It should be set to the sum of the weights for the ports"]
    #[inline(always)]
    #[must_use]
    pub fn sumofweights_13_0(&mut self) -> Sumofweights13_0W<CtrlgrpMpweightMpweight1_4Spec> {
        Sumofweights13_0W::new(self, 18)
    }
}
#[doc = "This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_1_4::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_1_4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpMpweightMpweight1_4Spec;
impl crate::RegisterSpec for CtrlgrpMpweightMpweight1_4Spec {
    type Ux = u32;
    const OFFSET: u64 = 20660u64;
}
#[doc = "`read()` method returns [`ctrlgrp_mpweight_mpweight_1_4::R`](R) reader structure"]
impl crate::Readable for CtrlgrpMpweightMpweight1_4Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_mpweight_mpweight_1_4::W`](W) writer structure"]
impl crate::Writable for CtrlgrpMpweightMpweight1_4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
