// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `protogrp_CFR` reader"]
pub type R = crate::R<ProtogrpCfrSpec>;
#[doc = "Register `protogrp_CFR` writer"]
pub type W = crate::W<ProtogrpCfrSpec>;
#[doc = "Field `ClkStAck` reader - Clock Stop Acknowledgement"]
pub type ClkStAckR = crate::BitReader;
#[doc = "Field `ClkStAck` writer - Clock Stop Acknowledgement"]
pub type ClkStAckW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ClkStReq` reader - Clock Stop Request"]
pub type ClkStReqR = crate::BitReader;
#[doc = "Field `ClkStReq` writer - Clock Stop Request"]
pub type ClkStReqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Request for automatic RAM Initialization\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Raminit {
    #[doc = "0: `0`"]
    NoAuto = 0,
    #[doc = "1: `1`"]
    StartAuto = 1,
}
impl From<Raminit> for bool {
    #[inline(always)]
    fn from(variant: Raminit) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `RAMinit` reader - Request for automatic RAM Initialization"]
pub type RaminitR = crate::BitReader<Raminit>;
impl RaminitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Raminit {
        match self.bits {
            false => Raminit::NoAuto,
            true => Raminit::StartAuto,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_auto(&self) -> bool {
        *self == Raminit::NoAuto
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_start_auto(&self) -> bool {
        *self == Raminit::StartAuto
    }
}
#[doc = "Field `RAMinit` writer - Request for automatic RAM Initialization"]
pub type RaminitW<'a, REG> = crate::BitWriter<'a, REG, Raminit>;
impl<'a, REG> RaminitW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_auto(self) -> &'a mut crate::W<REG> {
        self.variant(Raminit::NoAuto)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn start_auto(self) -> &'a mut crate::W<REG> {
        self.variant(Raminit::StartAuto)
    }
}
impl R {
    #[doc = "Bit 0 - Clock Stop Acknowledgement"]
    #[inline(always)]
    pub fn clk_st_ack(&self) -> ClkStAckR {
        ClkStAckR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Clock Stop Request"]
    #[inline(always)]
    pub fn clk_st_req(&self) -> ClkStReqR {
        ClkStReqR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Request for automatic RAM Initialization"]
    #[inline(always)]
    pub fn raminit(&self) -> RaminitR {
        RaminitR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clock Stop Acknowledgement"]
    #[inline(always)]
    #[must_use]
    pub fn clk_st_ack(&mut self) -> ClkStAckW<ProtogrpCfrSpec> {
        ClkStAckW::new(self, 0)
    }
    #[doc = "Bit 1 - Clock Stop Request"]
    #[inline(always)]
    #[must_use]
    pub fn clk_st_req(&mut self) -> ClkStReqW<ProtogrpCfrSpec> {
        ClkStReqW::new(self, 1)
    }
    #[doc = "Bit 3 - Request for automatic RAM Initialization"]
    #[inline(always)]
    #[must_use]
    pub fn raminit(&mut self) -> RaminitW<ProtogrpCfrSpec> {
        RaminitW::new(self, 3)
    }
}
#[doc = "The Function Register controls the features RAM_Initialisation and Power_Down also by application register. The CAN module can be prepared for Power_Down by setting the port CAN_CLKSTOP_REQ to one or writing to CFR.ClkStReq a one. The power down state is left by setting port CAN_CLKSTOP_REQ to zero or writing to CFR.ClkStReq a zero, acknowledged by CAN_CLKSTOP_ACK is going to zero as well as CFR.ClkStAck. The CCTRL.Init bit is left one and has to be written by the application to re-enable CAN transfers. Note: It's recommended to use either the ports CAN_CLKSTOP_REQ and CAN_CLKSTOP_ACK or the CCTRL.ClkStReq and CFR.ClkStAck. The application CFR.ClkStReq showsalso the actual status of the portCAN_CLKSTOP_REQ.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cfr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_cfr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCfrSpec;
impl crate::RegisterSpec for ProtogrpCfrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`protogrp_cfr::R`](R) reader structure"]
impl crate::Readable for ProtogrpCfrSpec {}
#[doc = "`write(|w| ..)` method takes [`protogrp_cfr::W`](W) writer structure"]
impl crate::Writable for ProtogrpCfrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets protogrp_CFR to value 0"]
impl crate::Resettable for ProtogrpCfrSpec {
    const RESET_VALUE: u32 = 0;
}
