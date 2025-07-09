// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `frzctrl_hwctrl` reader"]
pub type R = crate::R<FrzctrlHwctrlSpec>;
#[doc = "Register `frzctrl_hwctrl` writer"]
pub type W = crate::W<FrzctrlHwctrlSpec>;
#[doc = "Requests hardware state machine to generate freeze signal sequence to transition between frozen and thawed states. If this field is read by software, it contains the value previously written by software (i.e. this field is not written by hardware).\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vio1req {
    #[doc = "0: `0`"]
    ReqThaw = 0,
    #[doc = "1: `1`"]
    ReqFrz = 1,
}
impl From<Vio1req> for bool {
    #[inline(always)]
    fn from(variant: Vio1req) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vio1req` reader - Requests hardware state machine to generate freeze signal sequence to transition between frozen and thawed states. If this field is read by software, it contains the value previously written by software (i.e. this field is not written by hardware)."]
pub type Vio1reqR = crate::BitReader<Vio1req>;
impl Vio1reqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vio1req {
        match self.bits {
            false => Vio1req::ReqThaw,
            true => Vio1req::ReqFrz,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_req_thaw(&self) -> bool {
        *self == Vio1req::ReqThaw
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_req_frz(&self) -> bool {
        *self == Vio1req::ReqFrz
    }
}
#[doc = "Field `vio1req` writer - Requests hardware state machine to generate freeze signal sequence to transition between frozen and thawed states. If this field is read by software, it contains the value previously written by software (i.e. this field is not written by hardware)."]
pub type Vio1reqW<'a, REG> = crate::BitWriter<'a, REG, Vio1req>;
impl<'a, REG> Vio1reqW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn req_thaw(self) -> &'a mut crate::W<REG> {
        self.variant(Vio1req::ReqThaw)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn req_frz(self) -> &'a mut crate::W<REG> {
        self.variant(Vio1req::ReqFrz)
    }
}
#[doc = "Software reads this field to determine the current frozen/thawed state of the VIO channel 1 or to determine when a freeze/thaw request is made by writing the corresponding *REQ field in this register has completed. Reset by a cold reset (ignores warm reset).\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Vio1state {
    #[doc = "0: `0`"]
    Thawed2frozen = 0,
    #[doc = "1: `1`"]
    Thawed = 1,
    #[doc = "2: `10`"]
    Frozen = 2,
    #[doc = "3: `11`"]
    Frozen2thawed = 3,
}
impl From<Vio1state> for u8 {
    #[inline(always)]
    fn from(variant: Vio1state) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Vio1state {
    type Ux = u8;
}
#[doc = "Field `vio1state` reader - Software reads this field to determine the current frozen/thawed state of the VIO channel 1 or to determine when a freeze/thaw request is made by writing the corresponding *REQ field in this register has completed. Reset by a cold reset (ignores warm reset)."]
pub type Vio1stateR = crate::FieldReader<Vio1state>;
impl Vio1stateR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vio1state {
        match self.bits {
            0 => Vio1state::Thawed2frozen,
            1 => Vio1state::Thawed,
            2 => Vio1state::Frozen,
            3 => Vio1state::Frozen2thawed,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_thawed2frozen(&self) -> bool {
        *self == Vio1state::Thawed2frozen
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_thawed(&self) -> bool {
        *self == Vio1state::Thawed
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_frozen(&self) -> bool {
        *self == Vio1state::Frozen
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_frozen2thawed(&self) -> bool {
        *self == Vio1state::Frozen2thawed
    }
}
#[doc = "Field `vio1state` writer - Software reads this field to determine the current frozen/thawed state of the VIO channel 1 or to determine when a freeze/thaw request is made by writing the corresponding *REQ field in this register has completed. Reset by a cold reset (ignores warm reset)."]
pub type Vio1stateW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Requests hardware state machine to generate freeze signal sequence to transition between frozen and thawed states. If this field is read by software, it contains the value previously written by software (i.e. this field is not written by hardware)."]
    #[inline(always)]
    pub fn vio1req(&self) -> Vio1reqR {
        Vio1reqR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Software reads this field to determine the current frozen/thawed state of the VIO channel 1 or to determine when a freeze/thaw request is made by writing the corresponding *REQ field in this register has completed. Reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    pub fn vio1state(&self) -> Vio1stateR {
        Vio1stateR::new(((self.bits >> 1) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Requests hardware state machine to generate freeze signal sequence to transition between frozen and thawed states. If this field is read by software, it contains the value previously written by software (i.e. this field is not written by hardware)."]
    #[inline(always)]
    #[must_use]
    pub fn vio1req(&mut self) -> Vio1reqW<FrzctrlHwctrlSpec> {
        Vio1reqW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Software reads this field to determine the current frozen/thawed state of the VIO channel 1 or to determine when a freeze/thaw request is made by writing the corresponding *REQ field in this register has completed. Reset by a cold reset (ignores warm reset)."]
    #[inline(always)]
    #[must_use]
    pub fn vio1state(&mut self) -> Vio1stateW<FrzctrlHwctrlSpec> {
        Vio1stateW::new(self, 1)
    }
}
#[doc = "Activate freeze or thaw operations on VIO channel 1 (HPS IO bank 2 and bank 3) and monitor for completeness and the current state. These fields interact with the hardware state machine in the Freeze Controller. These fields can be accessed independent of the value of SRC1.VIO1 although they only have an effect on the VIO channel 1 freeze signals when SRC1.VIO1 is setup to have the hardware state machine be the freeze signal source. All fields are only reset by a cold reset (ignore warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_hwctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_hwctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FrzctrlHwctrlSpec;
impl crate::RegisterSpec for FrzctrlHwctrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`frzctrl_hwctrl::R`](R) reader structure"]
impl crate::Readable for FrzctrlHwctrlSpec {}
#[doc = "`write(|w| ..)` method takes [`frzctrl_hwctrl::W`](W) writer structure"]
impl crate::Writable for FrzctrlHwctrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets frzctrl_hwctrl to value 0x05"]
impl crate::Resettable for FrzctrlHwctrlSpec {
    const RESET_VALUE: u32 = 0x05;
}
