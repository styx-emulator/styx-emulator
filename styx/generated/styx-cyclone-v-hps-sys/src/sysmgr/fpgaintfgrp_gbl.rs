// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fpgaintfgrp_gbl` reader"]
pub type R = crate::R<FpgaintfgrpGblSpec>;
#[doc = "Register `fpgaintfgrp_gbl` writer"]
pub type W = crate::W<FpgaintfgrpGblSpec>;
#[doc = "Used to disable all interfaces between the FPGA and HPS. Software must ensure that all interfaces between the FPGA and HPS are inactive before disabling them.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Intf> for bool {
    #[inline(always)]
    fn from(variant: Intf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `intf` reader - Used to disable all interfaces between the FPGA and HPS. Software must ensure that all interfaces between the FPGA and HPS are inactive before disabling them."]
pub type IntfR = crate::BitReader<Intf>;
impl IntfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Intf {
        match self.bits {
            false => Intf::Disable,
            true => Intf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Intf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Intf::Enable
    }
}
#[doc = "Field `intf` writer - Used to disable all interfaces between the FPGA and HPS. Software must ensure that all interfaces between the FPGA and HPS are inactive before disabling them."]
pub type IntfW<'a, REG> = crate::BitWriter<'a, REG, Intf>;
impl<'a, REG> IntfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Intf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Intf::Enable)
    }
}
impl R {
    #[doc = "Bit 0 - Used to disable all interfaces between the FPGA and HPS. Software must ensure that all interfaces between the FPGA and HPS are inactive before disabling them."]
    #[inline(always)]
    pub fn intf(&self) -> IntfR {
        IntfR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Used to disable all interfaces between the FPGA and HPS. Software must ensure that all interfaces between the FPGA and HPS are inactive before disabling them."]
    #[inline(always)]
    #[must_use]
    pub fn intf(&mut self) -> IntfW<FpgaintfgrpGblSpec> {
        IntfW::new(self, 0)
    }
}
#[doc = "Used to disable all interfaces between the FPGA and HPS.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpgaintfgrp_gbl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpgaintfgrp_gbl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FpgaintfgrpGblSpec;
impl crate::RegisterSpec for FpgaintfgrpGblSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`fpgaintfgrp_gbl::R`](R) reader structure"]
impl crate::Readable for FpgaintfgrpGblSpec {}
#[doc = "`write(|w| ..)` method takes [`fpgaintfgrp_gbl::W`](W) writer structure"]
impl crate::Writable for FpgaintfgrpGblSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fpgaintfgrp_gbl to value 0x01"]
impl crate::Resettable for FpgaintfgrpGblSpec {
    const RESET_VALUE: u32 = 0x01;
}
