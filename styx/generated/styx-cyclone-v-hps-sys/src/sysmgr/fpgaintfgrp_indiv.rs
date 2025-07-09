// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fpgaintfgrp_indiv` reader"]
pub type R = crate::R<FpgaintfgrpIndivSpec>;
#[doc = "Register `fpgaintfgrp_indiv` writer"]
pub type W = crate::W<FpgaintfgrpIndivSpec>;
#[doc = "Used to disable the reset request interface. This interface allows logic in the FPGA fabric to request HPS resets. This field disables the following reset request signals from the FPGA fabric to HPS:\\[list\\]\\[*\\]f2h_cold_rst_req_n - Triggers a cold reset of the HPS\\[*\\]f2h_warm_rst_req_n - Triggers a warm reset of the HPS\\[*\\]f2h_dbg_rst_req_n - Triggers a debug reset of the HPS\\[/list\\]\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rstreqintf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Rstreqintf> for bool {
    #[inline(always)]
    fn from(variant: Rstreqintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rstreqintf` reader - Used to disable the reset request interface. This interface allows logic in the FPGA fabric to request HPS resets. This field disables the following reset request signals from the FPGA fabric to HPS:\\[list\\]\\[*\\]f2h_cold_rst_req_n - Triggers a cold reset of the HPS\\[*\\]f2h_warm_rst_req_n - Triggers a warm reset of the HPS\\[*\\]f2h_dbg_rst_req_n - Triggers a debug reset of the HPS\\[/list\\]"]
pub type RstreqintfR = crate::BitReader<Rstreqintf>;
impl RstreqintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rstreqintf {
        match self.bits {
            false => Rstreqintf::Disable,
            true => Rstreqintf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Rstreqintf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Rstreqintf::Enable
    }
}
#[doc = "Field `rstreqintf` writer - Used to disable the reset request interface. This interface allows logic in the FPGA fabric to request HPS resets. This field disables the following reset request signals from the FPGA fabric to HPS:\\[list\\]\\[*\\]f2h_cold_rst_req_n - Triggers a cold reset of the HPS\\[*\\]f2h_warm_rst_req_n - Triggers a warm reset of the HPS\\[*\\]f2h_dbg_rst_req_n - Triggers a debug reset of the HPS\\[/list\\]"]
pub type RstreqintfW<'a, REG> = crate::BitWriter<'a, REG, Rstreqintf>;
impl<'a, REG> RstreqintfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Rstreqintf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Rstreqintf::Enable)
    }
}
#[doc = "Used to disable the JTAG enable interface. This interface allows logic in the FPGA fabric to disable the HPS JTAG operation.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Jtagenintf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Jtagenintf> for bool {
    #[inline(always)]
    fn from(variant: Jtagenintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `jtagenintf` reader - Used to disable the JTAG enable interface. This interface allows logic in the FPGA fabric to disable the HPS JTAG operation."]
pub type JtagenintfR = crate::BitReader<Jtagenintf>;
impl JtagenintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Jtagenintf {
        match self.bits {
            false => Jtagenintf::Disable,
            true => Jtagenintf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Jtagenintf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Jtagenintf::Enable
    }
}
#[doc = "Field `jtagenintf` writer - Used to disable the JTAG enable interface. This interface allows logic in the FPGA fabric to disable the HPS JTAG operation."]
pub type JtagenintfW<'a, REG> = crate::BitWriter<'a, REG, Jtagenintf>;
impl<'a, REG> JtagenintfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Jtagenintf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Jtagenintf::Enable)
    }
}
#[doc = "Used to disable the CONFIG_IO interface. This interface allows the FPGA JTAG TAP controller to execute the CONFIG_IO instruction and configure all device I/Os (FPGA and HPS). This is typically done before executing boundary-scan instructions. The CONFIG_IO interface must be enabled before attempting to send the CONFIG_IO instruction to the FPGA JTAG TAP controller.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Configiointf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Configiointf> for bool {
    #[inline(always)]
    fn from(variant: Configiointf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `configiointf` reader - Used to disable the CONFIG_IO interface. This interface allows the FPGA JTAG TAP controller to execute the CONFIG_IO instruction and configure all device I/Os (FPGA and HPS). This is typically done before executing boundary-scan instructions. The CONFIG_IO interface must be enabled before attempting to send the CONFIG_IO instruction to the FPGA JTAG TAP controller."]
pub type ConfigiointfR = crate::BitReader<Configiointf>;
impl ConfigiointfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Configiointf {
        match self.bits {
            false => Configiointf::Disable,
            true => Configiointf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Configiointf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Configiointf::Enable
    }
}
#[doc = "Field `configiointf` writer - Used to disable the CONFIG_IO interface. This interface allows the FPGA JTAG TAP controller to execute the CONFIG_IO instruction and configure all device I/Os (FPGA and HPS). This is typically done before executing boundary-scan instructions. The CONFIG_IO interface must be enabled before attempting to send the CONFIG_IO instruction to the FPGA JTAG TAP controller."]
pub type ConfigiointfW<'a, REG> = crate::BitWriter<'a, REG, Configiointf>;
impl<'a, REG> ConfigiointfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Configiointf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Configiointf::Enable)
    }
}
#[doc = "Used to disable the boundary-scan interface. This interface allows the FPGA JTAG TAP controller to execute boundary-scan instructions such as SAMPLE/PRELOAD, EXTEST, and HIGHZ. The boundary-scan interface must be enabled before attempting to send the boundary-scan instructions to the FPGA JTAG TAP controller.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bscanintf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Bscanintf> for bool {
    #[inline(always)]
    fn from(variant: Bscanintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bscanintf` reader - Used to disable the boundary-scan interface. This interface allows the FPGA JTAG TAP controller to execute boundary-scan instructions such as SAMPLE/PRELOAD, EXTEST, and HIGHZ. The boundary-scan interface must be enabled before attempting to send the boundary-scan instructions to the FPGA JTAG TAP controller."]
pub type BscanintfR = crate::BitReader<Bscanintf>;
impl BscanintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bscanintf {
        match self.bits {
            false => Bscanintf::Disable,
            true => Bscanintf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Bscanintf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Bscanintf::Enable
    }
}
#[doc = "Field `bscanintf` writer - Used to disable the boundary-scan interface. This interface allows the FPGA JTAG TAP controller to execute boundary-scan instructions such as SAMPLE/PRELOAD, EXTEST, and HIGHZ. The boundary-scan interface must be enabled before attempting to send the boundary-scan instructions to the FPGA JTAG TAP controller."]
pub type BscanintfW<'a, REG> = crate::BitWriter<'a, REG, Bscanintf>;
impl<'a, REG> BscanintfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Bscanintf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Bscanintf::Enable)
    }
}
#[doc = "Used to disable the trace interface. This interface allows the HPS debug logic to send trace data to logic in the FPGA fabric.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Traceintf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Traceintf> for bool {
    #[inline(always)]
    fn from(variant: Traceintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `traceintf` reader - Used to disable the trace interface. This interface allows the HPS debug logic to send trace data to logic in the FPGA fabric."]
pub type TraceintfR = crate::BitReader<Traceintf>;
impl TraceintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Traceintf {
        match self.bits {
            false => Traceintf::Disable,
            true => Traceintf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Traceintf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Traceintf::Enable
    }
}
#[doc = "Field `traceintf` writer - Used to disable the trace interface. This interface allows the HPS debug logic to send trace data to logic in the FPGA fabric."]
pub type TraceintfW<'a, REG> = crate::BitWriter<'a, REG, Traceintf>;
impl<'a, REG> TraceintfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Traceintf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Traceintf::Enable)
    }
}
#[doc = "Used to disable the STM event interface. This interface allows logic in the FPGA fabric to trigger events to the STM debug module in the HPS.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stmeventintf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Stmeventintf> for bool {
    #[inline(always)]
    fn from(variant: Stmeventintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stmeventintf` reader - Used to disable the STM event interface. This interface allows logic in the FPGA fabric to trigger events to the STM debug module in the HPS."]
pub type StmeventintfR = crate::BitReader<Stmeventintf>;
impl StmeventintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stmeventintf {
        match self.bits {
            false => Stmeventintf::Disable,
            true => Stmeventintf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Stmeventintf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Stmeventintf::Enable
    }
}
#[doc = "Field `stmeventintf` writer - Used to disable the STM event interface. This interface allows logic in the FPGA fabric to trigger events to the STM debug module in the HPS."]
pub type StmeventintfW<'a, REG> = crate::BitWriter<'a, REG, Stmeventintf>;
impl<'a, REG> StmeventintfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Stmeventintf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Stmeventintf::Enable)
    }
}
#[doc = "Used to disable the FPGA Fabric from sending triggers to HPS debug logic. Note that this doesn't prevent the HPS debug logic from sending triggers to the FPGA Fabric.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crosstrigintf {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Crosstrigintf> for bool {
    #[inline(always)]
    fn from(variant: Crosstrigintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `crosstrigintf` reader - Used to disable the FPGA Fabric from sending triggers to HPS debug logic. Note that this doesn't prevent the HPS debug logic from sending triggers to the FPGA Fabric."]
pub type CrosstrigintfR = crate::BitReader<Crosstrigintf>;
impl CrosstrigintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Crosstrigintf {
        match self.bits {
            false => Crosstrigintf::Disable,
            true => Crosstrigintf::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Crosstrigintf::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Crosstrigintf::Enable
    }
}
#[doc = "Field `crosstrigintf` writer - Used to disable the FPGA Fabric from sending triggers to HPS debug logic. Note that this doesn't prevent the HPS debug logic from sending triggers to the FPGA Fabric."]
pub type CrosstrigintfW<'a, REG> = crate::BitWriter<'a, REG, Crosstrigintf>;
impl<'a, REG> CrosstrigintfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Crosstrigintf::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Crosstrigintf::Enable)
    }
}
impl R {
    #[doc = "Bit 0 - Used to disable the reset request interface. This interface allows logic in the FPGA fabric to request HPS resets. This field disables the following reset request signals from the FPGA fabric to HPS:\\[list\\]\\[*\\]f2h_cold_rst_req_n - Triggers a cold reset of the HPS\\[*\\]f2h_warm_rst_req_n - Triggers a warm reset of the HPS\\[*\\]f2h_dbg_rst_req_n - Triggers a debug reset of the HPS\\[/list\\]"]
    #[inline(always)]
    pub fn rstreqintf(&self) -> RstreqintfR {
        RstreqintfR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Used to disable the JTAG enable interface. This interface allows logic in the FPGA fabric to disable the HPS JTAG operation."]
    #[inline(always)]
    pub fn jtagenintf(&self) -> JtagenintfR {
        JtagenintfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Used to disable the CONFIG_IO interface. This interface allows the FPGA JTAG TAP controller to execute the CONFIG_IO instruction and configure all device I/Os (FPGA and HPS). This is typically done before executing boundary-scan instructions. The CONFIG_IO interface must be enabled before attempting to send the CONFIG_IO instruction to the FPGA JTAG TAP controller."]
    #[inline(always)]
    pub fn configiointf(&self) -> ConfigiointfR {
        ConfigiointfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Used to disable the boundary-scan interface. This interface allows the FPGA JTAG TAP controller to execute boundary-scan instructions such as SAMPLE/PRELOAD, EXTEST, and HIGHZ. The boundary-scan interface must be enabled before attempting to send the boundary-scan instructions to the FPGA JTAG TAP controller."]
    #[inline(always)]
    pub fn bscanintf(&self) -> BscanintfR {
        BscanintfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Used to disable the trace interface. This interface allows the HPS debug logic to send trace data to logic in the FPGA fabric."]
    #[inline(always)]
    pub fn traceintf(&self) -> TraceintfR {
        TraceintfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Used to disable the STM event interface. This interface allows logic in the FPGA fabric to trigger events to the STM debug module in the HPS."]
    #[inline(always)]
    pub fn stmeventintf(&self) -> StmeventintfR {
        StmeventintfR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Used to disable the FPGA Fabric from sending triggers to HPS debug logic. Note that this doesn't prevent the HPS debug logic from sending triggers to the FPGA Fabric."]
    #[inline(always)]
    pub fn crosstrigintf(&self) -> CrosstrigintfR {
        CrosstrigintfR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Used to disable the reset request interface. This interface allows logic in the FPGA fabric to request HPS resets. This field disables the following reset request signals from the FPGA fabric to HPS:\\[list\\]\\[*\\]f2h_cold_rst_req_n - Triggers a cold reset of the HPS\\[*\\]f2h_warm_rst_req_n - Triggers a warm reset of the HPS\\[*\\]f2h_dbg_rst_req_n - Triggers a debug reset of the HPS\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn rstreqintf(&mut self) -> RstreqintfW<FpgaintfgrpIndivSpec> {
        RstreqintfW::new(self, 0)
    }
    #[doc = "Bit 1 - Used to disable the JTAG enable interface. This interface allows logic in the FPGA fabric to disable the HPS JTAG operation."]
    #[inline(always)]
    #[must_use]
    pub fn jtagenintf(&mut self) -> JtagenintfW<FpgaintfgrpIndivSpec> {
        JtagenintfW::new(self, 1)
    }
    #[doc = "Bit 2 - Used to disable the CONFIG_IO interface. This interface allows the FPGA JTAG TAP controller to execute the CONFIG_IO instruction and configure all device I/Os (FPGA and HPS). This is typically done before executing boundary-scan instructions. The CONFIG_IO interface must be enabled before attempting to send the CONFIG_IO instruction to the FPGA JTAG TAP controller."]
    #[inline(always)]
    #[must_use]
    pub fn configiointf(&mut self) -> ConfigiointfW<FpgaintfgrpIndivSpec> {
        ConfigiointfW::new(self, 2)
    }
    #[doc = "Bit 3 - Used to disable the boundary-scan interface. This interface allows the FPGA JTAG TAP controller to execute boundary-scan instructions such as SAMPLE/PRELOAD, EXTEST, and HIGHZ. The boundary-scan interface must be enabled before attempting to send the boundary-scan instructions to the FPGA JTAG TAP controller."]
    #[inline(always)]
    #[must_use]
    pub fn bscanintf(&mut self) -> BscanintfW<FpgaintfgrpIndivSpec> {
        BscanintfW::new(self, 3)
    }
    #[doc = "Bit 4 - Used to disable the trace interface. This interface allows the HPS debug logic to send trace data to logic in the FPGA fabric."]
    #[inline(always)]
    #[must_use]
    pub fn traceintf(&mut self) -> TraceintfW<FpgaintfgrpIndivSpec> {
        TraceintfW::new(self, 4)
    }
    #[doc = "Bit 6 - Used to disable the STM event interface. This interface allows logic in the FPGA fabric to trigger events to the STM debug module in the HPS."]
    #[inline(always)]
    #[must_use]
    pub fn stmeventintf(&mut self) -> StmeventintfW<FpgaintfgrpIndivSpec> {
        StmeventintfW::new(self, 6)
    }
    #[doc = "Bit 7 - Used to disable the FPGA Fabric from sending triggers to HPS debug logic. Note that this doesn't prevent the HPS debug logic from sending triggers to the FPGA Fabric."]
    #[inline(always)]
    #[must_use]
    pub fn crosstrigintf(&mut self) -> CrosstrigintfW<FpgaintfgrpIndivSpec> {
        CrosstrigintfW::new(self, 7)
    }
}
#[doc = "Used to disable individual interfaces between the FPGA and HPS.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpgaintfgrp_indiv::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpgaintfgrp_indiv::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FpgaintfgrpIndivSpec;
impl crate::RegisterSpec for FpgaintfgrpIndivSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`fpgaintfgrp_indiv::R`](R) reader structure"]
impl crate::Readable for FpgaintfgrpIndivSpec {}
#[doc = "`write(|w| ..)` method takes [`fpgaintfgrp_indiv::W`](W) writer structure"]
impl crate::Writable for FpgaintfgrpIndivSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fpgaintfgrp_indiv to value 0xff"]
impl crate::Resettable for FpgaintfgrpIndivSpec {
    const RESET_VALUE: u32 = 0xff;
}
