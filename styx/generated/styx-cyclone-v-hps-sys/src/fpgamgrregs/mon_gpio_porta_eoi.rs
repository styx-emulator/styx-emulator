// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `mon_gpio_porta_eoi` reader"]
pub type R = crate::R<MonGpioPortaEoiSpec>;
#[doc = "Register `mon_gpio_porta_eoi` writer"]
pub type W = crate::W<MonGpioPortaEoiSpec>;
#[doc = "Field `ns` reader - Used by software to clear an nSTATUS edge interrupt."]
pub type NsR = crate::BitReader;
#[doc = "Used by software to clear an nSTATUS edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ns {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Ns> for bool {
    #[inline(always)]
    fn from(variant: Ns) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ns` writer - Used by software to clear an nSTATUS edge interrupt."]
pub type NsW<'a, REG> = crate::BitWriter<'a, REG, Ns>;
impl<'a, REG> NsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Clr)
    }
}
#[doc = "Field `cd` reader - Used by software to clear an CONF_DONE edge interrupt."]
pub type CdR = crate::BitReader;
#[doc = "Used by software to clear an CONF_DONE edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` writer - Used by software to clear an CONF_DONE edge interrupt."]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG, Cd>;
impl<'a, REG> CdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Clr)
    }
}
#[doc = "Field `id` reader - Used by software to clear an INIT_DONE edge interrupt."]
pub type IdR = crate::BitReader;
#[doc = "Used by software to clear an INIT_DONE edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Id> for bool {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `id` writer - Used by software to clear an INIT_DONE edge interrupt."]
pub type IdW<'a, REG> = crate::BitWriter<'a, REG, Id>;
impl<'a, REG> IdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Clr)
    }
}
#[doc = "Field `crc` reader - Used by software to clear an CRC_ERROR edge interrupt."]
pub type CrcR = crate::BitReader;
#[doc = "Used by software to clear an CRC_ERROR edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crc {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Crc> for bool {
    #[inline(always)]
    fn from(variant: Crc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `crc` writer - Used by software to clear an CRC_ERROR edge interrupt."]
pub type CrcW<'a, REG> = crate::BitWriter<'a, REG, Crc>;
impl<'a, REG> CrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Clr)
    }
}
#[doc = "Field `ccd` reader - Used by software to clear an CVP_CONF_DONE edge interrupt."]
pub type CcdR = crate::BitReader;
#[doc = "Used by software to clear an CVP_CONF_DONE edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ccd {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Ccd> for bool {
    #[inline(always)]
    fn from(variant: Ccd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ccd` writer - Used by software to clear an CVP_CONF_DONE edge interrupt."]
pub type CcdW<'a, REG> = crate::BitWriter<'a, REG, Ccd>;
impl<'a, REG> CcdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Clr)
    }
}
#[doc = "Field `prr` reader - Used by software to clear an PR_READY edge interrupt."]
pub type PrrR = crate::BitReader;
#[doc = "Used by software to clear an PR_READY edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prr {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Prr> for bool {
    #[inline(always)]
    fn from(variant: Prr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prr` writer - Used by software to clear an PR_READY edge interrupt."]
pub type PrrW<'a, REG> = crate::BitWriter<'a, REG, Prr>;
impl<'a, REG> PrrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Clr)
    }
}
#[doc = "Field `pre` reader - Used by software to clear an PR_ERROR edge interrupt."]
pub type PreR = crate::BitReader;
#[doc = "Used by software to clear an PR_ERROR edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pre {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Pre> for bool {
    #[inline(always)]
    fn from(variant: Pre) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pre` writer - Used by software to clear an PR_ERROR edge interrupt."]
pub type PreW<'a, REG> = crate::BitWriter<'a, REG, Pre>;
impl<'a, REG> PreW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Clr)
    }
}
#[doc = "Field `prd` reader - Used by software to clear an PR_DONE edge interrupt."]
pub type PrdR = crate::BitReader;
#[doc = "Used by software to clear an PR_DONE edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prd {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Prd> for bool {
    #[inline(always)]
    fn from(variant: Prd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prd` writer - Used by software to clear an PR_DONE edge interrupt."]
pub type PrdW<'a, REG> = crate::BitWriter<'a, REG, Prd>;
impl<'a, REG> PrdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Clr)
    }
}
#[doc = "Field `ncp` reader - Used by software to clear an nCONFIG Pin edge interrupt."]
pub type NcpR = crate::BitReader;
#[doc = "Used by software to clear an nCONFIG Pin edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ncp {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Ncp> for bool {
    #[inline(always)]
    fn from(variant: Ncp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ncp` writer - Used by software to clear an nCONFIG Pin edge interrupt."]
pub type NcpW<'a, REG> = crate::BitWriter<'a, REG, Ncp>;
impl<'a, REG> NcpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Clr)
    }
}
#[doc = "Field `nsp` reader - Used by software to clear an nSTATUS Pin edge interrupt."]
pub type NspR = crate::BitReader;
#[doc = "Used by software to clear an nSTATUS Pin edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nsp {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Nsp> for bool {
    #[inline(always)]
    fn from(variant: Nsp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nsp` writer - Used by software to clear an nSTATUS Pin edge interrupt."]
pub type NspW<'a, REG> = crate::BitWriter<'a, REG, Nsp>;
impl<'a, REG> NspW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Clr)
    }
}
#[doc = "Field `cdp` reader - Used by software to clear an CONF_DONE Pin edge interrupt."]
pub type CdpR = crate::BitReader;
#[doc = "Used by software to clear an CONF_DONE Pin edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cdp {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Cdp> for bool {
    #[inline(always)]
    fn from(variant: Cdp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cdp` writer - Used by software to clear an CONF_DONE Pin edge interrupt."]
pub type CdpW<'a, REG> = crate::BitWriter<'a, REG, Cdp>;
impl<'a, REG> CdpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Clr)
    }
}
#[doc = "Field `fpo` reader - Used by software to clear an FPGA_POWER_ON edge interrupt."]
pub type FpoR = crate::BitReader;
#[doc = "Used by software to clear an FPGA_POWER_ON edge interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpo {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<Fpo> for bool {
    #[inline(always)]
    fn from(variant: Fpo) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpo` writer - Used by software to clear an FPGA_POWER_ON edge interrupt."]
pub type FpoW<'a, REG> = crate::BitWriter<'a, REG, Fpo>;
impl<'a, REG> FpoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Clr)
    }
}
impl R {
    #[doc = "Bit 0 - Used by software to clear an nSTATUS edge interrupt."]
    #[inline(always)]
    pub fn ns(&self) -> NsR {
        NsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Used by software to clear an CONF_DONE edge interrupt."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Used by software to clear an INIT_DONE edge interrupt."]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Used by software to clear an CRC_ERROR edge interrupt."]
    #[inline(always)]
    pub fn crc(&self) -> CrcR {
        CrcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Used by software to clear an CVP_CONF_DONE edge interrupt."]
    #[inline(always)]
    pub fn ccd(&self) -> CcdR {
        CcdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Used by software to clear an PR_READY edge interrupt."]
    #[inline(always)]
    pub fn prr(&self) -> PrrR {
        PrrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Used by software to clear an PR_ERROR edge interrupt."]
    #[inline(always)]
    pub fn pre(&self) -> PreR {
        PreR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Used by software to clear an PR_DONE edge interrupt."]
    #[inline(always)]
    pub fn prd(&self) -> PrdR {
        PrdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Used by software to clear an nCONFIG Pin edge interrupt."]
    #[inline(always)]
    pub fn ncp(&self) -> NcpR {
        NcpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Used by software to clear an nSTATUS Pin edge interrupt."]
    #[inline(always)]
    pub fn nsp(&self) -> NspR {
        NspR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Used by software to clear an CONF_DONE Pin edge interrupt."]
    #[inline(always)]
    pub fn cdp(&self) -> CdpR {
        CdpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Used by software to clear an FPGA_POWER_ON edge interrupt."]
    #[inline(always)]
    pub fn fpo(&self) -> FpoR {
        FpoR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Used by software to clear an nSTATUS edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ns(&mut self) -> NsW<MonGpioPortaEoiSpec> {
        NsW::new(self, 0)
    }
    #[doc = "Bit 1 - Used by software to clear an CONF_DONE edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MonGpioPortaEoiSpec> {
        CdW::new(self, 1)
    }
    #[doc = "Bit 2 - Used by software to clear an INIT_DONE edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MonGpioPortaEoiSpec> {
        IdW::new(self, 2)
    }
    #[doc = "Bit 3 - Used by software to clear an CRC_ERROR edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn crc(&mut self) -> CrcW<MonGpioPortaEoiSpec> {
        CrcW::new(self, 3)
    }
    #[doc = "Bit 4 - Used by software to clear an CVP_CONF_DONE edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ccd(&mut self) -> CcdW<MonGpioPortaEoiSpec> {
        CcdW::new(self, 4)
    }
    #[doc = "Bit 5 - Used by software to clear an PR_READY edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn prr(&mut self) -> PrrW<MonGpioPortaEoiSpec> {
        PrrW::new(self, 5)
    }
    #[doc = "Bit 6 - Used by software to clear an PR_ERROR edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn pre(&mut self) -> PreW<MonGpioPortaEoiSpec> {
        PreW::new(self, 6)
    }
    #[doc = "Bit 7 - Used by software to clear an PR_DONE edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn prd(&mut self) -> PrdW<MonGpioPortaEoiSpec> {
        PrdW::new(self, 7)
    }
    #[doc = "Bit 8 - Used by software to clear an nCONFIG Pin edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ncp(&mut self) -> NcpW<MonGpioPortaEoiSpec> {
        NcpW::new(self, 8)
    }
    #[doc = "Bit 9 - Used by software to clear an nSTATUS Pin edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn nsp(&mut self) -> NspW<MonGpioPortaEoiSpec> {
        NspW::new(self, 9)
    }
    #[doc = "Bit 10 - Used by software to clear an CONF_DONE Pin edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cdp(&mut self) -> CdpW<MonGpioPortaEoiSpec> {
        CdpW::new(self, 10)
    }
    #[doc = "Bit 11 - Used by software to clear an FPGA_POWER_ON edge interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn fpo(&mut self) -> FpoW<MonGpioPortaEoiSpec> {
        FpoW::new(self, 11)
    }
}
#[doc = "This register is written by software to clear edge interrupts generated by each individual GPIO input. This register always reads back as zero.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_porta_eoi::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioPortaEoiSpec;
impl crate::RegisterSpec for MonGpioPortaEoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 2124u64;
}
#[doc = "`write(|w| ..)` method takes [`mon_gpio_porta_eoi::W`](W) writer structure"]
impl crate::Writable for MonGpioPortaEoiSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mon_gpio_porta_eoi to value 0"]
impl crate::Resettable for MonGpioPortaEoiSpec {
    const RESET_VALUE: u32 = 0;
}
