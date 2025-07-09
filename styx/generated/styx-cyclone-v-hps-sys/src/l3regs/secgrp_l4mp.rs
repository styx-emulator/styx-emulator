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
#[doc = "Register `secgrp_l4mp` reader"]
pub type R = crate::R<SecgrpL4mpSpec>;
#[doc = "Register `secgrp_l4mp` writer"]
pub type W = crate::W<SecgrpL4mpSpec>;
#[doc = "Field `fpgamgrregs` reader - Controls whether secure or non-secure masters can access the FPGA Manager Register slave."]
pub type FpgamgrregsR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the FPGA Manager Register slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpgamgrregs {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Fpgamgrregs> for bool {
    #[inline(always)]
    fn from(variant: Fpgamgrregs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpgamgrregs` writer - Controls whether secure or non-secure masters can access the FPGA Manager Register slave."]
pub type FpgamgrregsW<'a, REG> = crate::BitWriter<'a, REG, Fpgamgrregs>;
impl<'a, REG> FpgamgrregsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Fpgamgrregs::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Fpgamgrregs::Nonsecure)
    }
}
#[doc = "Field `dap` reader - Controls whether secure or non-secure masters can access the DAP slave."]
pub type DapR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the DAP slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dap {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Dap> for bool {
    #[inline(always)]
    fn from(variant: Dap) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dap` writer - Controls whether secure or non-secure masters can access the DAP slave."]
pub type DapW<'a, REG> = crate::BitWriter<'a, REG, Dap>;
impl<'a, REG> DapW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Dap::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Dap::Nonsecure)
    }
}
#[doc = "Field `qspiregs` reader - Controls whether secure or non-secure masters can access the QSPI Registers slave."]
pub type QspiregsR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the QSPI Registers slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qspiregs {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Qspiregs> for bool {
    #[inline(always)]
    fn from(variant: Qspiregs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `qspiregs` writer - Controls whether secure or non-secure masters can access the QSPI Registers slave."]
pub type QspiregsW<'a, REG> = crate::BitWriter<'a, REG, Qspiregs>;
impl<'a, REG> QspiregsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Qspiregs::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Qspiregs::Nonsecure)
    }
}
#[doc = "Field `sdmmc` reader - Controls whether secure or non-secure masters can access the SDMMC slave."]
pub type SdmmcR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SDMMC slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sdmmc {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Sdmmc> for bool {
    #[inline(always)]
    fn from(variant: Sdmmc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sdmmc` writer - Controls whether secure or non-secure masters can access the SDMMC slave."]
pub type SdmmcW<'a, REG> = crate::BitWriter<'a, REG, Sdmmc>;
impl<'a, REG> SdmmcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmmc::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmmc::Nonsecure)
    }
}
#[doc = "Field `emac0` reader - Controls whether secure or non-secure masters can access the EMAC 0 slave."]
pub type Emac0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the EMAC 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emac0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Emac0> for bool {
    #[inline(always)]
    fn from(variant: Emac0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `emac0` writer - Controls whether secure or non-secure masters can access the EMAC 0 slave."]
pub type Emac0W<'a, REG> = crate::BitWriter<'a, REG, Emac0>;
impl<'a, REG> Emac0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Emac0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Emac0::Nonsecure)
    }
}
#[doc = "Field `emac1` reader - Controls whether secure or non-secure masters can access the EMAC 1 slave."]
pub type Emac1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the EMAC 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emac1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Emac1> for bool {
    #[inline(always)]
    fn from(variant: Emac1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `emac1` writer - Controls whether secure or non-secure masters can access the EMAC 1 slave."]
pub type Emac1W<'a, REG> = crate::BitWriter<'a, REG, Emac1>;
impl<'a, REG> Emac1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Emac1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Emac1::Nonsecure)
    }
}
#[doc = "Field `acpidmap` reader - Controls whether secure or non-secure masters can access the ACP ID Mapper slave."]
pub type AcpidmapR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the ACP ID Mapper slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acpidmap {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Acpidmap> for bool {
    #[inline(always)]
    fn from(variant: Acpidmap) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `acpidmap` writer - Controls whether secure or non-secure masters can access the ACP ID Mapper slave."]
pub type AcpidmapW<'a, REG> = crate::BitWriter<'a, REG, Acpidmap>;
impl<'a, REG> AcpidmapW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Acpidmap::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Acpidmap::Nonsecure)
    }
}
#[doc = "Field `gpio0` reader - Controls whether secure or non-secure masters can access the GPIO 0 slave."]
pub type Gpio0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the GPIO 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gpio0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Gpio0> for bool {
    #[inline(always)]
    fn from(variant: Gpio0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gpio0` writer - Controls whether secure or non-secure masters can access the GPIO 0 slave."]
pub type Gpio0W<'a, REG> = crate::BitWriter<'a, REG, Gpio0>;
impl<'a, REG> Gpio0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Gpio0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Gpio0::Nonsecure)
    }
}
#[doc = "Field `gpio1` reader - Controls whether secure or non-secure masters can access the GPIO 1 slave."]
pub type Gpio1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the GPIO 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gpio1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Gpio1> for bool {
    #[inline(always)]
    fn from(variant: Gpio1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gpio1` writer - Controls whether secure or non-secure masters can access the GPIO 1 slave."]
pub type Gpio1W<'a, REG> = crate::BitWriter<'a, REG, Gpio1>;
impl<'a, REG> Gpio1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Gpio1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Gpio1::Nonsecure)
    }
}
#[doc = "Field `gpio2` reader - Controls whether secure or non-secure masters can access the GPIO 2 slave."]
pub type Gpio2R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the GPIO 2 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gpio2 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Gpio2> for bool {
    #[inline(always)]
    fn from(variant: Gpio2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gpio2` writer - Controls whether secure or non-secure masters can access the GPIO 2 slave."]
pub type Gpio2W<'a, REG> = crate::BitWriter<'a, REG, Gpio2>;
impl<'a, REG> Gpio2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Gpio2::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Gpio2::Nonsecure)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the FPGA Manager Register slave."]
    #[inline(always)]
    pub fn fpgamgrregs(&self) -> FpgamgrregsR {
        FpgamgrregsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the DAP slave."]
    #[inline(always)]
    pub fn dap(&self) -> DapR {
        DapR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the QSPI Registers slave."]
    #[inline(always)]
    pub fn qspiregs(&self) -> QspiregsR {
        QspiregsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the SDMMC slave."]
    #[inline(always)]
    pub fn sdmmc(&self) -> SdmmcR {
        SdmmcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls whether secure or non-secure masters can access the EMAC 0 slave."]
    #[inline(always)]
    pub fn emac0(&self) -> Emac0R {
        Emac0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Controls whether secure or non-secure masters can access the EMAC 1 slave."]
    #[inline(always)]
    pub fn emac1(&self) -> Emac1R {
        Emac1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Controls whether secure or non-secure masters can access the ACP ID Mapper slave."]
    #[inline(always)]
    pub fn acpidmap(&self) -> AcpidmapR {
        AcpidmapR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Controls whether secure or non-secure masters can access the GPIO 0 slave."]
    #[inline(always)]
    pub fn gpio0(&self) -> Gpio0R {
        Gpio0R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Controls whether secure or non-secure masters can access the GPIO 1 slave."]
    #[inline(always)]
    pub fn gpio1(&self) -> Gpio1R {
        Gpio1R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Controls whether secure or non-secure masters can access the GPIO 2 slave."]
    #[inline(always)]
    pub fn gpio2(&self) -> Gpio2R {
        Gpio2R::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the FPGA Manager Register slave."]
    #[inline(always)]
    #[must_use]
    pub fn fpgamgrregs(&mut self) -> FpgamgrregsW<SecgrpL4mpSpec> {
        FpgamgrregsW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the DAP slave."]
    #[inline(always)]
    #[must_use]
    pub fn dap(&mut self) -> DapW<SecgrpL4mpSpec> {
        DapW::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the QSPI Registers slave."]
    #[inline(always)]
    #[must_use]
    pub fn qspiregs(&mut self) -> QspiregsW<SecgrpL4mpSpec> {
        QspiregsW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the SDMMC slave."]
    #[inline(always)]
    #[must_use]
    pub fn sdmmc(&mut self) -> SdmmcW<SecgrpL4mpSpec> {
        SdmmcW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls whether secure or non-secure masters can access the EMAC 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn emac0(&mut self) -> Emac0W<SecgrpL4mpSpec> {
        Emac0W::new(self, 4)
    }
    #[doc = "Bit 5 - Controls whether secure or non-secure masters can access the EMAC 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn emac1(&mut self) -> Emac1W<SecgrpL4mpSpec> {
        Emac1W::new(self, 5)
    }
    #[doc = "Bit 6 - Controls whether secure or non-secure masters can access the ACP ID Mapper slave."]
    #[inline(always)]
    #[must_use]
    pub fn acpidmap(&mut self) -> AcpidmapW<SecgrpL4mpSpec> {
        AcpidmapW::new(self, 6)
    }
    #[doc = "Bit 7 - Controls whether secure or non-secure masters can access the GPIO 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn gpio0(&mut self) -> Gpio0W<SecgrpL4mpSpec> {
        Gpio0W::new(self, 7)
    }
    #[doc = "Bit 8 - Controls whether secure or non-secure masters can access the GPIO 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn gpio1(&mut self) -> Gpio1W<SecgrpL4mpSpec> {
        Gpio1W::new(self, 8)
    }
    #[doc = "Bit 9 - Controls whether secure or non-secure masters can access the GPIO 2 slave."]
    #[inline(always)]
    #[must_use]
    pub fn gpio2(&mut self) -> Gpio2W<SecgrpL4mpSpec> {
        Gpio2W::new(self, 9)
    }
}
#[doc = "Controls security settings for L4 MP peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4mp::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SecgrpL4mpSpec;
impl crate::RegisterSpec for SecgrpL4mpSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`write(|w| ..)` method takes [`secgrp_l4mp::W`](W) writer structure"]
impl crate::Writable for SecgrpL4mpSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets secgrp_l4mp to value 0"]
impl crate::Resettable for SecgrpL4mpSpec {
    const RESET_VALUE: u32 = 0;
}
