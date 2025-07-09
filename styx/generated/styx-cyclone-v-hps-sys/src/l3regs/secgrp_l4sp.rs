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
#[doc = "Register `secgrp_l4sp` reader"]
pub type R = crate::R<SecgrpL4spSpec>;
#[doc = "Register `secgrp_l4sp` writer"]
pub type W = crate::W<SecgrpL4spSpec>;
#[doc = "Field `sdrregs` reader - Controls whether secure or non-secure masters can access the SDRAM Registers slave."]
pub type SdrregsR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SDRAM Registers slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sdrregs {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Sdrregs> for bool {
    #[inline(always)]
    fn from(variant: Sdrregs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sdrregs` writer - Controls whether secure or non-secure masters can access the SDRAM Registers slave."]
pub type SdrregsW<'a, REG> = crate::BitWriter<'a, REG, Sdrregs>;
impl<'a, REG> SdrregsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Sdrregs::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Sdrregs::Nonsecure)
    }
}
#[doc = "Field `sptimer0` reader - Controls whether secure or non-secure masters can access the SP Timer 0 slave."]
pub type Sptimer0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SP Timer 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sptimer0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Sptimer0> for bool {
    #[inline(always)]
    fn from(variant: Sptimer0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sptimer0` writer - Controls whether secure or non-secure masters can access the SP Timer 0 slave."]
pub type Sptimer0W<'a, REG> = crate::BitWriter<'a, REG, Sptimer0>;
impl<'a, REG> Sptimer0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Sptimer0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Sptimer0::Nonsecure)
    }
}
#[doc = "Field `i2c0` reader - Controls whether secure or non-secure masters can access the I2C0 slave."]
pub type I2c0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the I2C0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2c0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<I2c0> for bool {
    #[inline(always)]
    fn from(variant: I2c0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `i2c0` writer - Controls whether secure or non-secure masters can access the I2C0 slave."]
pub type I2c0W<'a, REG> = crate::BitWriter<'a, REG, I2c0>;
impl<'a, REG> I2c0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c0::Nonsecure)
    }
}
#[doc = "Field `i2c1` reader - Controls whether secure or non-secure masters can access the I2C1 slave."]
pub type I2c1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the I2C1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2c1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<I2c1> for bool {
    #[inline(always)]
    fn from(variant: I2c1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `i2c1` writer - Controls whether secure or non-secure masters can access the I2C1 slave."]
pub type I2c1W<'a, REG> = crate::BitWriter<'a, REG, I2c1>;
impl<'a, REG> I2c1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c1::Nonsecure)
    }
}
#[doc = "Field `i2c2` reader - Controls whether secure or non-secure masters can access the I2C2 (EMAC 0) slave."]
pub type I2c2R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the I2C2 (EMAC 0) slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2c2 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<I2c2> for bool {
    #[inline(always)]
    fn from(variant: I2c2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `i2c2` writer - Controls whether secure or non-secure masters can access the I2C2 (EMAC 0) slave."]
pub type I2c2W<'a, REG> = crate::BitWriter<'a, REG, I2c2>;
impl<'a, REG> I2c2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c2::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c2::Nonsecure)
    }
}
#[doc = "Field `i2c3` reader - Controls whether secure or non-secure masters can access the I2C3 (EMAC 1) slave."]
pub type I2c3R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the I2C3 (EMAC 1) slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2c3 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<I2c3> for bool {
    #[inline(always)]
    fn from(variant: I2c3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `i2c3` writer - Controls whether secure or non-secure masters can access the I2C3 (EMAC 1) slave."]
pub type I2c3W<'a, REG> = crate::BitWriter<'a, REG, I2c3>;
impl<'a, REG> I2c3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c3::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(I2c3::Nonsecure)
    }
}
#[doc = "Field `uart0` reader - Controls whether secure or non-secure masters can access the UART 0 slave."]
pub type Uart0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the UART 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uart0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Uart0> for bool {
    #[inline(always)]
    fn from(variant: Uart0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `uart0` writer - Controls whether secure or non-secure masters can access the UART 0 slave."]
pub type Uart0W<'a, REG> = crate::BitWriter<'a, REG, Uart0>;
impl<'a, REG> Uart0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Uart0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Uart0::Nonsecure)
    }
}
#[doc = "Field `uart1` reader - Controls whether secure or non-secure masters can access the UART 1 slave."]
pub type Uart1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the UART 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uart1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Uart1> for bool {
    #[inline(always)]
    fn from(variant: Uart1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `uart1` writer - Controls whether secure or non-secure masters can access the UART 1 slave."]
pub type Uart1W<'a, REG> = crate::BitWriter<'a, REG, Uart1>;
impl<'a, REG> Uart1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Uart1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Uart1::Nonsecure)
    }
}
#[doc = "Field `can0` reader - Controls whether secure or non-secure masters can access the CAN 0 slave."]
pub type Can0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the CAN 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Can0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Can0> for bool {
    #[inline(always)]
    fn from(variant: Can0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `can0` writer - Controls whether secure or non-secure masters can access the CAN 0 slave."]
pub type Can0W<'a, REG> = crate::BitWriter<'a, REG, Can0>;
impl<'a, REG> Can0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Can0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Can0::Nonsecure)
    }
}
#[doc = "Field `can1` reader - Controls whether secure or non-secure masters can access the CAN 1 slave."]
pub type Can1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the CAN 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Can1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Can1> for bool {
    #[inline(always)]
    fn from(variant: Can1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `can1` writer - Controls whether secure or non-secure masters can access the CAN 1 slave."]
pub type Can1W<'a, REG> = crate::BitWriter<'a, REG, Can1>;
impl<'a, REG> Can1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Can1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Can1::Nonsecure)
    }
}
#[doc = "Field `sptimer1` reader - Controls whether secure or non-secure masters can access the SP Timer 1 slave."]
pub type Sptimer1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SP Timer 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sptimer1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Sptimer1> for bool {
    #[inline(always)]
    fn from(variant: Sptimer1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sptimer1` writer - Controls whether secure or non-secure masters can access the SP Timer 1 slave."]
pub type Sptimer1W<'a, REG> = crate::BitWriter<'a, REG, Sptimer1>;
impl<'a, REG> Sptimer1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Sptimer1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Sptimer1::Nonsecure)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the SDRAM Registers slave."]
    #[inline(always)]
    pub fn sdrregs(&self) -> SdrregsR {
        SdrregsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the SP Timer 0 slave."]
    #[inline(always)]
    pub fn sptimer0(&self) -> Sptimer0R {
        Sptimer0R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the I2C0 slave."]
    #[inline(always)]
    pub fn i2c0(&self) -> I2c0R {
        I2c0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the I2C1 slave."]
    #[inline(always)]
    pub fn i2c1(&self) -> I2c1R {
        I2c1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls whether secure or non-secure masters can access the I2C2 (EMAC 0) slave."]
    #[inline(always)]
    pub fn i2c2(&self) -> I2c2R {
        I2c2R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Controls whether secure or non-secure masters can access the I2C3 (EMAC 1) slave."]
    #[inline(always)]
    pub fn i2c3(&self) -> I2c3R {
        I2c3R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Controls whether secure or non-secure masters can access the UART 0 slave."]
    #[inline(always)]
    pub fn uart0(&self) -> Uart0R {
        Uart0R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Controls whether secure or non-secure masters can access the UART 1 slave."]
    #[inline(always)]
    pub fn uart1(&self) -> Uart1R {
        Uart1R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Controls whether secure or non-secure masters can access the CAN 0 slave."]
    #[inline(always)]
    pub fn can0(&self) -> Can0R {
        Can0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Controls whether secure or non-secure masters can access the CAN 1 slave."]
    #[inline(always)]
    pub fn can1(&self) -> Can1R {
        Can1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Controls whether secure or non-secure masters can access the SP Timer 1 slave."]
    #[inline(always)]
    pub fn sptimer1(&self) -> Sptimer1R {
        Sptimer1R::new(((self.bits >> 10) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the SDRAM Registers slave."]
    #[inline(always)]
    #[must_use]
    pub fn sdrregs(&mut self) -> SdrregsW<SecgrpL4spSpec> {
        SdrregsW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the SP Timer 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn sptimer0(&mut self) -> Sptimer0W<SecgrpL4spSpec> {
        Sptimer0W::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the I2C0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn i2c0(&mut self) -> I2c0W<SecgrpL4spSpec> {
        I2c0W::new(self, 2)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the I2C1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn i2c1(&mut self) -> I2c1W<SecgrpL4spSpec> {
        I2c1W::new(self, 3)
    }
    #[doc = "Bit 4 - Controls whether secure or non-secure masters can access the I2C2 (EMAC 0) slave."]
    #[inline(always)]
    #[must_use]
    pub fn i2c2(&mut self) -> I2c2W<SecgrpL4spSpec> {
        I2c2W::new(self, 4)
    }
    #[doc = "Bit 5 - Controls whether secure or non-secure masters can access the I2C3 (EMAC 1) slave."]
    #[inline(always)]
    #[must_use]
    pub fn i2c3(&mut self) -> I2c3W<SecgrpL4spSpec> {
        I2c3W::new(self, 5)
    }
    #[doc = "Bit 6 - Controls whether secure or non-secure masters can access the UART 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn uart0(&mut self) -> Uart0W<SecgrpL4spSpec> {
        Uart0W::new(self, 6)
    }
    #[doc = "Bit 7 - Controls whether secure or non-secure masters can access the UART 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn uart1(&mut self) -> Uart1W<SecgrpL4spSpec> {
        Uart1W::new(self, 7)
    }
    #[doc = "Bit 8 - Controls whether secure or non-secure masters can access the CAN 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn can0(&mut self) -> Can0W<SecgrpL4spSpec> {
        Can0W::new(self, 8)
    }
    #[doc = "Bit 9 - Controls whether secure or non-secure masters can access the CAN 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn can1(&mut self) -> Can1W<SecgrpL4spSpec> {
        Can1W::new(self, 9)
    }
    #[doc = "Bit 10 - Controls whether secure or non-secure masters can access the SP Timer 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn sptimer1(&mut self) -> Sptimer1W<SecgrpL4spSpec> {
        Sptimer1W::new(self, 10)
    }
}
#[doc = "Controls security settings for L4 SP peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4sp::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SecgrpL4spSpec;
impl crate::RegisterSpec for SecgrpL4spSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`write(|w| ..)` method takes [`secgrp_l4sp::W`](W) writer structure"]
impl crate::Writable for SecgrpL4spSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets secgrp_l4sp to value 0"]
impl crate::Resettable for SecgrpL4spSpec {
    const RESET_VALUE: u32 = 0;
}
