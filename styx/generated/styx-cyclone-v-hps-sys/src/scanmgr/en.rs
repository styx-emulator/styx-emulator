// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `en` reader"]
pub type R = crate::R<EnSpec>;
#[doc = "Register `en` writer"]
pub type W = crate::W<EnSpec>;
#[doc = "Used to enable or disable I/O Scan-Chain 0 The name of this field in ARM documentation is PSEL0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ioscanchain0 {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ioscanchain0> for bool {
    #[inline(always)]
    fn from(variant: Ioscanchain0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ioscanchain0` reader - Used to enable or disable I/O Scan-Chain 0 The name of this field in ARM documentation is PSEL0."]
pub type Ioscanchain0R = crate::BitReader<Ioscanchain0>;
impl Ioscanchain0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ioscanchain0 {
        match self.bits {
            false => Ioscanchain0::Disable,
            true => Ioscanchain0::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ioscanchain0::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ioscanchain0::Enable
    }
}
#[doc = "Field `ioscanchain0` writer - Used to enable or disable I/O Scan-Chain 0 The name of this field in ARM documentation is PSEL0."]
pub type Ioscanchain0W<'a, REG> = crate::BitWriter<'a, REG, Ioscanchain0>;
impl<'a, REG> Ioscanchain0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain0::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain0::Enable)
    }
}
#[doc = "Used to enable or disable I/O Scan-Chain 1 The name of this field in ARM documentation is PSEL1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ioscanchain1 {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ioscanchain1> for bool {
    #[inline(always)]
    fn from(variant: Ioscanchain1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ioscanchain1` reader - Used to enable or disable I/O Scan-Chain 1 The name of this field in ARM documentation is PSEL1."]
pub type Ioscanchain1R = crate::BitReader<Ioscanchain1>;
impl Ioscanchain1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ioscanchain1 {
        match self.bits {
            false => Ioscanchain1::Disable,
            true => Ioscanchain1::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ioscanchain1::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ioscanchain1::Enable
    }
}
#[doc = "Field `ioscanchain1` writer - Used to enable or disable I/O Scan-Chain 1 The name of this field in ARM documentation is PSEL1."]
pub type Ioscanchain1W<'a, REG> = crate::BitWriter<'a, REG, Ioscanchain1>;
impl<'a, REG> Ioscanchain1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain1::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain1::Enable)
    }
}
#[doc = "Used to enable or disable I/O Scan-Chain 2 The name of this field in ARM documentation is PSEL2.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ioscanchain2 {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ioscanchain2> for bool {
    #[inline(always)]
    fn from(variant: Ioscanchain2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ioscanchain2` reader - Used to enable or disable I/O Scan-Chain 2 The name of this field in ARM documentation is PSEL2."]
pub type Ioscanchain2R = crate::BitReader<Ioscanchain2>;
impl Ioscanchain2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ioscanchain2 {
        match self.bits {
            false => Ioscanchain2::Disable,
            true => Ioscanchain2::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ioscanchain2::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ioscanchain2::Enable
    }
}
#[doc = "Field `ioscanchain2` writer - Used to enable or disable I/O Scan-Chain 2 The name of this field in ARM documentation is PSEL2."]
pub type Ioscanchain2W<'a, REG> = crate::BitWriter<'a, REG, Ioscanchain2>;
impl<'a, REG> Ioscanchain2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain2::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain2::Enable)
    }
}
#[doc = "Used to enable or disable I/O Scan-Chain 3 The name of this field in ARM documentation is PSEL3.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ioscanchain3 {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ioscanchain3> for bool {
    #[inline(always)]
    fn from(variant: Ioscanchain3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ioscanchain3` reader - Used to enable or disable I/O Scan-Chain 3 The name of this field in ARM documentation is PSEL3."]
pub type Ioscanchain3R = crate::BitReader<Ioscanchain3>;
impl Ioscanchain3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ioscanchain3 {
        match self.bits {
            false => Ioscanchain3::Disable,
            true => Ioscanchain3::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ioscanchain3::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ioscanchain3::Enable
    }
}
#[doc = "Field `ioscanchain3` writer - Used to enable or disable I/O Scan-Chain 3 The name of this field in ARM documentation is PSEL3."]
pub type Ioscanchain3W<'a, REG> = crate::BitWriter<'a, REG, Ioscanchain3>;
impl<'a, REG> Ioscanchain3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain3::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ioscanchain3::Enable)
    }
}
#[doc = "Used to enable or disable FPGA JTAG scan-chain.Software must use the System Manager to enable the Scan Manager to drive the FPGA JTAG before attempting to communicate with the FPGA JTAG via the Scan Manager. The name of this field in ARM documentation is PSEL7.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpgajtag {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Fpgajtag> for bool {
    #[inline(always)]
    fn from(variant: Fpgajtag) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpgajtag` reader - Used to enable or disable FPGA JTAG scan-chain.Software must use the System Manager to enable the Scan Manager to drive the FPGA JTAG before attempting to communicate with the FPGA JTAG via the Scan Manager. The name of this field in ARM documentation is PSEL7."]
pub type FpgajtagR = crate::BitReader<Fpgajtag>;
impl FpgajtagR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fpgajtag {
        match self.bits {
            false => Fpgajtag::Disable,
            true => Fpgajtag::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Fpgajtag::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Fpgajtag::Enable
    }
}
#[doc = "Field `fpgajtag` writer - Used to enable or disable FPGA JTAG scan-chain.Software must use the System Manager to enable the Scan Manager to drive the FPGA JTAG before attempting to communicate with the FPGA JTAG via the Scan Manager. The name of this field in ARM documentation is PSEL7."]
pub type FpgajtagW<'a, REG> = crate::BitWriter<'a, REG, Fpgajtag>;
impl<'a, REG> FpgajtagW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Fpgajtag::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Fpgajtag::Enable)
    }
}
impl R {
    #[doc = "Bit 0 - Used to enable or disable I/O Scan-Chain 0 The name of this field in ARM documentation is PSEL0."]
    #[inline(always)]
    pub fn ioscanchain0(&self) -> Ioscanchain0R {
        Ioscanchain0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Used to enable or disable I/O Scan-Chain 1 The name of this field in ARM documentation is PSEL1."]
    #[inline(always)]
    pub fn ioscanchain1(&self) -> Ioscanchain1R {
        Ioscanchain1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Used to enable or disable I/O Scan-Chain 2 The name of this field in ARM documentation is PSEL2."]
    #[inline(always)]
    pub fn ioscanchain2(&self) -> Ioscanchain2R {
        Ioscanchain2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Used to enable or disable I/O Scan-Chain 3 The name of this field in ARM documentation is PSEL3."]
    #[inline(always)]
    pub fn ioscanchain3(&self) -> Ioscanchain3R {
        Ioscanchain3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 7 - Used to enable or disable FPGA JTAG scan-chain.Software must use the System Manager to enable the Scan Manager to drive the FPGA JTAG before attempting to communicate with the FPGA JTAG via the Scan Manager. The name of this field in ARM documentation is PSEL7."]
    #[inline(always)]
    pub fn fpgajtag(&self) -> FpgajtagR {
        FpgajtagR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Used to enable or disable I/O Scan-Chain 0 The name of this field in ARM documentation is PSEL0."]
    #[inline(always)]
    #[must_use]
    pub fn ioscanchain0(&mut self) -> Ioscanchain0W<EnSpec> {
        Ioscanchain0W::new(self, 0)
    }
    #[doc = "Bit 1 - Used to enable or disable I/O Scan-Chain 1 The name of this field in ARM documentation is PSEL1."]
    #[inline(always)]
    #[must_use]
    pub fn ioscanchain1(&mut self) -> Ioscanchain1W<EnSpec> {
        Ioscanchain1W::new(self, 1)
    }
    #[doc = "Bit 2 - Used to enable or disable I/O Scan-Chain 2 The name of this field in ARM documentation is PSEL2."]
    #[inline(always)]
    #[must_use]
    pub fn ioscanchain2(&mut self) -> Ioscanchain2W<EnSpec> {
        Ioscanchain2W::new(self, 2)
    }
    #[doc = "Bit 3 - Used to enable or disable I/O Scan-Chain 3 The name of this field in ARM documentation is PSEL3."]
    #[inline(always)]
    #[must_use]
    pub fn ioscanchain3(&mut self) -> Ioscanchain3W<EnSpec> {
        Ioscanchain3W::new(self, 3)
    }
    #[doc = "Bit 7 - Used to enable or disable FPGA JTAG scan-chain.Software must use the System Manager to enable the Scan Manager to drive the FPGA JTAG before attempting to communicate with the FPGA JTAG via the Scan Manager. The name of this field in ARM documentation is PSEL7."]
    #[inline(always)]
    #[must_use]
    pub fn fpgajtag(&mut self) -> FpgajtagW<EnSpec> {
        FpgajtagW::new(self, 7)
    }
}
#[doc = "This register is used to enable one of the 5 scan-chains (0-3 and 7). Only one scan-chain must be enabled at a time. A scan-chain is enabled by writing its corresponding enable field. Software must use the System Manager to put the corresponding I/O scan-chain into the frozen state before attempting to send I/O configuration data to the I/O scan-chain. Software must only write to this register when the Scan-Chain Engine is inactive.Writing this field at any other time has unpredictable results. This means that before writing to this field, software must read the STAT register and check that the ACTIVE and WFIFOCNT fields are both zero. The name of this register in ARM documentation is PSEL.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`en::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`en::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EnSpec;
impl crate::RegisterSpec for EnSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`en::R`](R) reader structure"]
impl crate::Readable for EnSpec {}
#[doc = "`write(|w| ..)` method takes [`en::W`](W) writer structure"]
impl crate::Writable for EnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets en to value 0"]
impl crate::Resettable for EnSpec {
    const RESET_VALUE: u32 = 0;
}
