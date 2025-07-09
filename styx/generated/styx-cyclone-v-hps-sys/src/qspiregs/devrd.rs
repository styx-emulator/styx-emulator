// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devrd` reader"]
pub type R = crate::R<DevrdSpec>;
#[doc = "Register `devrd` writer"]
pub type W = crate::W<DevrdSpec>;
#[doc = "Read Opcode to use when not in XIP mode\n\nValue on reset: 3"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rdopcode {
    #[doc = "3: `11`"]
    Read = 3,
    #[doc = "11: `1011`"]
    Fastread = 11,
}
impl From<Rdopcode> for u8 {
    #[inline(always)]
    fn from(variant: Rdopcode) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rdopcode {
    type Ux = u8;
}
#[doc = "Field `rdopcode` reader - Read Opcode to use when not in XIP mode"]
pub type RdopcodeR = crate::FieldReader<Rdopcode>;
impl RdopcodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rdopcode> {
        match self.bits {
            3 => Some(Rdopcode::Read),
            11 => Some(Rdopcode::Fastread),
            _ => None,
        }
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_read(&self) -> bool {
        *self == Rdopcode::Read
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_fastread(&self) -> bool {
        *self == Rdopcode::Fastread
    }
}
#[doc = "Field `rdopcode` writer - Read Opcode to use when not in XIP mode"]
pub type RdopcodeW<'a, REG> = crate::FieldWriter<'a, REG, 8, Rdopcode>;
impl<'a, REG> RdopcodeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`11`"]
    #[inline(always)]
    pub fn read(self) -> &'a mut crate::W<REG> {
        self.variant(Rdopcode::Read)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn fastread(self) -> &'a mut crate::W<REG> {
        self.variant(Rdopcode::Fastread)
    }
}
#[doc = "Sets instruction transfer width (1, 2, or 4 bits). Applies to all instructions sent to SPI flash device (not just read instructions).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Instwidth {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Dual = 1,
    #[doc = "2: `10`"]
    Quad = 2,
}
impl From<Instwidth> for u8 {
    #[inline(always)]
    fn from(variant: Instwidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Instwidth {
    type Ux = u8;
}
#[doc = "Field `instwidth` reader - Sets instruction transfer width (1, 2, or 4 bits). Applies to all instructions sent to SPI flash device (not just read instructions)."]
pub type InstwidthR = crate::FieldReader<Instwidth>;
impl InstwidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Instwidth> {
        match self.bits {
            0 => Some(Instwidth::Single),
            1 => Some(Instwidth::Dual),
            2 => Some(Instwidth::Quad),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Instwidth::Single
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dual(&self) -> bool {
        *self == Instwidth::Dual
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_quad(&self) -> bool {
        *self == Instwidth::Quad
    }
}
#[doc = "Field `instwidth` writer - Sets instruction transfer width (1, 2, or 4 bits). Applies to all instructions sent to SPI flash device (not just read instructions)."]
pub type InstwidthW<'a, REG> = crate::FieldWriter<'a, REG, 2, Instwidth>;
impl<'a, REG> InstwidthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Instwidth::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dual(self) -> &'a mut crate::W<REG> {
        self.variant(Instwidth::Dual)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quad(self) -> &'a mut crate::W<REG> {
        self.variant(Instwidth::Quad)
    }
}
#[doc = "Sets read address transfer width (1, 2, or 4 bits).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Addrwidth {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Dual = 1,
    #[doc = "2: `10`"]
    Quad = 2,
}
impl From<Addrwidth> for u8 {
    #[inline(always)]
    fn from(variant: Addrwidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Addrwidth {
    type Ux = u8;
}
#[doc = "Field `addrwidth` reader - Sets read address transfer width (1, 2, or 4 bits)."]
pub type AddrwidthR = crate::FieldReader<Addrwidth>;
impl AddrwidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Addrwidth> {
        match self.bits {
            0 => Some(Addrwidth::Single),
            1 => Some(Addrwidth::Dual),
            2 => Some(Addrwidth::Quad),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Addrwidth::Single
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dual(&self) -> bool {
        *self == Addrwidth::Dual
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_quad(&self) -> bool {
        *self == Addrwidth::Quad
    }
}
#[doc = "Field `addrwidth` writer - Sets read address transfer width (1, 2, or 4 bits)."]
pub type AddrwidthW<'a, REG> = crate::FieldWriter<'a, REG, 2, Addrwidth>;
impl<'a, REG> AddrwidthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Addrwidth::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dual(self) -> &'a mut crate::W<REG> {
        self.variant(Addrwidth::Dual)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quad(self) -> &'a mut crate::W<REG> {
        self.variant(Addrwidth::Quad)
    }
}
#[doc = "Sets read data transfer width (1, 2, or 4 bits).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Datawidth {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Dual = 1,
    #[doc = "2: `10`"]
    Quad = 2,
}
impl From<Datawidth> for u8 {
    #[inline(always)]
    fn from(variant: Datawidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Datawidth {
    type Ux = u8;
}
#[doc = "Field `datawidth` reader - Sets read data transfer width (1, 2, or 4 bits)."]
pub type DatawidthR = crate::FieldReader<Datawidth>;
impl DatawidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Datawidth> {
        match self.bits {
            0 => Some(Datawidth::Single),
            1 => Some(Datawidth::Dual),
            2 => Some(Datawidth::Quad),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Datawidth::Single
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dual(&self) -> bool {
        *self == Datawidth::Dual
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_quad(&self) -> bool {
        *self == Datawidth::Quad
    }
}
#[doc = "Field `datawidth` writer - Sets read data transfer width (1, 2, or 4 bits)."]
pub type DatawidthW<'a, REG> = crate::FieldWriter<'a, REG, 2, Datawidth>;
impl<'a, REG> DatawidthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Datawidth::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dual(self) -> &'a mut crate::W<REG> {
        self.variant(Datawidth::Dual)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quad(self) -> &'a mut crate::W<REG> {
        self.variant(Datawidth::Quad)
    }
}
#[doc = "If this bit is set, the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enmodebits {
    #[doc = "0: `0`"]
    Noorder = 0,
    #[doc = "1: `1`"]
    Order = 1,
}
impl From<Enmodebits> for bool {
    #[inline(always)]
    fn from(variant: Enmodebits) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enmodebits` reader - If this bit is set, the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
pub type EnmodebitsR = crate::BitReader<Enmodebits>;
impl EnmodebitsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enmodebits {
        match self.bits {
            false => Enmodebits::Noorder,
            true => Enmodebits::Order,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noorder(&self) -> bool {
        *self == Enmodebits::Noorder
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_order(&self) -> bool {
        *self == Enmodebits::Order
    }
}
#[doc = "Field `enmodebits` writer - If this bit is set, the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
pub type EnmodebitsW<'a, REG> = crate::BitWriter<'a, REG, Enmodebits>;
impl<'a, REG> EnmodebitsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noorder(self) -> &'a mut crate::W<REG> {
        self.variant(Enmodebits::Noorder)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn order(self) -> &'a mut crate::W<REG> {
        self.variant(Enmodebits::Order)
    }
}
#[doc = "Field `dummyrdclks` reader - Number of dummy clock cycles required by device for read instruction."]
pub type DummyrdclksR = crate::FieldReader;
#[doc = "Field `dummyrdclks` writer - Number of dummy clock cycles required by device for read instruction."]
pub type DummyrdclksW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:7 - Read Opcode to use when not in XIP mode"]
    #[inline(always)]
    pub fn rdopcode(&self) -> RdopcodeR {
        RdopcodeR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:9 - Sets instruction transfer width (1, 2, or 4 bits). Applies to all instructions sent to SPI flash device (not just read instructions)."]
    #[inline(always)]
    pub fn instwidth(&self) -> InstwidthR {
        InstwidthR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 12:13 - Sets read address transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    pub fn addrwidth(&self) -> AddrwidthR {
        AddrwidthR::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 16:17 - Sets read data transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    pub fn datawidth(&self) -> DatawidthR {
        DatawidthR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 20 - If this bit is set, the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
    #[inline(always)]
    pub fn enmodebits(&self) -> EnmodebitsR {
        EnmodebitsR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bits 24:28 - Number of dummy clock cycles required by device for read instruction."]
    #[inline(always)]
    pub fn dummyrdclks(&self) -> DummyrdclksR {
        DummyrdclksR::new(((self.bits >> 24) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Read Opcode to use when not in XIP mode"]
    #[inline(always)]
    #[must_use]
    pub fn rdopcode(&mut self) -> RdopcodeW<DevrdSpec> {
        RdopcodeW::new(self, 0)
    }
    #[doc = "Bits 8:9 - Sets instruction transfer width (1, 2, or 4 bits). Applies to all instructions sent to SPI flash device (not just read instructions)."]
    #[inline(always)]
    #[must_use]
    pub fn instwidth(&mut self) -> InstwidthW<DevrdSpec> {
        InstwidthW::new(self, 8)
    }
    #[doc = "Bits 12:13 - Sets read address transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    #[must_use]
    pub fn addrwidth(&mut self) -> AddrwidthW<DevrdSpec> {
        AddrwidthW::new(self, 12)
    }
    #[doc = "Bits 16:17 - Sets read data transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    #[must_use]
    pub fn datawidth(&mut self) -> DatawidthW<DevrdSpec> {
        DatawidthW::new(self, 16)
    }
    #[doc = "Bit 20 - If this bit is set, the mode bits as defined in the Mode Bit Configuration register are sent following the address bytes."]
    #[inline(always)]
    #[must_use]
    pub fn enmodebits(&mut self) -> EnmodebitsW<DevrdSpec> {
        EnmodebitsW::new(self, 20)
    }
    #[doc = "Bits 24:28 - Number of dummy clock cycles required by device for read instruction."]
    #[inline(always)]
    #[must_use]
    pub fn dummyrdclks(&mut self) -> DummyrdclksW<DevrdSpec> {
        DummyrdclksW::new(self, 24)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devrd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devrd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevrdSpec;
impl crate::RegisterSpec for DevrdSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`devrd::R`](R) reader structure"]
impl crate::Readable for DevrdSpec {}
#[doc = "`write(|w| ..)` method takes [`devrd::W`](W) writer structure"]
impl crate::Writable for DevrdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devrd to value 0x03"]
impl crate::Resettable for DevrdSpec {
    const RESET_VALUE: u32 = 0x03;
}
