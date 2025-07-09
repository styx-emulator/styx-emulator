// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_ctrl` reader"]
pub type R = crate::R<DmagrpCtrlSpec>;
#[doc = "Register `dmagrp_ctrl` writer"]
pub type W = crate::W<DmagrpCtrlSpec>;
#[doc = "Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chansel0 {
    #[doc = "0: `0`"]
    Fpga = 0,
    #[doc = "1: `1`"]
    Can = 1,
}
impl From<Chansel0> for bool {
    #[inline(always)]
    fn from(variant: Chansel0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chansel_0` reader - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel0R = crate::BitReader<Chansel0>;
impl Chansel0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chansel0 {
        match self.bits {
            false => Chansel0::Fpga,
            true => Chansel0::Can,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fpga(&self) -> bool {
        *self == Chansel0::Fpga
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_can(&self) -> bool {
        *self == Chansel0::Can
    }
}
#[doc = "Field `chansel_0` writer - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel0W<'a, REG> = crate::BitWriter<'a, REG, Chansel0>;
impl<'a, REG> Chansel0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fpga(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel0::Fpga)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn can(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel0::Can)
    }
}
#[doc = "Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chansel1 {
    #[doc = "0: `0`"]
    Fpga = 0,
    #[doc = "1: `1`"]
    Can = 1,
}
impl From<Chansel1> for bool {
    #[inline(always)]
    fn from(variant: Chansel1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chansel_1` reader - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel1R = crate::BitReader<Chansel1>;
impl Chansel1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chansel1 {
        match self.bits {
            false => Chansel1::Fpga,
            true => Chansel1::Can,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fpga(&self) -> bool {
        *self == Chansel1::Fpga
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_can(&self) -> bool {
        *self == Chansel1::Can
    }
}
#[doc = "Field `chansel_1` writer - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel1W<'a, REG> = crate::BitWriter<'a, REG, Chansel1>;
impl<'a, REG> Chansel1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fpga(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel1::Fpga)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn can(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel1::Can)
    }
}
#[doc = "Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chansel2 {
    #[doc = "0: `0`"]
    Fpga = 0,
    #[doc = "1: `1`"]
    Can = 1,
}
impl From<Chansel2> for bool {
    #[inline(always)]
    fn from(variant: Chansel2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chansel_2` reader - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel2R = crate::BitReader<Chansel2>;
impl Chansel2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chansel2 {
        match self.bits {
            false => Chansel2::Fpga,
            true => Chansel2::Can,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fpga(&self) -> bool {
        *self == Chansel2::Fpga
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_can(&self) -> bool {
        *self == Chansel2::Can
    }
}
#[doc = "Field `chansel_2` writer - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel2W<'a, REG> = crate::BitWriter<'a, REG, Chansel2>;
impl<'a, REG> Chansel2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fpga(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel2::Fpga)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn can(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel2::Can)
    }
}
#[doc = "Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chansel3 {
    #[doc = "0: `0`"]
    Fpga = 0,
    #[doc = "1: `1`"]
    Can = 1,
}
impl From<Chansel3> for bool {
    #[inline(always)]
    fn from(variant: Chansel3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chansel_3` reader - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel3R = crate::BitReader<Chansel3>;
impl Chansel3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chansel3 {
        match self.bits {
            false => Chansel3::Fpga,
            true => Chansel3::Can,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fpga(&self) -> bool {
        *self == Chansel3::Fpga
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_can(&self) -> bool {
        *self == Chansel3::Can
    }
}
#[doc = "Field `chansel_3` writer - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
pub type Chansel3W<'a, REG> = crate::BitWriter<'a, REG, Chansel3>;
impl<'a, REG> Chansel3W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fpga(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel3::Fpga)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn can(self) -> &'a mut crate::W<REG> {
        self.variant(Chansel3::Can)
    }
}
#[doc = "Field `mgrnonsecure` reader - Specifies the security state of the DMA manager thread. 0 = assigns DMA manager to the Secure state. 1 = assigns DMA manager to the Non-secure state. Sampled by the DMA controller when it exits from reset."]
pub type MgrnonsecureR = crate::BitReader;
#[doc = "Field `mgrnonsecure` writer - Specifies the security state of the DMA manager thread. 0 = assigns DMA manager to the Secure state. 1 = assigns DMA manager to the Non-secure state. Sampled by the DMA controller when it exits from reset."]
pub type MgrnonsecureW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `irqnonsecure` reader - Specifies the security state of an event-interrupt resource. If bit index \\[x\\]
is 0, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Secure state. If bit index \\[x\\]
is 1, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Non-secure state."]
pub type IrqnonsecureR = crate::FieldReader;
#[doc = "Field `irqnonsecure` writer - Specifies the security state of an event-interrupt resource. If bit index \\[x\\]
is 0, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Secure state. If bit index \\[x\\]
is 1, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Non-secure state."]
pub type IrqnonsecureW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bit 0 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    pub fn chansel_0(&self) -> Chansel0R {
        Chansel0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    pub fn chansel_1(&self) -> Chansel1R {
        Chansel1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    pub fn chansel_2(&self) -> Chansel2R {
        Chansel2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    pub fn chansel_3(&self) -> Chansel3R {
        Chansel3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Specifies the security state of the DMA manager thread. 0 = assigns DMA manager to the Secure state. 1 = assigns DMA manager to the Non-secure state. Sampled by the DMA controller when it exits from reset."]
    #[inline(always)]
    pub fn mgrnonsecure(&self) -> MgrnonsecureR {
        MgrnonsecureR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:12 - Specifies the security state of an event-interrupt resource. If bit index \\[x\\]
is 0, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Secure state. If bit index \\[x\\]
is 1, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Non-secure state."]
    #[inline(always)]
    pub fn irqnonsecure(&self) -> IrqnonsecureR {
        IrqnonsecureR::new(((self.bits >> 5) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    #[must_use]
    pub fn chansel_0(&mut self) -> Chansel0W<DmagrpCtrlSpec> {
        Chansel0W::new(self, 0)
    }
    #[doc = "Bit 1 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    #[must_use]
    pub fn chansel_1(&mut self) -> Chansel1W<DmagrpCtrlSpec> {
        Chansel1W::new(self, 1)
    }
    #[doc = "Bit 2 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    #[must_use]
    pub fn chansel_2(&mut self) -> Chansel2W<DmagrpCtrlSpec> {
        Chansel2W::new(self, 2)
    }
    #[doc = "Bit 3 - Controls mux that selects whether FPGA or CAN connects to one of the DMA peripheral request interfaces.The peripheral request interface index equals the array index + 4. For example, array index 0 is for peripheral request index 4."]
    #[inline(always)]
    #[must_use]
    pub fn chansel_3(&mut self) -> Chansel3W<DmagrpCtrlSpec> {
        Chansel3W::new(self, 3)
    }
    #[doc = "Bit 4 - Specifies the security state of the DMA manager thread. 0 = assigns DMA manager to the Secure state. 1 = assigns DMA manager to the Non-secure state. Sampled by the DMA controller when it exits from reset."]
    #[inline(always)]
    #[must_use]
    pub fn mgrnonsecure(&mut self) -> MgrnonsecureW<DmagrpCtrlSpec> {
        MgrnonsecureW::new(self, 4)
    }
    #[doc = "Bits 5:12 - Specifies the security state of an event-interrupt resource. If bit index \\[x\\]
is 0, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Secure state. If bit index \\[x\\]
is 1, the DMAC assigns event&lt;x> or irq\\[x\\]
to the Non-secure state."]
    #[inline(always)]
    #[must_use]
    pub fn irqnonsecure(&mut self) -> IrqnonsecureW<DmagrpCtrlSpec> {
        IrqnonsecureW::new(self, 5)
    }
}
#[doc = "Registers used by the DMA Controller. All fields are reset by a cold or warm reset. These register bits should be updated during system initialization prior to removing the DMA controller from reset. They may not be changed dynamically during DMA operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpCtrlSpec;
impl crate::RegisterSpec for DmagrpCtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`dmagrp_ctrl::R`](R) reader structure"]
impl crate::Readable for DmagrpCtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_ctrl::W`](W) writer structure"]
impl crate::Writable for DmagrpCtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_ctrl to value 0"]
impl crate::Resettable for DmagrpCtrlSpec {
    const RESET_VALUE: u32 = 0;
}
