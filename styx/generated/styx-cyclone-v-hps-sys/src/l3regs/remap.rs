// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `remap` reader"]
pub type R = crate::R<RemapSpec>;
#[doc = "Register `remap` writer"]
pub type W = crate::W<RemapSpec>;
#[doc = "Field `mpuzero` reader - Controls whether address 0x0 for the MPU L3 master is mapped to the Boot ROM or On-chip RAM. This field only has an effect on the MPU L3 master."]
pub type MpuzeroR = crate::BitReader;
#[doc = "Controls whether address 0x0 for the MPU L3 master is mapped to the Boot ROM or On-chip RAM. This field only has an effect on the MPU L3 master.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mpuzero {
    #[doc = "0: `0`"]
    Bootrom = 0,
    #[doc = "1: `1`"]
    Ocram = 1,
}
impl From<Mpuzero> for bool {
    #[inline(always)]
    fn from(variant: Mpuzero) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mpuzero` writer - Controls whether address 0x0 for the MPU L3 master is mapped to the Boot ROM or On-chip RAM. This field only has an effect on the MPU L3 master."]
pub type MpuzeroW<'a, REG> = crate::BitWriter<'a, REG, Mpuzero>;
impl<'a, REG> MpuzeroW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn bootrom(self) -> &'a mut crate::W<REG> {
        self.variant(Mpuzero::Bootrom)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ocram(self) -> &'a mut crate::W<REG> {
        self.variant(Mpuzero::Ocram)
    }
}
#[doc = "Field `nonmpuzero` reader - Controls whether address 0x0 for the non-MPU L3 masters is mapped to the SDRAM or On-chip RAM. This field only has an effect on the non-MPU L3 masters. The non-MPU L3 masters are the DMA controllers (standalone and those built-in to peripherals), the FPGA2HPS AXI Bridge, and the DAP."]
pub type NonmpuzeroR = crate::BitReader;
#[doc = "Controls whether address 0x0 for the non-MPU L3 masters is mapped to the SDRAM or On-chip RAM. This field only has an effect on the non-MPU L3 masters. The non-MPU L3 masters are the DMA controllers (standalone and those built-in to peripherals), the FPGA2HPS AXI Bridge, and the DAP.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nonmpuzero {
    #[doc = "0: `0`"]
    Sdram = 0,
    #[doc = "1: `1`"]
    Ocram = 1,
}
impl From<Nonmpuzero> for bool {
    #[inline(always)]
    fn from(variant: Nonmpuzero) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nonmpuzero` writer - Controls whether address 0x0 for the non-MPU L3 masters is mapped to the SDRAM or On-chip RAM. This field only has an effect on the non-MPU L3 masters. The non-MPU L3 masters are the DMA controllers (standalone and those built-in to peripherals), the FPGA2HPS AXI Bridge, and the DAP."]
pub type NonmpuzeroW<'a, REG> = crate::BitWriter<'a, REG, Nonmpuzero>;
impl<'a, REG> NonmpuzeroW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn sdram(self) -> &'a mut crate::W<REG> {
        self.variant(Nonmpuzero::Sdram)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ocram(self) -> &'a mut crate::W<REG> {
        self.variant(Nonmpuzero::Ocram)
    }
}
#[doc = "Field `hps2fpga` reader - Controls whether the HPS2FPGA AXI Bridge is visible to L3 masters or not."]
pub type Hps2fpgaR = crate::BitReader;
#[doc = "Controls whether the HPS2FPGA AXI Bridge is visible to L3 masters or not.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hps2fpga {
    #[doc = "0: `0`"]
    Invisible = 0,
    #[doc = "1: `1`"]
    Visible = 1,
}
impl From<Hps2fpga> for bool {
    #[inline(always)]
    fn from(variant: Hps2fpga) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hps2fpga` writer - Controls whether the HPS2FPGA AXI Bridge is visible to L3 masters or not."]
pub type Hps2fpgaW<'a, REG> = crate::BitWriter<'a, REG, Hps2fpga>;
impl<'a, REG> Hps2fpgaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn invisible(self) -> &'a mut crate::W<REG> {
        self.variant(Hps2fpga::Invisible)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn visible(self) -> &'a mut crate::W<REG> {
        self.variant(Hps2fpga::Visible)
    }
}
#[doc = "Field `lwhps2fpga` reader - Controls whether the Lightweight HPS2FPGA AXI Bridge is visible to L3 masters or not."]
pub type Lwhps2fpgaR = crate::BitReader;
#[doc = "Controls whether the Lightweight HPS2FPGA AXI Bridge is visible to L3 masters or not.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lwhps2fpga {
    #[doc = "0: `0`"]
    Invisible = 0,
    #[doc = "1: `1`"]
    Visible = 1,
}
impl From<Lwhps2fpga> for bool {
    #[inline(always)]
    fn from(variant: Lwhps2fpga) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lwhps2fpga` writer - Controls whether the Lightweight HPS2FPGA AXI Bridge is visible to L3 masters or not."]
pub type Lwhps2fpgaW<'a, REG> = crate::BitWriter<'a, REG, Lwhps2fpga>;
impl<'a, REG> Lwhps2fpgaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn invisible(self) -> &'a mut crate::W<REG> {
        self.variant(Lwhps2fpga::Invisible)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn visible(self) -> &'a mut crate::W<REG> {
        self.variant(Lwhps2fpga::Visible)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether address 0x0 for the MPU L3 master is mapped to the Boot ROM or On-chip RAM. This field only has an effect on the MPU L3 master."]
    #[inline(always)]
    pub fn mpuzero(&self) -> MpuzeroR {
        MpuzeroR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether address 0x0 for the non-MPU L3 masters is mapped to the SDRAM or On-chip RAM. This field only has an effect on the non-MPU L3 masters. The non-MPU L3 masters are the DMA controllers (standalone and those built-in to peripherals), the FPGA2HPS AXI Bridge, and the DAP."]
    #[inline(always)]
    pub fn nonmpuzero(&self) -> NonmpuzeroR {
        NonmpuzeroR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether the HPS2FPGA AXI Bridge is visible to L3 masters or not."]
    #[inline(always)]
    pub fn hps2fpga(&self) -> Hps2fpgaR {
        Hps2fpgaR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls whether the Lightweight HPS2FPGA AXI Bridge is visible to L3 masters or not."]
    #[inline(always)]
    pub fn lwhps2fpga(&self) -> Lwhps2fpgaR {
        Lwhps2fpgaR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether address 0x0 for the MPU L3 master is mapped to the Boot ROM or On-chip RAM. This field only has an effect on the MPU L3 master."]
    #[inline(always)]
    #[must_use]
    pub fn mpuzero(&mut self) -> MpuzeroW<RemapSpec> {
        MpuzeroW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether address 0x0 for the non-MPU L3 masters is mapped to the SDRAM or On-chip RAM. This field only has an effect on the non-MPU L3 masters. The non-MPU L3 masters are the DMA controllers (standalone and those built-in to peripherals), the FPGA2HPS AXI Bridge, and the DAP."]
    #[inline(always)]
    #[must_use]
    pub fn nonmpuzero(&mut self) -> NonmpuzeroW<RemapSpec> {
        NonmpuzeroW::new(self, 1)
    }
    #[doc = "Bit 3 - Controls whether the HPS2FPGA AXI Bridge is visible to L3 masters or not."]
    #[inline(always)]
    #[must_use]
    pub fn hps2fpga(&mut self) -> Hps2fpgaW<RemapSpec> {
        Hps2fpgaW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls whether the Lightweight HPS2FPGA AXI Bridge is visible to L3 masters or not."]
    #[inline(always)]
    #[must_use]
    pub fn lwhps2fpga(&mut self) -> Lwhps2fpgaW<RemapSpec> {
        Lwhps2fpgaW::new(self, 4)
    }
}
#[doc = "The L3 interconnect has separate address maps for the various L3 Masters. Generally, the addresses are the same for most masters. However, the sparse interconnect of the L3 switch causes some masters to have holes in their memory maps. The remap bits are not mutually exclusive. Each bit can be set independently and in combinations. Priority for the bits is determined by the bit offset: lower offset bits take precedence over higher offset bits.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`remap::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RemapSpec;
impl crate::RegisterSpec for RemapSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`write(|w| ..)` method takes [`remap::W`](W) writer structure"]
impl crate::Writable for RemapSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets remap to value 0"]
impl crate::Resettable for RemapSpec {
    const RESET_VALUE: u32 = 0;
}
