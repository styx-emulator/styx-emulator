// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_features` reader"]
pub type R = crate::R<ParamFeaturesSpec>;
#[doc = "Register `param_features` writer"]
pub type W = crate::W<ParamFeaturesSpec>;
#[doc = "Field `n_banks` reader - Maximum number of banks supported by hardware. This is an encoded value. \\[list\\]\\[*\\]0 - Two banks \\[*\\]1 - Four banks \\[*\\]2 - Eight banks \\[*\\]3 - Sixteen banks\\[/list\\]"]
pub type NBanksR = crate::FieldReader;
#[doc = "Field `n_banks` writer - Maximum number of banks supported by hardware. This is an encoded value. \\[list\\]\\[*\\]0 - Two banks \\[*\\]1 - Four banks \\[*\\]2 - Eight banks \\[*\\]3 - Sixteen banks\\[/list\\]"]
pub type NBanksW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `dma` reader - if set, DATA-DMA is present in hardware."]
pub type DmaR = crate::BitReader;
#[doc = "Field `dma` writer - if set, DATA-DMA is present in hardware."]
pub type DmaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cmd_dma` reader - Not implemented."]
pub type CmdDmaR = crate::BitReader;
#[doc = "Field `cmd_dma` writer - Not implemented."]
pub type CmdDmaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `partition` reader - if set, Partition logic is present in hardware."]
pub type PartitionR = crate::BitReader;
#[doc = "Field `partition` writer - if set, Partition logic is present in hardware."]
pub type PartitionW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `xdma_sideband` reader - if set, Side band DMA signals are present in hardware."]
pub type XdmaSidebandR = crate::BitReader;
#[doc = "Field `xdma_sideband` writer - if set, Side band DMA signals are present in hardware."]
pub type XdmaSidebandW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gpreg` reader - if set, General purpose registers are is present in hardware."]
pub type GpregR = crate::BitReader;
#[doc = "Field `gpreg` writer - if set, General purpose registers are is present in hardware."]
pub type GpregW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `index_addr` reader - if set, hardware support only Indexed addressing."]
pub type IndexAddrR = crate::BitReader;
#[doc = "Field `index_addr` writer - if set, hardware support only Indexed addressing."]
pub type IndexAddrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dfi_intf` reader - if set, hardware supports ONFI2.x synchronous interface."]
pub type DfiIntfR = crate::BitReader;
#[doc = "Field `dfi_intf` writer - if set, hardware supports ONFI2.x synchronous interface."]
pub type DfiIntfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `lba` reader - if set, hardware supports Toshiba LBA devices."]
pub type LbaR = crate::BitReader;
#[doc = "Field `lba` writer - if set, hardware supports Toshiba LBA devices."]
pub type LbaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - Maximum number of banks supported by hardware. This is an encoded value. \\[list\\]\\[*\\]0 - Two banks \\[*\\]1 - Four banks \\[*\\]2 - Eight banks \\[*\\]3 - Sixteen banks\\[/list\\]"]
    #[inline(always)]
    pub fn n_banks(&self) -> NBanksR {
        NBanksR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 6 - if set, DATA-DMA is present in hardware."]
    #[inline(always)]
    pub fn dma(&self) -> DmaR {
        DmaR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Not implemented."]
    #[inline(always)]
    pub fn cmd_dma(&self) -> CmdDmaR {
        CmdDmaR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - if set, Partition logic is present in hardware."]
    #[inline(always)]
    pub fn partition(&self) -> PartitionR {
        PartitionR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - if set, Side band DMA signals are present in hardware."]
    #[inline(always)]
    pub fn xdma_sideband(&self) -> XdmaSidebandR {
        XdmaSidebandR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - if set, General purpose registers are is present in hardware."]
    #[inline(always)]
    pub fn gpreg(&self) -> GpregR {
        GpregR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - if set, hardware support only Indexed addressing."]
    #[inline(always)]
    pub fn index_addr(&self) -> IndexAddrR {
        IndexAddrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - if set, hardware supports ONFI2.x synchronous interface."]
    #[inline(always)]
    pub fn dfi_intf(&self) -> DfiIntfR {
        DfiIntfR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - if set, hardware supports Toshiba LBA devices."]
    #[inline(always)]
    pub fn lba(&self) -> LbaR {
        LbaR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - Maximum number of banks supported by hardware. This is an encoded value. \\[list\\]\\[*\\]0 - Two banks \\[*\\]1 - Four banks \\[*\\]2 - Eight banks \\[*\\]3 - Sixteen banks\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn n_banks(&mut self) -> NBanksW<ParamFeaturesSpec> {
        NBanksW::new(self, 0)
    }
    #[doc = "Bit 6 - if set, DATA-DMA is present in hardware."]
    #[inline(always)]
    #[must_use]
    pub fn dma(&mut self) -> DmaW<ParamFeaturesSpec> {
        DmaW::new(self, 6)
    }
    #[doc = "Bit 7 - Not implemented."]
    #[inline(always)]
    #[must_use]
    pub fn cmd_dma(&mut self) -> CmdDmaW<ParamFeaturesSpec> {
        CmdDmaW::new(self, 7)
    }
    #[doc = "Bit 8 - if set, Partition logic is present in hardware."]
    #[inline(always)]
    #[must_use]
    pub fn partition(&mut self) -> PartitionW<ParamFeaturesSpec> {
        PartitionW::new(self, 8)
    }
    #[doc = "Bit 9 - if set, Side band DMA signals are present in hardware."]
    #[inline(always)]
    #[must_use]
    pub fn xdma_sideband(&mut self) -> XdmaSidebandW<ParamFeaturesSpec> {
        XdmaSidebandW::new(self, 9)
    }
    #[doc = "Bit 10 - if set, General purpose registers are is present in hardware."]
    #[inline(always)]
    #[must_use]
    pub fn gpreg(&mut self) -> GpregW<ParamFeaturesSpec> {
        GpregW::new(self, 10)
    }
    #[doc = "Bit 11 - if set, hardware support only Indexed addressing."]
    #[inline(always)]
    #[must_use]
    pub fn index_addr(&mut self) -> IndexAddrW<ParamFeaturesSpec> {
        IndexAddrW::new(self, 11)
    }
    #[doc = "Bit 12 - if set, hardware supports ONFI2.x synchronous interface."]
    #[inline(always)]
    #[must_use]
    pub fn dfi_intf(&mut self) -> DfiIntfW<ParamFeaturesSpec> {
        DfiIntfW::new(self, 12)
    }
    #[doc = "Bit 13 - if set, hardware supports Toshiba LBA devices."]
    #[inline(always)]
    #[must_use]
    pub fn lba(&mut self) -> LbaW<ParamFeaturesSpec> {
        LbaW::new(self, 13)
    }
}
#[doc = "Shows Available hardware features or attributes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_features::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamFeaturesSpec;
impl crate::RegisterSpec for ParamFeaturesSpec {
    type Ux = u32;
    const OFFSET: u64 = 1008u64;
}
#[doc = "`read()` method returns [`param_features::R`](R) reader structure"]
impl crate::Readable for ParamFeaturesSpec {}
#[doc = "`reset()` method sets param_features to value 0x0841"]
impl crate::Resettable for ParamFeaturesSpec {
    const RESET_VALUE: u32 = 0x0841;
}
