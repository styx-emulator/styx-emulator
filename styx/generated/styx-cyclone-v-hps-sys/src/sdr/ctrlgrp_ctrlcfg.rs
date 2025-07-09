// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_ctrlcfg` reader"]
pub type R = crate::R<CtrlgrpCtrlcfgSpec>;
#[doc = "Register `ctrlgrp_ctrlcfg` writer"]
pub type W = crate::W<CtrlgrpCtrlcfgSpec>;
#[doc = "Field `memtype` reader - Selects memory type. Program this field with one of the following binary values, &amp;quot;001&amp;quot; for DDR2 SDRAM, &amp;quot;010&amp;quot; for DDR3 SDRAM, &amp;quot;011&amp;quot; for LPDDR1 SDRAM or &amp;quot;100&amp;quot; for LPDDR2 SDRAM."]
pub type MemtypeR = crate::FieldReader;
#[doc = "Field `memtype` writer - Selects memory type. Program this field with one of the following binary values, &amp;quot;001&amp;quot; for DDR2 SDRAM, &amp;quot;010&amp;quot; for DDR3 SDRAM, &amp;quot;011&amp;quot; for LPDDR1 SDRAM or &amp;quot;100&amp;quot; for LPDDR2 SDRAM."]
pub type MemtypeW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `membl` reader - Configures burst length as a static decimal value. Legal values are valid for JEDEC allowed DRAM values for the DRAM selected in cfg_type. For DDR3, this should be programmed with 8 (binary &amp;quot;01000&amp;quot;), for DDR2 it can be either 4 or 8 depending on the exact DRAM chip. LPDDR2 can be programmed with 4, 8, or 16 and LPDDR can be programmed with 2, 4, or 8. You must also program the membl field in the staticcfg register."]
pub type MemblR = crate::FieldReader;
#[doc = "Field `membl` writer - Configures burst length as a static decimal value. Legal values are valid for JEDEC allowed DRAM values for the DRAM selected in cfg_type. For DDR3, this should be programmed with 8 (binary &amp;quot;01000&amp;quot;), for DDR2 it can be either 4 or 8 depending on the exact DRAM chip. LPDDR2 can be programmed with 4, 8, or 16 and LPDDR can be programmed with 2, 4, or 8. You must also program the membl field in the staticcfg register."]
pub type MemblW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `addrorder` reader - Selects the order for address interleaving. Programming this field with different values gives different mappings between the AXI or Avalon-MM address and the SDRAM address. Program this field with the following binary values to select the ordering. &amp;quot;00&amp;quot; - chip, row, bank, column, &amp;quot;01&amp;quot; - chip, bank, row, column, &amp;quot;10&amp;quot;-row, chip, bank, column"]
pub type AddrorderR = crate::FieldReader;
#[doc = "Field `addrorder` writer - Selects the order for address interleaving. Programming this field with different values gives different mappings between the AXI or Avalon-MM address and the SDRAM address. Program this field with the following binary values to select the ordering. &amp;quot;00&amp;quot; - chip, row, bank, column, &amp;quot;01&amp;quot; - chip, bank, row, column, &amp;quot;10&amp;quot;-row, chip, bank, column"]
pub type AddrorderW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `eccen` reader - Enable the generation and checking of ECC. This bit must only be set if the memory connected to the SDRAM interface is 24 or 40 bits wide. If you set this, you must clear the useeccasdata field in the staticcfg register."]
pub type EccenR = crate::BitReader;
#[doc = "Field `eccen` writer - Enable the generation and checking of ECC. This bit must only be set if the memory connected to the SDRAM interface is 24 or 40 bits wide. If you set this, you must clear the useeccasdata field in the staticcfg register."]
pub type EccenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ecccorren` reader - Enable auto correction of the read data returned when single bit error is detected."]
pub type EcccorrenR = crate::BitReader;
#[doc = "Field `ecccorren` writer - Enable auto correction of the read data returned when single bit error is detected."]
pub type EcccorrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cfg_enable_ecc_code_overwrites` reader - Set to a one to enable ECC overwrites. ECC overwrites occur when a correctable ECC error is seen and cause a new read/modify/write to be scheduled for that location to clear the ECC error."]
pub type CfgEnableEccCodeOverwritesR = crate::BitReader;
#[doc = "Field `cfg_enable_ecc_code_overwrites` writer - Set to a one to enable ECC overwrites. ECC overwrites occur when a correctable ECC error is seen and cause a new read/modify/write to be scheduled for that location to clear the ECC error."]
pub type CfgEnableEccCodeOverwritesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gensbe` reader - Enable the deliberate insertion of single bit errors in data written to memory. This should only be used for testing purposes."]
pub type GensbeR = crate::BitReader;
#[doc = "Field `gensbe` writer - Enable the deliberate insertion of single bit errors in data written to memory. This should only be used for testing purposes."]
pub type GensbeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gendbe` reader - Enable the deliberate insertion of double bit errors in data written to memory. This should only be used for testing purposes."]
pub type GendbeR = crate::BitReader;
#[doc = "Field `gendbe` writer - Enable the deliberate insertion of double bit errors in data written to memory. This should only be used for testing purposes."]
pub type GendbeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `reorderen` reader - This bit controls whether the controller can re-order operations to optimize SDRAM bandwidth. It should generally be set to a one."]
pub type ReorderenR = crate::BitReader;
#[doc = "Field `reorderen` writer - This bit controls whether the controller can re-order operations to optimize SDRAM bandwidth. It should generally be set to a one."]
pub type ReorderenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `starvelimit` reader - Specifies the number of DRAM burst transactions an individual transaction will allow to reorder ahead of it before its priority is raised in the memory controller."]
pub type StarvelimitR = crate::FieldReader;
#[doc = "Field `starvelimit` writer - Specifies the number of DRAM burst transactions an individual transaction will allow to reorder ahead of it before its priority is raised in the memory controller."]
pub type StarvelimitW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `dqstrken` reader - Enables DQS tracking in the PHY."]
pub type DqstrkenR = crate::BitReader;
#[doc = "Field `dqstrken` writer - Enables DQS tracking in the PHY."]
pub type DqstrkenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nodmpins` reader - Set to a one to enable DRAM operation if no DM pins are connected."]
pub type NodmpinsR = crate::BitReader;
#[doc = "Field `nodmpins` writer - Set to a one to enable DRAM operation if no DM pins are connected."]
pub type NodmpinsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `burstintren` reader - Set to a one to enable the controller to issue burst interrupt commands. This must only be set when the DRAM memory type is LPDDR2."]
pub type BurstintrenR = crate::BitReader;
#[doc = "Field `burstintren` writer - Set to a one to enable the controller to issue burst interrupt commands. This must only be set when the DRAM memory type is LPDDR2."]
pub type BurstintrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bursttermen` reader - Set to a one to enable the controller to issue burst terminate commands. This must only be set when the DRAM memory type is LPDDR2."]
pub type BursttermenR = crate::BitReader;
#[doc = "Field `bursttermen` writer - Set to a one to enable the controller to issue burst terminate commands. This must only be set when the DRAM memory type is LPDDR2."]
pub type BursttermenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - Selects memory type. Program this field with one of the following binary values, &amp;quot;001&amp;quot; for DDR2 SDRAM, &amp;quot;010&amp;quot; for DDR3 SDRAM, &amp;quot;011&amp;quot; for LPDDR1 SDRAM or &amp;quot;100&amp;quot; for LPDDR2 SDRAM."]
    #[inline(always)]
    pub fn memtype(&self) -> MemtypeR {
        MemtypeR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:7 - Configures burst length as a static decimal value. Legal values are valid for JEDEC allowed DRAM values for the DRAM selected in cfg_type. For DDR3, this should be programmed with 8 (binary &amp;quot;01000&amp;quot;), for DDR2 it can be either 4 or 8 depending on the exact DRAM chip. LPDDR2 can be programmed with 4, 8, or 16 and LPDDR can be programmed with 2, 4, or 8. You must also program the membl field in the staticcfg register."]
    #[inline(always)]
    pub fn membl(&self) -> MemblR {
        MemblR::new(((self.bits >> 3) & 0x1f) as u8)
    }
    #[doc = "Bits 8:9 - Selects the order for address interleaving. Programming this field with different values gives different mappings between the AXI or Avalon-MM address and the SDRAM address. Program this field with the following binary values to select the ordering. &amp;quot;00&amp;quot; - chip, row, bank, column, &amp;quot;01&amp;quot; - chip, bank, row, column, &amp;quot;10&amp;quot;-row, chip, bank, column"]
    #[inline(always)]
    pub fn addrorder(&self) -> AddrorderR {
        AddrorderR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bit 10 - Enable the generation and checking of ECC. This bit must only be set if the memory connected to the SDRAM interface is 24 or 40 bits wide. If you set this, you must clear the useeccasdata field in the staticcfg register."]
    #[inline(always)]
    pub fn eccen(&self) -> EccenR {
        EccenR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Enable auto correction of the read data returned when single bit error is detected."]
    #[inline(always)]
    pub fn ecccorren(&self) -> EcccorrenR {
        EcccorrenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Set to a one to enable ECC overwrites. ECC overwrites occur when a correctable ECC error is seen and cause a new read/modify/write to be scheduled for that location to clear the ECC error."]
    #[inline(always)]
    pub fn cfg_enable_ecc_code_overwrites(&self) -> CfgEnableEccCodeOverwritesR {
        CfgEnableEccCodeOverwritesR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Enable the deliberate insertion of single bit errors in data written to memory. This should only be used for testing purposes."]
    #[inline(always)]
    pub fn gensbe(&self) -> GensbeR {
        GensbeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Enable the deliberate insertion of double bit errors in data written to memory. This should only be used for testing purposes."]
    #[inline(always)]
    pub fn gendbe(&self) -> GendbeR {
        GendbeR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - This bit controls whether the controller can re-order operations to optimize SDRAM bandwidth. It should generally be set to a one."]
    #[inline(always)]
    pub fn reorderen(&self) -> ReorderenR {
        ReorderenR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:21 - Specifies the number of DRAM burst transactions an individual transaction will allow to reorder ahead of it before its priority is raised in the memory controller."]
    #[inline(always)]
    pub fn starvelimit(&self) -> StarvelimitR {
        StarvelimitR::new(((self.bits >> 16) & 0x3f) as u8)
    }
    #[doc = "Bit 22 - Enables DQS tracking in the PHY."]
    #[inline(always)]
    pub fn dqstrken(&self) -> DqstrkenR {
        DqstrkenR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Set to a one to enable DRAM operation if no DM pins are connected."]
    #[inline(always)]
    pub fn nodmpins(&self) -> NodmpinsR {
        NodmpinsR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Set to a one to enable the controller to issue burst interrupt commands. This must only be set when the DRAM memory type is LPDDR2."]
    #[inline(always)]
    pub fn burstintren(&self) -> BurstintrenR {
        BurstintrenR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Set to a one to enable the controller to issue burst terminate commands. This must only be set when the DRAM memory type is LPDDR2."]
    #[inline(always)]
    pub fn bursttermen(&self) -> BursttermenR {
        BursttermenR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - Selects memory type. Program this field with one of the following binary values, &amp;quot;001&amp;quot; for DDR2 SDRAM, &amp;quot;010&amp;quot; for DDR3 SDRAM, &amp;quot;011&amp;quot; for LPDDR1 SDRAM or &amp;quot;100&amp;quot; for LPDDR2 SDRAM."]
    #[inline(always)]
    #[must_use]
    pub fn memtype(&mut self) -> MemtypeW<CtrlgrpCtrlcfgSpec> {
        MemtypeW::new(self, 0)
    }
    #[doc = "Bits 3:7 - Configures burst length as a static decimal value. Legal values are valid for JEDEC allowed DRAM values for the DRAM selected in cfg_type. For DDR3, this should be programmed with 8 (binary &amp;quot;01000&amp;quot;), for DDR2 it can be either 4 or 8 depending on the exact DRAM chip. LPDDR2 can be programmed with 4, 8, or 16 and LPDDR can be programmed with 2, 4, or 8. You must also program the membl field in the staticcfg register."]
    #[inline(always)]
    #[must_use]
    pub fn membl(&mut self) -> MemblW<CtrlgrpCtrlcfgSpec> {
        MemblW::new(self, 3)
    }
    #[doc = "Bits 8:9 - Selects the order for address interleaving. Programming this field with different values gives different mappings between the AXI or Avalon-MM address and the SDRAM address. Program this field with the following binary values to select the ordering. &amp;quot;00&amp;quot; - chip, row, bank, column, &amp;quot;01&amp;quot; - chip, bank, row, column, &amp;quot;10&amp;quot;-row, chip, bank, column"]
    #[inline(always)]
    #[must_use]
    pub fn addrorder(&mut self) -> AddrorderW<CtrlgrpCtrlcfgSpec> {
        AddrorderW::new(self, 8)
    }
    #[doc = "Bit 10 - Enable the generation and checking of ECC. This bit must only be set if the memory connected to the SDRAM interface is 24 or 40 bits wide. If you set this, you must clear the useeccasdata field in the staticcfg register."]
    #[inline(always)]
    #[must_use]
    pub fn eccen(&mut self) -> EccenW<CtrlgrpCtrlcfgSpec> {
        EccenW::new(self, 10)
    }
    #[doc = "Bit 11 - Enable auto correction of the read data returned when single bit error is detected."]
    #[inline(always)]
    #[must_use]
    pub fn ecccorren(&mut self) -> EcccorrenW<CtrlgrpCtrlcfgSpec> {
        EcccorrenW::new(self, 11)
    }
    #[doc = "Bit 12 - Set to a one to enable ECC overwrites. ECC overwrites occur when a correctable ECC error is seen and cause a new read/modify/write to be scheduled for that location to clear the ECC error."]
    #[inline(always)]
    #[must_use]
    pub fn cfg_enable_ecc_code_overwrites(
        &mut self,
    ) -> CfgEnableEccCodeOverwritesW<CtrlgrpCtrlcfgSpec> {
        CfgEnableEccCodeOverwritesW::new(self, 12)
    }
    #[doc = "Bit 13 - Enable the deliberate insertion of single bit errors in data written to memory. This should only be used for testing purposes."]
    #[inline(always)]
    #[must_use]
    pub fn gensbe(&mut self) -> GensbeW<CtrlgrpCtrlcfgSpec> {
        GensbeW::new(self, 13)
    }
    #[doc = "Bit 14 - Enable the deliberate insertion of double bit errors in data written to memory. This should only be used for testing purposes."]
    #[inline(always)]
    #[must_use]
    pub fn gendbe(&mut self) -> GendbeW<CtrlgrpCtrlcfgSpec> {
        GendbeW::new(self, 14)
    }
    #[doc = "Bit 15 - This bit controls whether the controller can re-order operations to optimize SDRAM bandwidth. It should generally be set to a one."]
    #[inline(always)]
    #[must_use]
    pub fn reorderen(&mut self) -> ReorderenW<CtrlgrpCtrlcfgSpec> {
        ReorderenW::new(self, 15)
    }
    #[doc = "Bits 16:21 - Specifies the number of DRAM burst transactions an individual transaction will allow to reorder ahead of it before its priority is raised in the memory controller."]
    #[inline(always)]
    #[must_use]
    pub fn starvelimit(&mut self) -> StarvelimitW<CtrlgrpCtrlcfgSpec> {
        StarvelimitW::new(self, 16)
    }
    #[doc = "Bit 22 - Enables DQS tracking in the PHY."]
    #[inline(always)]
    #[must_use]
    pub fn dqstrken(&mut self) -> DqstrkenW<CtrlgrpCtrlcfgSpec> {
        DqstrkenW::new(self, 22)
    }
    #[doc = "Bit 23 - Set to a one to enable DRAM operation if no DM pins are connected."]
    #[inline(always)]
    #[must_use]
    pub fn nodmpins(&mut self) -> NodmpinsW<CtrlgrpCtrlcfgSpec> {
        NodmpinsW::new(self, 23)
    }
    #[doc = "Bit 24 - Set to a one to enable the controller to issue burst interrupt commands. This must only be set when the DRAM memory type is LPDDR2."]
    #[inline(always)]
    #[must_use]
    pub fn burstintren(&mut self) -> BurstintrenW<CtrlgrpCtrlcfgSpec> {
        BurstintrenW::new(self, 24)
    }
    #[doc = "Bit 25 - Set to a one to enable the controller to issue burst terminate commands. This must only be set when the DRAM memory type is LPDDR2."]
    #[inline(always)]
    #[must_use]
    pub fn bursttermen(&mut self) -> BursttermenW<CtrlgrpCtrlcfgSpec> {
        BursttermenW::new(self, 25)
    }
}
#[doc = "The Controller Configuration Register determines the behavior of the controller.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_ctrlcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_ctrlcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpCtrlcfgSpec;
impl crate::RegisterSpec for CtrlgrpCtrlcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 20480u64;
}
#[doc = "`read()` method returns [`ctrlgrp_ctrlcfg::R`](R) reader structure"]
impl crate::Readable for CtrlgrpCtrlcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_ctrlcfg::W`](W) writer structure"]
impl crate::Writable for CtrlgrpCtrlcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_ctrlcfg to value 0"]
impl crate::Resettable for CtrlgrpCtrlcfgSpec {
    const RESET_VALUE: u32 = 0;
}
