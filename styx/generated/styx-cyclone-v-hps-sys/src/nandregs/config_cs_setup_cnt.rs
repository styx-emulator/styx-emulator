// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_cs_setup_cnt` reader"]
pub type R = crate::R<ConfigCsSetupCntSpec>;
#[doc = "Register `config_cs_setup_cnt` writer"]
pub type W = crate::W<ConfigCsSetupCntSpec>;
#[doc = "Field `value` reader - Number of nand_mp_clk cycles required for meeting chip select setup time. This register refers to device timing parameter Tcs. The value in this registers reflects the extra setup cycles for chip select before read/write enable signal is set low. The default value is calculated for ONFI Timing mode 0 Tcs = 70ns and maximum nand_mp_clk period of 4ns for 1x/4x clock multiple for 16ns cycle time device. Please refer to Figure 3.3 for the relationship between the cs_setup_cnt and rdwr_en_lo_cnt values."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Number of nand_mp_clk cycles required for meeting chip select setup time. This register refers to device timing parameter Tcs. The value in this registers reflects the extra setup cycles for chip select before read/write enable signal is set low. The default value is calculated for ONFI Timing mode 0 Tcs = 70ns and maximum nand_mp_clk period of 4ns for 1x/4x clock multiple for 16ns cycle time device. Please refer to Figure 3.3 for the relationship between the cs_setup_cnt and rdwr_en_lo_cnt values."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - Number of nand_mp_clk cycles required for meeting chip select setup time. This register refers to device timing parameter Tcs. The value in this registers reflects the extra setup cycles for chip select before read/write enable signal is set low. The default value is calculated for ONFI Timing mode 0 Tcs = 70ns and maximum nand_mp_clk period of 4ns for 1x/4x clock multiple for 16ns cycle time device. Please refer to Figure 3.3 for the relationship between the cs_setup_cnt and rdwr_en_lo_cnt values."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - Number of nand_mp_clk cycles required for meeting chip select setup time. This register refers to device timing parameter Tcs. The value in this registers reflects the extra setup cycles for chip select before read/write enable signal is set low. The default value is calculated for ONFI Timing mode 0 Tcs = 70ns and maximum nand_mp_clk period of 4ns for 1x/4x clock multiple for 16ns cycle time device. Please refer to Figure 3.3 for the relationship between the cs_setup_cnt and rdwr_en_lo_cnt values."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigCsSetupCntSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Chip select setup time\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_cs_setup_cnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_cs_setup_cnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigCsSetupCntSpec;
impl crate::RegisterSpec for ConfigCsSetupCntSpec {
    type Ux = u32;
    const OFFSET: u64 = 544u64;
}
#[doc = "`read()` method returns [`config_cs_setup_cnt::R`](R) reader structure"]
impl crate::Readable for ConfigCsSetupCntSpec {}
#[doc = "`write(|w| ..)` method takes [`config_cs_setup_cnt::W`](W) writer structure"]
impl crate::Writable for ConfigCsSetupCntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_cs_setup_cnt to value 0x03"]
impl crate::Resettable for ConfigCsSetupCntSpec {
    const RESET_VALUE: u32 = 0x03;
}
