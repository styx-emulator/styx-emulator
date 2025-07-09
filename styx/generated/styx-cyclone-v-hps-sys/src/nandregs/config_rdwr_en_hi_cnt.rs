// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_rdwr_en_hi_cnt` reader"]
pub type R = crate::R<ConfigRdwrEnHiCntSpec>;
#[doc = "Register `config_rdwr_en_hi_cnt` writer"]
pub type W = crate::W<ConfigRdwrEnHiCntSpec>;
#[doc = "Field `value` reader - Number of nand_mp_clk cycles that read or write enable will kept high to meet the min Treh/Tweh parameter of the device. The value in this register plus rdwr_en_lo_cnt register value should meet the min cycle time of the device connected. The default value is calculated assuming the max nand_mp_clk time period of 4ns to work with ONFI Mode 0 mode of 100ns device cycle time. This assumes a 1x/4x clocking scheme."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Number of nand_mp_clk cycles that read or write enable will kept high to meet the min Treh/Tweh parameter of the device. The value in this register plus rdwr_en_lo_cnt register value should meet the min cycle time of the device connected. The default value is calculated assuming the max nand_mp_clk time period of 4ns to work with ONFI Mode 0 mode of 100ns device cycle time. This assumes a 1x/4x clocking scheme."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - Number of nand_mp_clk cycles that read or write enable will kept high to meet the min Treh/Tweh parameter of the device. The value in this register plus rdwr_en_lo_cnt register value should meet the min cycle time of the device connected. The default value is calculated assuming the max nand_mp_clk time period of 4ns to work with ONFI Mode 0 mode of 100ns device cycle time. This assumes a 1x/4x clocking scheme."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - Number of nand_mp_clk cycles that read or write enable will kept high to meet the min Treh/Tweh parameter of the device. The value in this register plus rdwr_en_lo_cnt register value should meet the min cycle time of the device connected. The default value is calculated assuming the max nand_mp_clk time period of 4ns to work with ONFI Mode 0 mode of 100ns device cycle time. This assumes a 1x/4x clocking scheme."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigRdwrEnHiCntSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Read/Write Enable high pulse width\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_rdwr_en_hi_cnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_rdwr_en_hi_cnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigRdwrEnHiCntSpec;
impl crate::RegisterSpec for ConfigRdwrEnHiCntSpec {
    type Ux = u32;
    const OFFSET: u64 = 512u64;
}
#[doc = "`read()` method returns [`config_rdwr_en_hi_cnt::R`](R) reader structure"]
impl crate::Readable for ConfigRdwrEnHiCntSpec {}
#[doc = "`write(|w| ..)` method takes [`config_rdwr_en_hi_cnt::W`](W) writer structure"]
impl crate::Writable for ConfigRdwrEnHiCntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_rdwr_en_hi_cnt to value 0x0c"]
impl crate::Resettable for ConfigRdwrEnHiCntSpec {
    const RESET_VALUE: u32 = 0x0c;
}
