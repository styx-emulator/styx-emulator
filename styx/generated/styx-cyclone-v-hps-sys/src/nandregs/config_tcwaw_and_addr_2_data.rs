// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_tcwaw_and_addr_2_data` reader"]
pub type R = crate::R<ConfigTcwawAndAddr2DataSpec>;
#[doc = "Register `config_tcwaw_and_addr_2_data` writer"]
pub type W = crate::W<ConfigTcwawAndAddr2DataSpec>;
#[doc = "Field `addr_2_data` reader - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between address latch enable going low to write enable going low. The number of clocks is the function of device parameter Tadl and controller clock frequency."]
pub type Addr2DataR = crate::FieldReader;
#[doc = "Field `addr_2_data` writer - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between address latch enable going low to write enable going low. The number of clocks is the function of device parameter Tadl and controller clock frequency."]
pub type Addr2DataW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `tcwaw` reader - Signifies the number of controller clocks that should be introduced between the command cycle of a random data input command to the address cycle of the random data input command."]
pub type TcwawR = crate::FieldReader;
#[doc = "Field `tcwaw` writer - Signifies the number of controller clocks that should be introduced between the command cycle of a random data input command to the address cycle of the random data input command."]
pub type TcwawW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between address latch enable going low to write enable going low. The number of clocks is the function of device parameter Tadl and controller clock frequency."]
    #[inline(always)]
    pub fn addr_2_data(&self) -> Addr2DataR {
        Addr2DataR::new((self.bits & 0x3f) as u8)
    }
    #[doc = "Bits 8:13 - Signifies the number of controller clocks that should be introduced between the command cycle of a random data input command to the address cycle of the random data input command."]
    #[inline(always)]
    pub fn tcwaw(&self) -> TcwawR {
        TcwawR::new(((self.bits >> 8) & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between address latch enable going low to write enable going low. The number of clocks is the function of device parameter Tadl and controller clock frequency."]
    #[inline(always)]
    #[must_use]
    pub fn addr_2_data(&mut self) -> Addr2DataW<ConfigTcwawAndAddr2DataSpec> {
        Addr2DataW::new(self, 0)
    }
    #[doc = "Bits 8:13 - Signifies the number of controller clocks that should be introduced between the command cycle of a random data input command to the address cycle of the random data input command."]
    #[inline(always)]
    #[must_use]
    pub fn tcwaw(&mut self) -> TcwawW<ConfigTcwawAndAddr2DataSpec> {
        TcwawW::new(self, 8)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_tcwaw_and_addr_2_data::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_tcwaw_and_addr_2_data::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigTcwawAndAddr2DataSpec;
impl crate::RegisterSpec for ConfigTcwawAndAddr2DataSpec {
    type Ux = u32;
    const OFFSET: u64 = 272u64;
}
#[doc = "`read()` method returns [`config_tcwaw_and_addr_2_data::R`](R) reader structure"]
impl crate::Readable for ConfigTcwawAndAddr2DataSpec {}
#[doc = "`write(|w| ..)` method takes [`config_tcwaw_and_addr_2_data::W`](W) writer structure"]
impl crate::Writable for ConfigTcwawAndAddr2DataSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_tcwaw_and_addr_2_data to value 0x1432"]
impl crate::Resettable for ConfigTcwawAndAddr2DataSpec {
    const RESET_VALUE: u32 = 0x1432;
}
