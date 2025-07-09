// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `data` reader"]
pub type R = crate::R<DataSpec>;
#[doc = "Register `data` writer"]
pub type W = crate::W<DataSpec>;
#[doc = "Field `value` reader - Accepts configuration image to be sent to CB when the HPS configures the FPGA. Software normally just writes this register. If software reads this register, it returns the value 0 and replies with an AXI SLVERR error."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Accepts configuration image to be sent to CB when the HPS configures the FPGA. Software normally just writes this register. If software reads this register, it returns the value 0 and replies with an AXI SLVERR error."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Accepts configuration image to be sent to CB when the HPS configures the FPGA. Software normally just writes this register. If software reads this register, it returns the value 0 and replies with an AXI SLVERR error."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Accepts configuration image to be sent to CB when the HPS configures the FPGA. Software normally just writes this register. If software reads this register, it returns the value 0 and replies with an AXI SLVERR error."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DataSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Used to send configuration image to FPGA. The DATA register accepts 4 bytes of the configuration image on each write. The configuration image byte-stream is converted into a 4-byte word with little-endian ordering. If the configuration image is not an integer multiple of 4 bytes, software should pad the configuration image with extra zero bytes to make it an integer multiple of 4 bytes. The FPGA Manager converts the DATA to 16 bits wide when writing CB.DATA for partial reconfiguration. The FPGA Manager waits to transmit the data to the CB until the FPGA is able to receive it. For a full configuration, the FPGA Manager waits until the FPGA exits the Reset Phase and enters the Configuration Phase. For a partial reconfiguration, the FPGA Manager waits until the CB.PR_READY signal indicates that the FPGA is ready.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`data::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`data::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DataSpec;
impl crate::RegisterSpec for DataSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`data::R`](R) reader structure"]
impl crate::Readable for DataSpec {}
#[doc = "`write(|w| ..)` method takes [`data::W`](W) writer structure"]
impl crate::Writable for DataSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
