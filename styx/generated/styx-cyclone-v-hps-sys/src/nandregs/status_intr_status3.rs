// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `status_intr_status3` reader"]
pub type R = crate::R<StatusIntrStatus3Spec>;
#[doc = "Register `status_intr_status3` writer"]
pub type W = crate::W<StatusIntrStatus3Spec>;
#[doc = "Field `ecc_uncor_err` reader - Ecc logic detected uncorrectable error while reading data from flash device."]
pub type EccUncorErrR = crate::BitReader;
#[doc = "Field `ecc_uncor_err` writer - Ecc logic detected uncorrectable error while reading data from flash device."]
pub type EccUncorErrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `dma_cmd_comp` reader - Not implemented."]
pub type DmaCmdCompR = crate::BitReader;
#[doc = "Field `dma_cmd_comp` writer - Not implemented."]
pub type DmaCmdCompW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `time_out` reader - Watchdog timer has triggered in the controller due to one of the reasons like device not responding or controller state machine did not get back to idle"]
pub type TimeOutR = crate::BitReader;
#[doc = "Field `time_out` writer - Watchdog timer has triggered in the controller due to one of the reasons like device not responding or controller state machine did not get back to idle"]
pub type TimeOutW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `program_fail` reader - Program failure occurred in the device on issuance of a program command. err_block_addr and err_page_addr contain the block address and page address that failed program operation."]
pub type ProgramFailR = crate::BitReader;
#[doc = "Field `program_fail` writer - Program failure occurred in the device on issuance of a program command. err_block_addr and err_page_addr contain the block address and page address that failed program operation."]
pub type ProgramFailW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `erase_fail` reader - Erase failure occurred in the device on issuance of a erase command. err_block_addr and err_page_addr contain the block address and page address that failed erase operation."]
pub type EraseFailR = crate::BitReader;
#[doc = "Field `erase_fail` writer - Erase failure occurred in the device on issuance of a erase command. err_block_addr and err_page_addr contain the block address and page address that failed erase operation."]
pub type EraseFailW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `load_comp` reader - Device finished the last issued load command."]
pub type LoadCompR = crate::BitReader;
#[doc = "Field `load_comp` writer - Device finished the last issued load command."]
pub type LoadCompW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `program_comp` reader - Device finished the last issued program command."]
pub type ProgramCompR = crate::BitReader;
#[doc = "Field `program_comp` writer - Device finished the last issued program command."]
pub type ProgramCompW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `erase_comp` reader - Device erase operation complete"]
pub type EraseCompR = crate::BitReader;
#[doc = "Field `erase_comp` writer - Device erase operation complete"]
pub type EraseCompW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `pipe_cpybck_cmd_comp` reader - A pipeline command or a copyback bank command has completed on this particular bank"]
pub type PipeCpybckCmdCompR = crate::BitReader;
#[doc = "Field `pipe_cpybck_cmd_comp` writer - A pipeline command or a copyback bank command has completed on this particular bank"]
pub type PipeCpybckCmdCompW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `locked_blk` reader - The address to program or erase operation is to a locked block and the operation failed due to this reason"]
pub type LockedBlkR = crate::BitReader;
#[doc = "Field `locked_blk` writer - The address to program or erase operation is to a locked block and the operation failed due to this reason"]
pub type LockedBlkW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `unsup_cmd` reader - An unsupported command was received. This interrupt is set when an invalid command is received, or when a command sequence is broken."]
pub type UnsupCmdR = crate::BitReader;
#[doc = "Field `unsup_cmd` writer - An unsupported command was received. This interrupt is set when an invalid command is received, or when a command sequence is broken."]
pub type UnsupCmdW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `INT_act` reader - R/B pin of device transitioned from low to high"]
pub type IntActR = crate::BitReader;
#[doc = "Field `INT_act` writer - R/B pin of device transitioned from low to high"]
pub type IntActW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `rst_comp` reader - The NAND Flash Memory Controller has completed its reset and initialization process"]
pub type RstCompR = crate::BitReader;
#[doc = "Field `rst_comp` writer - The NAND Flash Memory Controller has completed its reset and initialization process"]
pub type RstCompW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `pipe_cmd_err` reader - A pipeline command sequence has been violated. This occurs when Map 01 page read/write address does not match the corresponding expected address from the pipeline commands issued earlier."]
pub type PipeCmdErrR = crate::BitReader;
#[doc = "Field `pipe_cmd_err` writer - A pipeline command sequence has been violated. This occurs when Map 01 page read/write address does not match the corresponding expected address from the pipeline commands issued earlier."]
pub type PipeCmdErrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `page_xfer_inc` reader - For every page of data transfer to or from the device, this bit will be set."]
pub type PageXferIncR = crate::BitReader;
#[doc = "Field `page_xfer_inc` writer - For every page of data transfer to or from the device, this bit will be set."]
pub type PageXferIncW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - Ecc logic detected uncorrectable error while reading data from flash device."]
    #[inline(always)]
    pub fn ecc_uncor_err(&self) -> EccUncorErrR {
        EccUncorErrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - Not implemented."]
    #[inline(always)]
    pub fn dma_cmd_comp(&self) -> DmaCmdCompR {
        DmaCmdCompR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Watchdog timer has triggered in the controller due to one of the reasons like device not responding or controller state machine did not get back to idle"]
    #[inline(always)]
    pub fn time_out(&self) -> TimeOutR {
        TimeOutR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Program failure occurred in the device on issuance of a program command. err_block_addr and err_page_addr contain the block address and page address that failed program operation."]
    #[inline(always)]
    pub fn program_fail(&self) -> ProgramFailR {
        ProgramFailR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Erase failure occurred in the device on issuance of a erase command. err_block_addr and err_page_addr contain the block address and page address that failed erase operation."]
    #[inline(always)]
    pub fn erase_fail(&self) -> EraseFailR {
        EraseFailR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Device finished the last issued load command."]
    #[inline(always)]
    pub fn load_comp(&self) -> LoadCompR {
        LoadCompR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Device finished the last issued program command."]
    #[inline(always)]
    pub fn program_comp(&self) -> ProgramCompR {
        ProgramCompR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Device erase operation complete"]
    #[inline(always)]
    pub fn erase_comp(&self) -> EraseCompR {
        EraseCompR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - A pipeline command or a copyback bank command has completed on this particular bank"]
    #[inline(always)]
    pub fn pipe_cpybck_cmd_comp(&self) -> PipeCpybckCmdCompR {
        PipeCpybckCmdCompR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - The address to program or erase operation is to a locked block and the operation failed due to this reason"]
    #[inline(always)]
    pub fn locked_blk(&self) -> LockedBlkR {
        LockedBlkR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - An unsupported command was received. This interrupt is set when an invalid command is received, or when a command sequence is broken."]
    #[inline(always)]
    pub fn unsup_cmd(&self) -> UnsupCmdR {
        UnsupCmdR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - R/B pin of device transitioned from low to high"]
    #[inline(always)]
    pub fn int_act(&self) -> IntActR {
        IntActR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - The NAND Flash Memory Controller has completed its reset and initialization process"]
    #[inline(always)]
    pub fn rst_comp(&self) -> RstCompR {
        RstCompR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - A pipeline command sequence has been violated. This occurs when Map 01 page read/write address does not match the corresponding expected address from the pipeline commands issued earlier."]
    #[inline(always)]
    pub fn pipe_cmd_err(&self) -> PipeCmdErrR {
        PipeCmdErrR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - For every page of data transfer to or from the device, this bit will be set."]
    #[inline(always)]
    pub fn page_xfer_inc(&self) -> PageXferIncR {
        PageXferIncR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Ecc logic detected uncorrectable error while reading data from flash device."]
    #[inline(always)]
    #[must_use]
    pub fn ecc_uncor_err(&mut self) -> EccUncorErrW<StatusIntrStatus3Spec> {
        EccUncorErrW::new(self, 0)
    }
    #[doc = "Bit 2 - Not implemented."]
    #[inline(always)]
    #[must_use]
    pub fn dma_cmd_comp(&mut self) -> DmaCmdCompW<StatusIntrStatus3Spec> {
        DmaCmdCompW::new(self, 2)
    }
    #[doc = "Bit 3 - Watchdog timer has triggered in the controller due to one of the reasons like device not responding or controller state machine did not get back to idle"]
    #[inline(always)]
    #[must_use]
    pub fn time_out(&mut self) -> TimeOutW<StatusIntrStatus3Spec> {
        TimeOutW::new(self, 3)
    }
    #[doc = "Bit 4 - Program failure occurred in the device on issuance of a program command. err_block_addr and err_page_addr contain the block address and page address that failed program operation."]
    #[inline(always)]
    #[must_use]
    pub fn program_fail(&mut self) -> ProgramFailW<StatusIntrStatus3Spec> {
        ProgramFailW::new(self, 4)
    }
    #[doc = "Bit 5 - Erase failure occurred in the device on issuance of a erase command. err_block_addr and err_page_addr contain the block address and page address that failed erase operation."]
    #[inline(always)]
    #[must_use]
    pub fn erase_fail(&mut self) -> EraseFailW<StatusIntrStatus3Spec> {
        EraseFailW::new(self, 5)
    }
    #[doc = "Bit 6 - Device finished the last issued load command."]
    #[inline(always)]
    #[must_use]
    pub fn load_comp(&mut self) -> LoadCompW<StatusIntrStatus3Spec> {
        LoadCompW::new(self, 6)
    }
    #[doc = "Bit 7 - Device finished the last issued program command."]
    #[inline(always)]
    #[must_use]
    pub fn program_comp(&mut self) -> ProgramCompW<StatusIntrStatus3Spec> {
        ProgramCompW::new(self, 7)
    }
    #[doc = "Bit 8 - Device erase operation complete"]
    #[inline(always)]
    #[must_use]
    pub fn erase_comp(&mut self) -> EraseCompW<StatusIntrStatus3Spec> {
        EraseCompW::new(self, 8)
    }
    #[doc = "Bit 9 - A pipeline command or a copyback bank command has completed on this particular bank"]
    #[inline(always)]
    #[must_use]
    pub fn pipe_cpybck_cmd_comp(&mut self) -> PipeCpybckCmdCompW<StatusIntrStatus3Spec> {
        PipeCpybckCmdCompW::new(self, 9)
    }
    #[doc = "Bit 10 - The address to program or erase operation is to a locked block and the operation failed due to this reason"]
    #[inline(always)]
    #[must_use]
    pub fn locked_blk(&mut self) -> LockedBlkW<StatusIntrStatus3Spec> {
        LockedBlkW::new(self, 10)
    }
    #[doc = "Bit 11 - An unsupported command was received. This interrupt is set when an invalid command is received, or when a command sequence is broken."]
    #[inline(always)]
    #[must_use]
    pub fn unsup_cmd(&mut self) -> UnsupCmdW<StatusIntrStatus3Spec> {
        UnsupCmdW::new(self, 11)
    }
    #[doc = "Bit 12 - R/B pin of device transitioned from low to high"]
    #[inline(always)]
    #[must_use]
    pub fn int_act(&mut self) -> IntActW<StatusIntrStatus3Spec> {
        IntActW::new(self, 12)
    }
    #[doc = "Bit 13 - The NAND Flash Memory Controller has completed its reset and initialization process"]
    #[inline(always)]
    #[must_use]
    pub fn rst_comp(&mut self) -> RstCompW<StatusIntrStatus3Spec> {
        RstCompW::new(self, 13)
    }
    #[doc = "Bit 14 - A pipeline command sequence has been violated. This occurs when Map 01 page read/write address does not match the corresponding expected address from the pipeline commands issued earlier."]
    #[inline(always)]
    #[must_use]
    pub fn pipe_cmd_err(&mut self) -> PipeCmdErrW<StatusIntrStatus3Spec> {
        PipeCmdErrW::new(self, 14)
    }
    #[doc = "Bit 15 - For every page of data transfer to or from the device, this bit will be set."]
    #[inline(always)]
    #[must_use]
    pub fn page_xfer_inc(&mut self) -> PageXferIncW<StatusIntrStatus3Spec> {
        PageXferIncW::new(self, 15)
    }
}
#[doc = "Interrupt status register for bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_status3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_status3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusIntrStatus3Spec;
impl crate::RegisterSpec for StatusIntrStatus3Spec {
    type Ux = u32;
    const OFFSET: u64 = 1280u64;
}
#[doc = "`read()` method returns [`status_intr_status3::R`](R) reader structure"]
impl crate::Readable for StatusIntrStatus3Spec {}
#[doc = "`write(|w| ..)` method takes [`status_intr_status3::W`](W) writer structure"]
impl crate::Writable for StatusIntrStatus3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0xfffd;
}
#[doc = "`reset()` method sets status_intr_status3 to value 0"]
impl crate::Resettable for StatusIntrStatus3Spec {
    const RESET_VALUE: u32 = 0;
}
