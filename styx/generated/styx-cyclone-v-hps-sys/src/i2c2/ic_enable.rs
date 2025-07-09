// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_enable` reader"]
pub type R = crate::R<IcEnableSpec>;
#[doc = "Register `ic_enable` writer"]
pub type W = crate::W<IcEnableSpec>;
#[doc = "Controls whether the I2C is enabled. Software can disable I2C while it is active. However, it is important that care be taken to ensure that I2C is disabled properly. When the I2C is disabled, the following occurs: The TX FIFO and RX FIFO get flushed. Status bits in the IC_INTR_STAT register are still active until I2C goes into IDLE state. If the module is transmitting, it stops as well as deletes the contents of the transmit buffer after the current transfer is complete. If the module is receiving, the I2C stops the current transfer at the end of the current byte and does not acknowledge the transfer. The l4_sp_clk synchronizes pclk and ic_clk. The register ic_enable_status is added to allow software to determine when the hardware has completely shutdown in response to the IC_ENABLE register being set from 1 to 0. Only one register is required to be monitored. Procedure for Disabling I2C 1. Define a timer interval (ti2c_poll) equal to the 10 times the signaling period for the highest I2C transfer speed used in the system and supported by I2C. For example, if the highest I2C transfer mode is 400 kb/s, then this ti2c_poll is 25us. 2. Define a maximum time-out parameter, MAX_T_POLL_COUNT, such that if any repeated polling operation exceeds this maximum value, an error is reported. 3. Execute a blocking thread/process/function that prevents any further I2C master transactions to be started by software, but allows any pending transfers to be completed. 4. The variable POLL_COUNT is initialized to zero. 5. Set IC_ENABLE to 0. 6. Read the IC_ENABLE_STATUS register and test the IC_EN bit (bit 0). Increment POLL_COUNT by one. If POLL_COUNT >= MAX_T_POLL_COUNT, exit with the relevant error code. 7. If IC_ENABLE_STATUS\\[0\\]
is 1, then sleep for ti2c_poll and proceed to the previous step. Otherwise, exit with a relevant success code.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enable {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Enable> for bool {
    #[inline(always)]
    fn from(variant: Enable) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enable` reader - Controls whether the I2C is enabled. Software can disable I2C while it is active. However, it is important that care be taken to ensure that I2C is disabled properly. When the I2C is disabled, the following occurs: The TX FIFO and RX FIFO get flushed. Status bits in the IC_INTR_STAT register are still active until I2C goes into IDLE state. If the module is transmitting, it stops as well as deletes the contents of the transmit buffer after the current transfer is complete. If the module is receiving, the I2C stops the current transfer at the end of the current byte and does not acknowledge the transfer. The l4_sp_clk synchronizes pclk and ic_clk. The register ic_enable_status is added to allow software to determine when the hardware has completely shutdown in response to the IC_ENABLE register being set from 1 to 0. Only one register is required to be monitored. Procedure for Disabling I2C 1. Define a timer interval (ti2c_poll) equal to the 10 times the signaling period for the highest I2C transfer speed used in the system and supported by I2C. For example, if the highest I2C transfer mode is 400 kb/s, then this ti2c_poll is 25us. 2. Define a maximum time-out parameter, MAX_T_POLL_COUNT, such that if any repeated polling operation exceeds this maximum value, an error is reported. 3. Execute a blocking thread/process/function that prevents any further I2C master transactions to be started by software, but allows any pending transfers to be completed. 4. The variable POLL_COUNT is initialized to zero. 5. Set IC_ENABLE to 0. 6. Read the IC_ENABLE_STATUS register and test the IC_EN bit (bit 0). Increment POLL_COUNT by one. If POLL_COUNT >= MAX_T_POLL_COUNT, exit with the relevant error code. 7. If IC_ENABLE_STATUS\\[0\\]
is 1, then sleep for ti2c_poll and proceed to the previous step. Otherwise, exit with a relevant success code."]
pub type EnableR = crate::BitReader<Enable>;
impl EnableR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enable {
        match self.bits {
            false => Enable::Disable,
            true => Enable::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Enable::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Enable::Enable
    }
}
#[doc = "Field `enable` writer - Controls whether the I2C is enabled. Software can disable I2C while it is active. However, it is important that care be taken to ensure that I2C is disabled properly. When the I2C is disabled, the following occurs: The TX FIFO and RX FIFO get flushed. Status bits in the IC_INTR_STAT register are still active until I2C goes into IDLE state. If the module is transmitting, it stops as well as deletes the contents of the transmit buffer after the current transfer is complete. If the module is receiving, the I2C stops the current transfer at the end of the current byte and does not acknowledge the transfer. The l4_sp_clk synchronizes pclk and ic_clk. The register ic_enable_status is added to allow software to determine when the hardware has completely shutdown in response to the IC_ENABLE register being set from 1 to 0. Only one register is required to be monitored. Procedure for Disabling I2C 1. Define a timer interval (ti2c_poll) equal to the 10 times the signaling period for the highest I2C transfer speed used in the system and supported by I2C. For example, if the highest I2C transfer mode is 400 kb/s, then this ti2c_poll is 25us. 2. Define a maximum time-out parameter, MAX_T_POLL_COUNT, such that if any repeated polling operation exceeds this maximum value, an error is reported. 3. Execute a blocking thread/process/function that prevents any further I2C master transactions to be started by software, but allows any pending transfers to be completed. 4. The variable POLL_COUNT is initialized to zero. 5. Set IC_ENABLE to 0. 6. Read the IC_ENABLE_STATUS register and test the IC_EN bit (bit 0). Increment POLL_COUNT by one. If POLL_COUNT >= MAX_T_POLL_COUNT, exit with the relevant error code. 7. If IC_ENABLE_STATUS\\[0\\]
is 1, then sleep for ti2c_poll and proceed to the previous step. Otherwise, exit with a relevant success code."]
pub type EnableW<'a, REG> = crate::BitWriter<'a, REG, Enable>;
impl<'a, REG> EnableW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Enable::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Enable::Enable)
    }
}
#[doc = "Field `txabort` reader - Write 1 does a TX abort. Self cleared on abort completion"]
pub type TxabortR = crate::BitReader;
#[doc = "Field `txabort` writer - Write 1 does a TX abort. Self cleared on abort completion"]
pub type TxabortW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Controls whether the I2C is enabled. Software can disable I2C while it is active. However, it is important that care be taken to ensure that I2C is disabled properly. When the I2C is disabled, the following occurs: The TX FIFO and RX FIFO get flushed. Status bits in the IC_INTR_STAT register are still active until I2C goes into IDLE state. If the module is transmitting, it stops as well as deletes the contents of the transmit buffer after the current transfer is complete. If the module is receiving, the I2C stops the current transfer at the end of the current byte and does not acknowledge the transfer. The l4_sp_clk synchronizes pclk and ic_clk. The register ic_enable_status is added to allow software to determine when the hardware has completely shutdown in response to the IC_ENABLE register being set from 1 to 0. Only one register is required to be monitored. Procedure for Disabling I2C 1. Define a timer interval (ti2c_poll) equal to the 10 times the signaling period for the highest I2C transfer speed used in the system and supported by I2C. For example, if the highest I2C transfer mode is 400 kb/s, then this ti2c_poll is 25us. 2. Define a maximum time-out parameter, MAX_T_POLL_COUNT, such that if any repeated polling operation exceeds this maximum value, an error is reported. 3. Execute a blocking thread/process/function that prevents any further I2C master transactions to be started by software, but allows any pending transfers to be completed. 4. The variable POLL_COUNT is initialized to zero. 5. Set IC_ENABLE to 0. 6. Read the IC_ENABLE_STATUS register and test the IC_EN bit (bit 0). Increment POLL_COUNT by one. If POLL_COUNT >= MAX_T_POLL_COUNT, exit with the relevant error code. 7. If IC_ENABLE_STATUS\\[0\\]
is 1, then sleep for ti2c_poll and proceed to the previous step. Otherwise, exit with a relevant success code."]
    #[inline(always)]
    pub fn enable(&self) -> EnableR {
        EnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Write 1 does a TX abort. Self cleared on abort completion"]
    #[inline(always)]
    pub fn txabort(&self) -> TxabortR {
        TxabortR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether the I2C is enabled. Software can disable I2C while it is active. However, it is important that care be taken to ensure that I2C is disabled properly. When the I2C is disabled, the following occurs: The TX FIFO and RX FIFO get flushed. Status bits in the IC_INTR_STAT register are still active until I2C goes into IDLE state. If the module is transmitting, it stops as well as deletes the contents of the transmit buffer after the current transfer is complete. If the module is receiving, the I2C stops the current transfer at the end of the current byte and does not acknowledge the transfer. The l4_sp_clk synchronizes pclk and ic_clk. The register ic_enable_status is added to allow software to determine when the hardware has completely shutdown in response to the IC_ENABLE register being set from 1 to 0. Only one register is required to be monitored. Procedure for Disabling I2C 1. Define a timer interval (ti2c_poll) equal to the 10 times the signaling period for the highest I2C transfer speed used in the system and supported by I2C. For example, if the highest I2C transfer mode is 400 kb/s, then this ti2c_poll is 25us. 2. Define a maximum time-out parameter, MAX_T_POLL_COUNT, such that if any repeated polling operation exceeds this maximum value, an error is reported. 3. Execute a blocking thread/process/function that prevents any further I2C master transactions to be started by software, but allows any pending transfers to be completed. 4. The variable POLL_COUNT is initialized to zero. 5. Set IC_ENABLE to 0. 6. Read the IC_ENABLE_STATUS register and test the IC_EN bit (bit 0). Increment POLL_COUNT by one. If POLL_COUNT >= MAX_T_POLL_COUNT, exit with the relevant error code. 7. If IC_ENABLE_STATUS\\[0\\]
is 1, then sleep for ti2c_poll and proceed to the previous step. Otherwise, exit with a relevant success code."]
    #[inline(always)]
    #[must_use]
    pub fn enable(&mut self) -> EnableW<IcEnableSpec> {
        EnableW::new(self, 0)
    }
    #[doc = "Bit 1 - Write 1 does a TX abort. Self cleared on abort completion"]
    #[inline(always)]
    #[must_use]
    pub fn txabort(&mut self) -> TxabortW<IcEnableSpec> {
        TxabortW::new(self, 1)
    }
}
#[doc = "Enable and disable i2c operation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcEnableSpec;
impl crate::RegisterSpec for IcEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 108u64;
}
#[doc = "`read()` method returns [`ic_enable::R`](R) reader structure"]
impl crate::Readable for IcEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_enable::W`](W) writer structure"]
impl crate::Writable for IcEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_enable to value 0"]
impl crate::Resettable for IcEnableSpec {
    const RESET_VALUE: u32 = 0;
}
