// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_enable_status` reader"]
pub type R = crate::R<IcEnableStatusSpec>;
#[doc = "Register `ic_enable_status` writer"]
pub type W = crate::W<IcEnableStatusSpec>;
#[doc = "Field `ic_en` reader - This bit always reflects the value driven on the output port ic_en. Not used in current application. When read as 1, i2c is deemed to be in an enabled state. When read as 0, i2c is deemed completely inactive. NOTE: The CPU can safely read this bit anytime. When this bit is read as 0, the CPU can safely read slv_rx_data_lost (bit 2) and slv_disabled_while_busy (bit 1)."]
pub type IcEnR = crate::BitReader;
#[doc = "Field `ic_en` writer - This bit always reflects the value driven on the output port ic_en. Not used in current application. When read as 1, i2c is deemed to be in an enabled state. When read as 0, i2c is deemed completely inactive. NOTE: The CPU can safely read this bit anytime. When this bit is read as 0, the CPU can safely read slv_rx_data_lost (bit 2) and slv_disabled_while_busy (bit 1)."]
pub type IcEnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `slv_disabled_while_busy` reader - This bit indicates if a potential or active Slave operation has been aborted due to the setting of the ic_enable register from 1 to 0. This bit is set when the CPU writes a 0 to the ic_enable register while: (a) I2C is receiving the address byte of the Slave-Transmitter operation from a remote master; OR, (b) address and data bytes of the Slave-Receiver operation from a remote master. When read as 1, I2C is deemed to have forced a NACK during any part of an I2C transfer, irrespective of whether the I2C address matches the slave address set in i2c (IC_SAR register) OR if the transfer is completed before IC_ENABLE is set to 0 but has not taken effect. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and IC_ENABLE has been set to 0, then this bit will also be set to 1. When read as 0, i2c is deemed to have been disabled when there is master activity, or when the I2C bus is idle. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
pub type SlvDisabledWhileBusyR = crate::BitReader;
#[doc = "Field `slv_disabled_while_busy` writer - This bit indicates if a potential or active Slave operation has been aborted due to the setting of the ic_enable register from 1 to 0. This bit is set when the CPU writes a 0 to the ic_enable register while: (a) I2C is receiving the address byte of the Slave-Transmitter operation from a remote master; OR, (b) address and data bytes of the Slave-Receiver operation from a remote master. When read as 1, I2C is deemed to have forced a NACK during any part of an I2C transfer, irrespective of whether the I2C address matches the slave address set in i2c (IC_SAR register) OR if the transfer is completed before IC_ENABLE is set to 0 but has not taken effect. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and IC_ENABLE has been set to 0, then this bit will also be set to 1. When read as 0, i2c is deemed to have been disabled when there is master activity, or when the I2C bus is idle. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
pub type SlvDisabledWhileBusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `slv_rx_data_lost` reader - This bit indicates if a Slave-Receiver operation has been aborted with at least one data byte received from an I2C transfer due to the setting of IC ENABLE from 1 to 0. When read as 1, i2c is deemed to have been actively engaged in an aborted I2C transfer (with matching address) and the data phase of the I2C transfer has been entered, even though a data byte has been responded with a NACK. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and ic_enable has been set to 0, then this bit is also set to 1. When read as 0, i2c is deemed to have been disabled without being actively involved in the data phase of a Slave-Receiver transfer. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
pub type SlvRxDataLostR = crate::BitReader;
#[doc = "Field `slv_rx_data_lost` writer - This bit indicates if a Slave-Receiver operation has been aborted with at least one data byte received from an I2C transfer due to the setting of IC ENABLE from 1 to 0. When read as 1, i2c is deemed to have been actively engaged in an aborted I2C transfer (with matching address) and the data phase of the I2C transfer has been entered, even though a data byte has been responded with a NACK. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and ic_enable has been set to 0, then this bit is also set to 1. When read as 0, i2c is deemed to have been disabled without being actively involved in the data phase of a Slave-Receiver transfer. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
pub type SlvRxDataLostW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit always reflects the value driven on the output port ic_en. Not used in current application. When read as 1, i2c is deemed to be in an enabled state. When read as 0, i2c is deemed completely inactive. NOTE: The CPU can safely read this bit anytime. When this bit is read as 0, the CPU can safely read slv_rx_data_lost (bit 2) and slv_disabled_while_busy (bit 1)."]
    #[inline(always)]
    pub fn ic_en(&self) -> IcEnR {
        IcEnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit indicates if a potential or active Slave operation has been aborted due to the setting of the ic_enable register from 1 to 0. This bit is set when the CPU writes a 0 to the ic_enable register while: (a) I2C is receiving the address byte of the Slave-Transmitter operation from a remote master; OR, (b) address and data bytes of the Slave-Receiver operation from a remote master. When read as 1, I2C is deemed to have forced a NACK during any part of an I2C transfer, irrespective of whether the I2C address matches the slave address set in i2c (IC_SAR register) OR if the transfer is completed before IC_ENABLE is set to 0 but has not taken effect. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and IC_ENABLE has been set to 0, then this bit will also be set to 1. When read as 0, i2c is deemed to have been disabled when there is master activity, or when the I2C bus is idle. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
    #[inline(always)]
    pub fn slv_disabled_while_busy(&self) -> SlvDisabledWhileBusyR {
        SlvDisabledWhileBusyR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit indicates if a Slave-Receiver operation has been aborted with at least one data byte received from an I2C transfer due to the setting of IC ENABLE from 1 to 0. When read as 1, i2c is deemed to have been actively engaged in an aborted I2C transfer (with matching address) and the data phase of the I2C transfer has been entered, even though a data byte has been responded with a NACK. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and ic_enable has been set to 0, then this bit is also set to 1. When read as 0, i2c is deemed to have been disabled without being actively involved in the data phase of a Slave-Receiver transfer. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
    #[inline(always)]
    pub fn slv_rx_data_lost(&self) -> SlvRxDataLostR {
        SlvRxDataLostR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit always reflects the value driven on the output port ic_en. Not used in current application. When read as 1, i2c is deemed to be in an enabled state. When read as 0, i2c is deemed completely inactive. NOTE: The CPU can safely read this bit anytime. When this bit is read as 0, the CPU can safely read slv_rx_data_lost (bit 2) and slv_disabled_while_busy (bit 1)."]
    #[inline(always)]
    #[must_use]
    pub fn ic_en(&mut self) -> IcEnW<IcEnableStatusSpec> {
        IcEnW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit indicates if a potential or active Slave operation has been aborted due to the setting of the ic_enable register from 1 to 0. This bit is set when the CPU writes a 0 to the ic_enable register while: (a) I2C is receiving the address byte of the Slave-Transmitter operation from a remote master; OR, (b) address and data bytes of the Slave-Receiver operation from a remote master. When read as 1, I2C is deemed to have forced a NACK during any part of an I2C transfer, irrespective of whether the I2C address matches the slave address set in i2c (IC_SAR register) OR if the transfer is completed before IC_ENABLE is set to 0 but has not taken effect. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and IC_ENABLE has been set to 0, then this bit will also be set to 1. When read as 0, i2c is deemed to have been disabled when there is master activity, or when the I2C bus is idle. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
    #[inline(always)]
    #[must_use]
    pub fn slv_disabled_while_busy(&mut self) -> SlvDisabledWhileBusyW<IcEnableStatusSpec> {
        SlvDisabledWhileBusyW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit indicates if a Slave-Receiver operation has been aborted with at least one data byte received from an I2C transfer due to the setting of IC ENABLE from 1 to 0. When read as 1, i2c is deemed to have been actively engaged in an aborted I2C transfer (with matching address) and the data phase of the I2C transfer has been entered, even though a data byte has been responded with a NACK. NOTE: If the remote I2C master terminates the transfer with a STOP condition before the i2c has a chance to NACK a transfer, and ic_enable has been set to 0, then this bit is also set to 1. When read as 0, i2c is deemed to have been disabled without being actively involved in the data phase of a Slave-Receiver transfer. NOTE: The CPU can safely read this bit when IC_EN (bit 0) is read as 0."]
    #[inline(always)]
    #[must_use]
    pub fn slv_rx_data_lost(&mut self) -> SlvRxDataLostW<IcEnableStatusSpec> {
        SlvRxDataLostW::new(self, 2)
    }
}
#[doc = "This register is used to report the i2c hardware status when the IC_ENABLE register is set from 1 to 0; that is, when i2c is disabled. If IC_ENABLE has been set to 1, bits 2:1 are forced to 0, and bit 0 is forced to 1. If IC_ENABLE has been set to 0, bits 2:1 are only valid as soon as bit 0 is read as '0'. Note: When ic_enable has been written with '0' a delay occurs for bit 0 to be read as '0' because disabling the i2c depends on I2C bus activities.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_enable_status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcEnableStatusSpec;
impl crate::RegisterSpec for IcEnableStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 156u64;
}
#[doc = "`read()` method returns [`ic_enable_status::R`](R) reader structure"]
impl crate::Readable for IcEnableStatusSpec {}
#[doc = "`reset()` method sets ic_enable_status to value 0"]
impl crate::Resettable for IcEnableStatusSpec {
    const RESET_VALUE: u32 = 0;
}
