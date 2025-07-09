// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_con` reader"]
pub type R = crate::R<IcConSpec>;
#[doc = "Register `ic_con` writer"]
pub type W = crate::W<IcConSpec>;
#[doc = "This bit controls whether the i2c master is enabled. NOTE: Software should ensure that if this bit is written with '1', then bit 6 should also be written with a '1'.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasterMode {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<MasterMode> for bool {
    #[inline(always)]
    fn from(variant: MasterMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `master_mode` reader - This bit controls whether the i2c master is enabled. NOTE: Software should ensure that if this bit is written with '1', then bit 6 should also be written with a '1'."]
pub type MasterModeR = crate::BitReader<MasterMode>;
impl MasterModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MasterMode {
        match self.bits {
            false => MasterMode::Disable,
            true => MasterMode::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == MasterMode::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == MasterMode::Enable
    }
}
#[doc = "Field `master_mode` writer - This bit controls whether the i2c master is enabled. NOTE: Software should ensure that if this bit is written with '1', then bit 6 should also be written with a '1'."]
pub type MasterModeW<'a, REG> = crate::BitWriter<'a, REG, MasterMode>;
impl<'a, REG> MasterModeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(MasterMode::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(MasterMode::Enable)
    }
}
#[doc = "These bits control at which speed the I2C operates, its setting is relevant only if one is operating the I2C in master mode. Hardware protects against illegal values being programmed by software. This field should be programmed only with standard or fast speed.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Speed {
    #[doc = "1: `1`"]
    Standard = 1,
    #[doc = "2: `10`"]
    Fast = 2,
}
impl From<Speed> for u8 {
    #[inline(always)]
    fn from(variant: Speed) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Speed {
    type Ux = u8;
}
#[doc = "Field `speed` reader - These bits control at which speed the I2C operates, its setting is relevant only if one is operating the I2C in master mode. Hardware protects against illegal values being programmed by software. This field should be programmed only with standard or fast speed."]
pub type SpeedR = crate::FieldReader<Speed>;
impl SpeedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Speed> {
        match self.bits {
            1 => Some(Speed::Standard),
            2 => Some(Speed::Fast),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_standard(&self) -> bool {
        *self == Speed::Standard
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_fast(&self) -> bool {
        *self == Speed::Fast
    }
}
#[doc = "Field `speed` writer - These bits control at which speed the I2C operates, its setting is relevant only if one is operating the I2C in master mode. Hardware protects against illegal values being programmed by software. This field should be programmed only with standard or fast speed."]
pub type SpeedW<'a, REG> = crate::FieldWriter<'a, REG, 2, Speed>;
impl<'a, REG> SpeedW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn standard(self) -> &'a mut crate::W<REG> {
        self.variant(Speed::Standard)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn fast(self) -> &'a mut crate::W<REG> {
        self.variant(Speed::Fast)
    }
}
#[doc = "When acting as a slave, this bit controls whether the I2C responds to 7- or 10-bit addresses. In 7-bit addressing, only the lower 7 bits of the Slave Address Register are compared. The I2C responds will only respond to 10-bit addressing transfers that match the full 10 bits of the Slave Address register.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ic10bitaddrSlave {
    #[doc = "0: `0`"]
    Slvaddr7bit = 0,
    #[doc = "1: `1`"]
    Slvaddr10bit = 1,
}
impl From<Ic10bitaddrSlave> for bool {
    #[inline(always)]
    fn from(variant: Ic10bitaddrSlave) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ic_10bitaddr_slave` reader - When acting as a slave, this bit controls whether the I2C responds to 7- or 10-bit addresses. In 7-bit addressing, only the lower 7 bits of the Slave Address Register are compared. The I2C responds will only respond to 10-bit addressing transfers that match the full 10 bits of the Slave Address register."]
pub type Ic10bitaddrSlaveR = crate::BitReader<Ic10bitaddrSlave>;
impl Ic10bitaddrSlaveR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ic10bitaddrSlave {
        match self.bits {
            false => Ic10bitaddrSlave::Slvaddr7bit,
            true => Ic10bitaddrSlave::Slvaddr10bit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_slvaddr7bit(&self) -> bool {
        *self == Ic10bitaddrSlave::Slvaddr7bit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_slvaddr10bit(&self) -> bool {
        *self == Ic10bitaddrSlave::Slvaddr10bit
    }
}
#[doc = "Field `ic_10bitaddr_slave` writer - When acting as a slave, this bit controls whether the I2C responds to 7- or 10-bit addresses. In 7-bit addressing, only the lower 7 bits of the Slave Address Register are compared. The I2C responds will only respond to 10-bit addressing transfers that match the full 10 bits of the Slave Address register."]
pub type Ic10bitaddrSlaveW<'a, REG> = crate::BitWriter<'a, REG, Ic10bitaddrSlave>;
impl<'a, REG> Ic10bitaddrSlaveW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn slvaddr7bit(self) -> &'a mut crate::W<REG> {
        self.variant(Ic10bitaddrSlave::Slvaddr7bit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn slvaddr10bit(self) -> &'a mut crate::W<REG> {
        self.variant(Ic10bitaddrSlave::Slvaddr10bit)
    }
}
#[doc = "This bit controls whether the I2C starts its transfers in 7-or 10-bit addressing mode when acting as a master.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ic10bitaddrMaster {
    #[doc = "0: `0`"]
    Mstaddr7bit = 0,
    #[doc = "1: `1`"]
    Mstaddr10bit = 1,
}
impl From<Ic10bitaddrMaster> for bool {
    #[inline(always)]
    fn from(variant: Ic10bitaddrMaster) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ic_10bitaddr_master` reader - This bit controls whether the I2C starts its transfers in 7-or 10-bit addressing mode when acting as a master."]
pub type Ic10bitaddrMasterR = crate::BitReader<Ic10bitaddrMaster>;
impl Ic10bitaddrMasterR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ic10bitaddrMaster {
        match self.bits {
            false => Ic10bitaddrMaster::Mstaddr7bit,
            true => Ic10bitaddrMaster::Mstaddr10bit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mstaddr7bit(&self) -> bool {
        *self == Ic10bitaddrMaster::Mstaddr7bit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_mstaddr10bit(&self) -> bool {
        *self == Ic10bitaddrMaster::Mstaddr10bit
    }
}
#[doc = "Field `ic_10bitaddr_master` writer - This bit controls whether the I2C starts its transfers in 7-or 10-bit addressing mode when acting as a master."]
pub type Ic10bitaddrMasterW<'a, REG> = crate::BitWriter<'a, REG, Ic10bitaddrMaster>;
impl<'a, REG> Ic10bitaddrMasterW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mstaddr7bit(self) -> &'a mut crate::W<REG> {
        self.variant(Ic10bitaddrMaster::Mstaddr7bit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn mstaddr10bit(self) -> &'a mut crate::W<REG> {
        self.variant(Ic10bitaddrMaster::Mstaddr10bit)
    }
}
#[doc = "Determines whether RESTART conditions may be sent when acting as a master. Some older slaves do not support handling RESTART conditions; however, RESTART conditions are used in several I2C operations. When RESTART is disabled, the master is prohibited from performing the following functions - Changing direction within a transfer (split), - Sending a START BYTE, - High-speed mode operation, - Combined format transfers in 7-bit addressing modes, - Read operation with a 10-bit address, - Sending multiple bytes per transfer, By replacing RESTART condition followed by a STOP and a subsequent START condition, split operations are broken down into multiple I2C transfers. If the above operations are performed, it will result in setting bit \\[6\\](tx_abort) of the Raw Interrupt Status Register.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcRestartEn {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<IcRestartEn> for bool {
    #[inline(always)]
    fn from(variant: IcRestartEn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ic_restart_en` reader - Determines whether RESTART conditions may be sent when acting as a master. Some older slaves do not support handling RESTART conditions; however, RESTART conditions are used in several I2C operations. When RESTART is disabled, the master is prohibited from performing the following functions - Changing direction within a transfer (split), - Sending a START BYTE, - High-speed mode operation, - Combined format transfers in 7-bit addressing modes, - Read operation with a 10-bit address, - Sending multiple bytes per transfer, By replacing RESTART condition followed by a STOP and a subsequent START condition, split operations are broken down into multiple I2C transfers. If the above operations are performed, it will result in setting bit \\[6\\](tx_abort) of the Raw Interrupt Status Register."]
pub type IcRestartEnR = crate::BitReader<IcRestartEn>;
impl IcRestartEnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IcRestartEn {
        match self.bits {
            false => IcRestartEn::Disable,
            true => IcRestartEn::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == IcRestartEn::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == IcRestartEn::Enable
    }
}
#[doc = "Field `ic_restart_en` writer - Determines whether RESTART conditions may be sent when acting as a master. Some older slaves do not support handling RESTART conditions; however, RESTART conditions are used in several I2C operations. When RESTART is disabled, the master is prohibited from performing the following functions - Changing direction within a transfer (split), - Sending a START BYTE, - High-speed mode operation, - Combined format transfers in 7-bit addressing modes, - Read operation with a 10-bit address, - Sending multiple bytes per transfer, By replacing RESTART condition followed by a STOP and a subsequent START condition, split operations are broken down into multiple I2C transfers. If the above operations are performed, it will result in setting bit \\[6\\](tx_abort) of the Raw Interrupt Status Register."]
pub type IcRestartEnW<'a, REG> = crate::BitWriter<'a, REG, IcRestartEn>;
impl<'a, REG> IcRestartEnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(IcRestartEn::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(IcRestartEn::Enable)
    }
}
#[doc = "This bit controls whether I2C has its slave disabled. The slave will be disabled, after reset. NOTE: Software should ensure that if this bit is written with 0, then bit \\[0\\]
of this register should also be written with a 0.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcSlaveDisable {
    #[doc = "1: `1`"]
    Disable = 1,
    #[doc = "0: `0`"]
    Enable = 0,
}
impl From<IcSlaveDisable> for bool {
    #[inline(always)]
    fn from(variant: IcSlaveDisable) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ic_slave_disable` reader - This bit controls whether I2C has its slave disabled. The slave will be disabled, after reset. NOTE: Software should ensure that if this bit is written with 0, then bit \\[0\\]
of this register should also be written with a 0."]
pub type IcSlaveDisableR = crate::BitReader<IcSlaveDisable>;
impl IcSlaveDisableR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IcSlaveDisable {
        match self.bits {
            true => IcSlaveDisable::Disable,
            false => IcSlaveDisable::Enable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == IcSlaveDisable::Disable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == IcSlaveDisable::Enable
    }
}
#[doc = "Field `ic_slave_disable` writer - This bit controls whether I2C has its slave disabled. The slave will be disabled, after reset. NOTE: Software should ensure that if this bit is written with 0, then bit \\[0\\]
of this register should also be written with a 0."]
pub type IcSlaveDisableW<'a, REG> = crate::BitWriter<'a, REG, IcSlaveDisable>;
impl<'a, REG> IcSlaveDisableW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(IcSlaveDisable::Disable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(IcSlaveDisable::Enable)
    }
}
impl R {
    #[doc = "Bit 0 - This bit controls whether the i2c master is enabled. NOTE: Software should ensure that if this bit is written with '1', then bit 6 should also be written with a '1'."]
    #[inline(always)]
    pub fn master_mode(&self) -> MasterModeR {
        MasterModeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - These bits control at which speed the I2C operates, its setting is relevant only if one is operating the I2C in master mode. Hardware protects against illegal values being programmed by software. This field should be programmed only with standard or fast speed."]
    #[inline(always)]
    pub fn speed(&self) -> SpeedR {
        SpeedR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 3 - When acting as a slave, this bit controls whether the I2C responds to 7- or 10-bit addresses. In 7-bit addressing, only the lower 7 bits of the Slave Address Register are compared. The I2C responds will only respond to 10-bit addressing transfers that match the full 10 bits of the Slave Address register."]
    #[inline(always)]
    pub fn ic_10bitaddr_slave(&self) -> Ic10bitaddrSlaveR {
        Ic10bitaddrSlaveR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit controls whether the I2C starts its transfers in 7-or 10-bit addressing mode when acting as a master."]
    #[inline(always)]
    pub fn ic_10bitaddr_master(&self) -> Ic10bitaddrMasterR {
        Ic10bitaddrMasterR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Determines whether RESTART conditions may be sent when acting as a master. Some older slaves do not support handling RESTART conditions; however, RESTART conditions are used in several I2C operations. When RESTART is disabled, the master is prohibited from performing the following functions - Changing direction within a transfer (split), - Sending a START BYTE, - High-speed mode operation, - Combined format transfers in 7-bit addressing modes, - Read operation with a 10-bit address, - Sending multiple bytes per transfer, By replacing RESTART condition followed by a STOP and a subsequent START condition, split operations are broken down into multiple I2C transfers. If the above operations are performed, it will result in setting bit \\[6\\](tx_abort) of the Raw Interrupt Status Register."]
    #[inline(always)]
    pub fn ic_restart_en(&self) -> IcRestartEnR {
        IcRestartEnR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit controls whether I2C has its slave disabled. The slave will be disabled, after reset. NOTE: Software should ensure that if this bit is written with 0, then bit \\[0\\]
of this register should also be written with a 0."]
    #[inline(always)]
    pub fn ic_slave_disable(&self) -> IcSlaveDisableR {
        IcSlaveDisableR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit controls whether the i2c master is enabled. NOTE: Software should ensure that if this bit is written with '1', then bit 6 should also be written with a '1'."]
    #[inline(always)]
    #[must_use]
    pub fn master_mode(&mut self) -> MasterModeW<IcConSpec> {
        MasterModeW::new(self, 0)
    }
    #[doc = "Bits 1:2 - These bits control at which speed the I2C operates, its setting is relevant only if one is operating the I2C in master mode. Hardware protects against illegal values being programmed by software. This field should be programmed only with standard or fast speed."]
    #[inline(always)]
    #[must_use]
    pub fn speed(&mut self) -> SpeedW<IcConSpec> {
        SpeedW::new(self, 1)
    }
    #[doc = "Bit 3 - When acting as a slave, this bit controls whether the I2C responds to 7- or 10-bit addresses. In 7-bit addressing, only the lower 7 bits of the Slave Address Register are compared. The I2C responds will only respond to 10-bit addressing transfers that match the full 10 bits of the Slave Address register."]
    #[inline(always)]
    #[must_use]
    pub fn ic_10bitaddr_slave(&mut self) -> Ic10bitaddrSlaveW<IcConSpec> {
        Ic10bitaddrSlaveW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit controls whether the I2C starts its transfers in 7-or 10-bit addressing mode when acting as a master."]
    #[inline(always)]
    #[must_use]
    pub fn ic_10bitaddr_master(&mut self) -> Ic10bitaddrMasterW<IcConSpec> {
        Ic10bitaddrMasterW::new(self, 4)
    }
    #[doc = "Bit 5 - Determines whether RESTART conditions may be sent when acting as a master. Some older slaves do not support handling RESTART conditions; however, RESTART conditions are used in several I2C operations. When RESTART is disabled, the master is prohibited from performing the following functions - Changing direction within a transfer (split), - Sending a START BYTE, - High-speed mode operation, - Combined format transfers in 7-bit addressing modes, - Read operation with a 10-bit address, - Sending multiple bytes per transfer, By replacing RESTART condition followed by a STOP and a subsequent START condition, split operations are broken down into multiple I2C transfers. If the above operations are performed, it will result in setting bit \\[6\\](tx_abort) of the Raw Interrupt Status Register."]
    #[inline(always)]
    #[must_use]
    pub fn ic_restart_en(&mut self) -> IcRestartEnW<IcConSpec> {
        IcRestartEnW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit controls whether I2C has its slave disabled. The slave will be disabled, after reset. NOTE: Software should ensure that if this bit is written with 0, then bit \\[0\\]
of this register should also be written with a 0."]
    #[inline(always)]
    #[must_use]
    pub fn ic_slave_disable(&mut self) -> IcSlaveDisableW<IcConSpec> {
        IcSlaveDisableW::new(self, 6)
    }
}
#[doc = "This register can be written only when the I2C is disabled, which corresponds to the Bit \\[0\\]
of the Enable Register being set to 0. Writes at other times have no effect.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_con::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_con::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcConSpec;
impl crate::RegisterSpec for IcConSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`ic_con::R`](R) reader structure"]
impl crate::Readable for IcConSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_con::W`](W) writer structure"]
impl crate::Writable for IcConSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_con to value 0x7d"]
impl crate::Resettable for IcConSpec {
    const RESET_VALUE: u32 = 0x7d;
}
