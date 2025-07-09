// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    timer1loadcount: Timer1loadcount,
    timer1currentval: Timer1currentval,
    timer1controlreg: Timer1controlreg,
    timer1eoi: Timer1eoi,
    timer1intstat: Timer1intstat,
    _reserved5: [u8; 0x8c],
    timersintstat: Timersintstat,
    timerseoi: Timerseoi,
    timersrawintstat: Timersrawintstat,
    timerscompversion: Timerscompversion,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Used to load counter value into Timer1"]
    #[inline(always)]
    pub const fn timer1loadcount(&self) -> &Timer1loadcount {
        &self.timer1loadcount
    }
    #[doc = "0x04 - Provides current value of Timer1"]
    #[inline(always)]
    pub const fn timer1currentval(&self) -> &Timer1currentval {
        &self.timer1currentval
    }
    #[doc = "0x08 - This register controls enabling, operating mode (free-running or user-defined-count), and interrupt mask of Timer1. You can program this register to enable or disable Timer1 and to control its mode of operation."]
    #[inline(always)]
    pub const fn timer1controlreg(&self) -> &Timer1controlreg {
        &self.timer1controlreg
    }
    #[doc = "0x0c - Clears Timer1 interrupt when read."]
    #[inline(always)]
    pub const fn timer1eoi(&self) -> &Timer1eoi {
        &self.timer1eoi
    }
    #[doc = "0x10 - Provides the interrupt status of Timer1 after masking."]
    #[inline(always)]
    pub const fn timer1intstat(&self) -> &Timer1intstat {
        &self.timer1intstat
    }
    #[doc = "0xa0 - Provides the interrupt status for all timers after masking. Because there is only Timer1 in this module instance, this status is the same as timer1intstat."]
    #[inline(always)]
    pub const fn timersintstat(&self) -> &Timersintstat {
        &self.timersintstat
    }
    #[doc = "0xa4 - Clears Timer1 interrupt when read. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi."]
    #[inline(always)]
    pub const fn timerseoi(&self) -> &Timerseoi {
        &self.timerseoi
    }
    #[doc = "0xa8 - Provides the interrupt status for all timers before masking. Note that there is only Timer1 in this module instance."]
    #[inline(always)]
    pub const fn timersrawintstat(&self) -> &Timersrawintstat {
        &self.timersrawintstat
    }
    #[doc = "0xac - "]
    #[inline(always)]
    pub const fn timerscompversion(&self) -> &Timerscompversion {
        &self.timerscompversion
    }
}
#[doc = "timer1loadcount (rw) register accessor: Used to load counter value into Timer1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1loadcount::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`timer1loadcount::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timer1loadcount`]
module"]
#[doc(alias = "timer1loadcount")]
pub type Timer1loadcount = crate::Reg<timer1loadcount::Timer1loadcountSpec>;
#[doc = "Used to load counter value into Timer1"]
pub mod timer1loadcount;
#[doc = "timer1currentval (r) register accessor: Provides current value of Timer1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1currentval::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timer1currentval`]
module"]
#[doc(alias = "timer1currentval")]
pub type Timer1currentval = crate::Reg<timer1currentval::Timer1currentvalSpec>;
#[doc = "Provides current value of Timer1"]
pub mod timer1currentval;
#[doc = "timer1controlreg (rw) register accessor: This register controls enabling, operating mode (free-running or user-defined-count), and interrupt mask of Timer1. You can program this register to enable or disable Timer1 and to control its mode of operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1controlreg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`timer1controlreg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timer1controlreg`]
module"]
#[doc(alias = "timer1controlreg")]
pub type Timer1controlreg = crate::Reg<timer1controlreg::Timer1controlregSpec>;
#[doc = "This register controls enabling, operating mode (free-running or user-defined-count), and interrupt mask of Timer1. You can program this register to enable or disable Timer1 and to control its mode of operation."]
pub mod timer1controlreg;
#[doc = "timer1eoi (r) register accessor: Clears Timer1 interrupt when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1eoi::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timer1eoi`]
module"]
#[doc(alias = "timer1eoi")]
pub type Timer1eoi = crate::Reg<timer1eoi::Timer1eoiSpec>;
#[doc = "Clears Timer1 interrupt when read."]
pub mod timer1eoi;
#[doc = "timer1intstat (r) register accessor: Provides the interrupt status of Timer1 after masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1intstat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timer1intstat`]
module"]
#[doc(alias = "timer1intstat")]
pub type Timer1intstat = crate::Reg<timer1intstat::Timer1intstatSpec>;
#[doc = "Provides the interrupt status of Timer1 after masking."]
pub mod timer1intstat;
#[doc = "timersintstat (r) register accessor: Provides the interrupt status for all timers after masking. Because there is only Timer1 in this module instance, this status is the same as timer1intstat.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timersintstat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timersintstat`]
module"]
#[doc(alias = "timersintstat")]
pub type Timersintstat = crate::Reg<timersintstat::TimersintstatSpec>;
#[doc = "Provides the interrupt status for all timers after masking. Because there is only Timer1 in this module instance, this status is the same as timer1intstat."]
pub mod timersintstat;
#[doc = "timerseoi (r) register accessor: Clears Timer1 interrupt when read. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timerseoi::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timerseoi`]
module"]
#[doc(alias = "timerseoi")]
pub type Timerseoi = crate::Reg<timerseoi::TimerseoiSpec>;
#[doc = "Clears Timer1 interrupt when read. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi."]
pub mod timerseoi;
#[doc = "timersrawintstat (r) register accessor: Provides the interrupt status for all timers before masking. Note that there is only Timer1 in this module instance.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timersrawintstat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timersrawintstat`]
module"]
#[doc(alias = "timersrawintstat")]
pub type Timersrawintstat = crate::Reg<timersrawintstat::TimersrawintstatSpec>;
#[doc = "Provides the interrupt status for all timers before masking. Note that there is only Timer1 in this module instance."]
pub mod timersrawintstat;
#[doc = "timerscompversion (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timerscompversion::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@timerscompversion`]
module"]
#[doc(alias = "timerscompversion")]
pub type Timerscompversion = crate::Reg<timerscompversion::TimerscompversionSpec>;
#[doc = ""]
pub mod timerscompversion;
