// SPDX-License-Identifier: BSD-2-Clause
use super::*;
use std::sync::{Arc, Mutex};
use styx_core::hooks::{MemoryReadHook, MemoryWriteHook};
use tracing::debug;

pub(crate) struct I2cCr1WHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryWriteHook for I2cCr1WHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "writing {:x?} to I2C CR1 [0x{:x}]",
            data,
            proc.cpu.pc().unwrap()
        );
        let port = self.inner.lock().unwrap();
        let val = u16::from_le_bytes(data[..2].try_into().unwrap());

        let mut i2c_inner = port.inner_hal.lock().unwrap();

        i2c_inner.cr1 = CR1::from(val);

        debug!("\t*0x{address:x} = {val:016b}");
        if i2c_inner.cr1.start().value() > 0 {
            // send start signal
            debug!("\tsending start signal");
            port.generate_start_cond(proc.event_controller.inner.as_mut())?;

            i2c_inner.sr1.set_sb(true.into());
            i2c_inner.sr2.set_busy(true.into());
            i2c_inner.sr2.set_msl(true.into());
            i2c_inner.cr1.set_start(false.into());
        }

        if i2c_inner.cr1.stop().value() > 0 {
            debug!("\tsending stop signal");
            port.generate_stop_cond();

            i2c_inner.sr2.set_busy(false.into());
            i2c_inner.sr2.set_msl(false.into());
            i2c_inner.cr1.set_stop(false.into());
        }
        Ok(())
    }
}

pub(crate) struct I2cCr1RHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryReadHook for I2cCr1RHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let port = self.inner.lock().unwrap();

        let cr1 = port.inner_hal.lock().unwrap().cr1.value.to_le_bytes();

        data[0] = cr1[0];
        data[1] = cr1[1];
        Ok(())
    }
}

const I2C_ITBUFEN: u16 = 1 << 10;
const I2C_ITEVTEN: u16 = 1 << 9;
const I2C_ITERREN: u16 = 1 << 8;

pub(crate) struct I2cCr2WHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryWriteHook for I2cCr2WHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "writing {:x?} to I2C CR2 [0x{:x}]",
            data,
            proc.cpu.pc().unwrap()
        );
        let mut port = self.inner.lock().unwrap();

        let val = u16::from_le_bytes(data[..2].try_into().unwrap());

        port.itbufen = (val & I2C_ITBUFEN) > 0;
        port.itevten = (val & I2C_ITEVTEN) > 0;
        port.iterren = (val & I2C_ITERREN) > 0;

        Ok(())
    }
}

pub(crate) struct I2cDrWHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryWriteHook for I2cDrWHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!("writing {:x?} to I2C DR", data[0]);

        // transmit byte
        let port = self.inner.lock().unwrap();

        port.send_data(data[0]);

        let mut hal = port.inner_hal.lock().unwrap();
        // clear TXE and BTF flag
        hal.sr1.set_txe(u1::from(false));
        hal.sr1.set_btf(u1::from(false));

        // save a copy, we need to read the lsb later
        hal.dr.set_dr(data[0]);
        Ok(())
    }
}

pub(crate) struct I2cDrRHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryReadHook for I2cDrRHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let port = self.inner.lock().unwrap();

        let dr = port.inner_hal.lock().unwrap().dr.dr();

        data[0] = dr;

        port.ready_for_more_data();

        Ok(())
    }
}

pub(crate) struct I2cSr1RHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryReadHook for I2cSr1RHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let port = self.inner.lock().unwrap();

        let sr1 = port.inner_hal.lock().unwrap().sr1.value.to_le_bytes();

        data[0] = sr1[0];
        data[1] = sr1[1];
        Ok(())
    }
}

pub(crate) struct I2cSr2RHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryReadHook for I2cSr2RHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let port = self.inner.lock().unwrap();

        let sr2 = port.inner_hal.lock().unwrap().sr2.value.to_le_bytes();

        data[0] = sr2[0];
        data[1] = sr2[1];
        Ok(())
    }
}
