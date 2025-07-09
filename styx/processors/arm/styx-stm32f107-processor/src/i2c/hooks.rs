// SPDX-License-Identifier: BSD-2-Clause
use super::*;
use tracing::debug;

pub(crate) fn i2c_cr1_w_hook(
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
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;
    let val = u16::from_le_bytes(data[..2].try_into().unwrap());

    let mut i2c_inner = i2c_controller.i2cs[address_to_i2c_n(address)]
        .inner_hal
        .lock()
        .unwrap();

    i2c_inner.cr1 = CR1::from(val);

    debug!("\t*0x{address:x} = {val:016b}");
    if i2c_inner.cr1.start().value() > 0 {
        // send start signal
        debug!("\tsending start signal");
        i2c_controller.i2cs[address_to_i2c_n(address)]
            .generate_start_cond(proc.event_controller.inner.as_mut())?;

        i2c_inner.sr1.set_sb(true.into());
        i2c_inner.sr2.set_busy(true.into());
        i2c_inner.sr2.set_msl(true.into());
        i2c_inner.cr1.set_start(false.into());
    }

    if i2c_inner.cr1.stop().value() > 0 {
        debug!("\tsending stop signal");
        i2c_controller.i2cs[address_to_i2c_n(address)].generate_stop_cond();

        i2c_inner.sr2.set_busy(false.into());
        i2c_inner.sr2.set_msl(false.into());
        i2c_inner.cr1.set_stop(false.into());
    }
    Ok(())
}
pub(crate) fn i2c_cr1_r_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;

    let i2c_inner = &i2c_controller.i2cs[address_to_i2c_n(address)];

    let cr1 = i2c_inner.inner_hal.lock().unwrap().cr1.value.to_le_bytes();

    data[0] = cr1[0];
    data[1] = cr1[1];
    Ok(())
}

const I2C_ITBUFEN: u16 = 1 << 10;
const I2C_ITEVTEN: u16 = 1 << 9;
const I2C_ITERREN: u16 = 1 << 8;

pub(crate) fn i2c_cr2_w_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    debug!(
        "writing {:x?} to I2C CR2 [0x{:x}]",
        data,
        proc.cpu.pc().unwrap()
    );
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;

    let val = u16::from_le_bytes(data[..2].try_into().unwrap());

    let i2c_port = &mut i2c_controller.i2cs[address_to_i2c_n(address)];

    i2c_port.itbufen = (val & I2C_ITBUFEN) > 0;
    i2c_port.itevten = (val & I2C_ITEVTEN) > 0;
    i2c_port.iterren = (val & I2C_ITERREN) > 0;

    Ok(())
}

pub(crate) fn i2c_dr_w_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    debug!("writing {:x?} to I2C DR", data[0]);

    // transmit byte
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;

    i2c_controller.i2cs[address_to_i2c_n(address)].send_data(data[0]);

    // clear TXE and BTF flag
    let i2c_inner = &i2c_controller.i2cs[address_to_i2c_n(address)];
    i2c_inner
        .inner_hal
        .lock()
        .unwrap()
        .sr1
        .set_txe(u1::from(false));
    i2c_inner
        .inner_hal
        .lock()
        .unwrap()
        .sr1
        .set_btf(u1::from(false));

    // save a copy, we need to read the lsb later
    i2c_inner.inner_hal.lock().unwrap().dr.set_dr(data[0]);
    Ok(())
}

pub(crate) fn i2c_dr_r_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;

    let i2c_inner = &i2c_controller.i2cs[address_to_i2c_n(address)];

    let dr = i2c_inner.inner_hal.lock().unwrap().dr.dr();

    data[0] = dr;

    i2c_inner.ready_for_more_data();

    Ok(())
}

pub(crate) fn i2c_sr1_r_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;

    let i2c_inner = &i2c_controller.i2cs[address_to_i2c_n(address)];

    let sr1 = i2c_inner.inner_hal.lock().unwrap().sr1.value.to_le_bytes();

    data[0] = sr1[0];
    data[1] = sr1[1];

    Ok(())
}

pub(crate) fn i2c_sr2_r_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let i2c_controller = proc
        .event_controller
        .peripherals
        .get_expect::<I2CController>()?;

    let i2c_inner = &i2c_controller.i2cs[address_to_i2c_n(address)];

    let sr2 = i2c_inner.inner_hal.lock().unwrap().sr2.value.to_le_bytes();

    data[0] = sr2[0];
    data[1] = sr2[1];

    Ok(())
}
