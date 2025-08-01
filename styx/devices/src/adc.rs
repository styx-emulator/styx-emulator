// SPDX-License-Identifier: BSD-2-Clause
//! implementation of the ADS7866 ADC
//! datasheet: <https://www.ti.com/lit/ds/symlink/ads7868.pdf?ts=1718813567795&ref_url=https%253A%252F%252Fwww.mouser.com%252F>
//!
use std::{borrow::Cow, time::SystemTime};
use styx_core::peripheral_clients::spi::SPIDevice;

pub struct ADS7866 {
    /// keeps track of if we are sending the first or second byte
    data_count: bool,
    time: SystemTime,
    val: u16,
}

impl SPIDevice for ADS7866 {
    fn get_name(&self) -> Cow<'static, str> {
        "ADS7866".into()
    }

    fn write_data(&mut self, _data: u8) {
        // this device has no data in line, writes are ignored
    }

    fn read_data(&mut self) -> Option<u8> {
        // after chip select is pulled low, 4 zeroes are sent followed by 12 bits of actual data
        // so all together it is 2 bytes, first byte sent is 0000<4 MSB of data>, second is <8 LSB of data>
        if !self.data_count {
            self.eval_signal();
            self.data_count = true;
            Some(((self.val >> 8) & 0xFF) as u8)
        } else {
            self.data_count = false;
            Some((self.val & 0xFF) as u8)
        }
    }
}

const NOISE_MAGNITUDE: f64 = 0.05;

impl Default for ADS7866 {
    fn default() -> Self {
        Self::new()
    }
}

impl ADS7866 {
    pub fn new() -> Self {
        Self {
            data_count: false,
            time: SystemTime::now(),
            val: 0,
        }
    }
    /// assume a sine wave between 0 and 1.6 V with some random noise
    fn eval_signal(&mut self) {
        let elapsed = self.time.elapsed();

        if let Ok(s) = elapsed {
            // 12 bits to represent scale
            // assume Vdd = 1.6 V
            // lsb is 1.6/4096 = .00039
            let t = s.as_secs_f64() / 5.0;

            let sig: f64 =
                (4.0 / 5.0) + (t.sin() * (4.0 / 5.0)) + (rand::random::<f64>() * NOISE_MAGNITUDE);
            let scaled_val = (4096_f64 * sig / 1.6).clamp(0.0, 4095.0);

            self.val = scaled_val.round() as u16 & 0xFFF;
        } else {
            self.val = 0;
        }
    }
}
