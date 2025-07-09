// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! implementation of the RHRDAC121 DAC
//! datasheet: <https://www.st.com/resource/en/datasheet/rhrdac121.pdf>
//!
use styx_core::peripheral_clients::spi::SPIDevice;

pub struct RHRDAC121 {
    /// output voltage
    v_out: f64,
    /// shift register to read data into
    shift_reg: u16,
    /// keeps track of how many bytes we have read into the shift register
    count: usize,
    /// reference voltage, output signal value will be between 0 and vcc
    vcc: f64,
}

impl Default for RHRDAC121 {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RHRDAC121 {
    pub fn new(vcc: Option<f64>) -> Self {
        Self {
            v_out: 0.0,
            shift_reg: 0,
            count: 0,
            vcc: vcc.unwrap_or(5.0),
        }
    }

    fn update_output(&mut self) {
        // 12 bit dac, max value is 4095
        let val = self.shift_reg & 0xFFF;
        let percent_out: f64 = (val as f64) / 4096.0;

        self.v_out = self.vcc * percent_out;
    }
}

impl SPIDevice for RHRDAC121 {
    fn get_name(&self) -> &str {
        "RHRDAC121"
    }

    fn write_data(&mut self, data: u8) {
        self.shift_reg = (self.shift_reg << 8) | data as u16;
        self.count += 1;

        // after every 2 bytes received, read value from shift register
        if self.count == 2 {
            self.update_output();
            self.count = 0;
        }
    }

    fn read_data(&mut self) -> Option<u8> {
        // device has no data out line
        None
    }
}
