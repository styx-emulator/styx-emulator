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
//! The ['Pin'] abstraction represents an individual pin within a GPIO port on a target device.
//! Pins can be individually set, cleared, toggled and configured.

/// Represents an individual pin within a GPIO port on a target device.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Pin {
    /// pin number
    pno: u32,
    /// pin mode (i.e. input/output)
    mode: PinMode,
    /// is the pin set
    is_set: bool,
    /// A mask for checking the register value for this pin.
    pub mask: u32,
}

impl Pin {
    /// Construct a new `struct Pin` with pno as the pin number (pno).
    pub fn new(pno: u32) -> Self {
        Self {
            pno,
            mask: 1 << pno,
            mode: PinMode::Input,
            is_set: false,
        }
    }

    /// Is the pin in some input mode?
    #[inline]
    pub fn is_input(&self) -> bool {
        self.mode == PinMode::Input
    }

    /// Is the pin in some output mode?
    #[inline]
    pub fn is_output(&self) -> bool {
        self.mode == PinMode::Output
    }

    #[inline]
    pub fn is_set(&self) -> bool {
        self.is_set
    }

    #[inline]
    pub fn set_to_input(&mut self) {
        self.mode = PinMode::Input;
    }

    #[inline]
    pub fn set_to_output(&mut self) {
        self.mode = PinMode::Output;
    }

    #[inline]
    pub fn clear_bit(&mut self) {
        self.is_set = false;
    }

    #[inline]
    pub fn set_bit(&mut self) {
        self.is_set = true;
    }

    #[inline]
    pub fn toggle_bit(&mut self) {
        self.is_set = !self.is_set;
    }
}

/// Represents the configured mode of a [`Pin`].
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum PinMode {
    Input = 0,
    Output = 1,
}

impl std::fmt::Display for PinMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PinMode::Input => write!(f, "Input"),
            PinMode::Output => write!(f, "Output"),
        }
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.pno, self.mode, self.is_set)
    }
}
