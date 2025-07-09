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
use crate::PcodeBackend;
use styx_cpu_type::arch::arm::ArmRegister;
use styx_processor::cpu::CpuBackendExt;
use styx_sync::sync::Mutex;

/// Represents the stack pointer currently selected, holding the deselected stack pointer's value.
#[derive(Debug)]
pub enum SelectedStackPointer {
    /// Sp is aliased to Msp, Psp is held in this struct.
    Main { process: u32 },
    /// Sp is aliased to Psp, Msp is held in this struct.
    Process { main: u32 },
}

impl Default for SelectedStackPointer {
    fn default() -> Self {
        Self::Main { process: 0 }
    }
}

/// Helper for managing Main Stack Pointer and Process Stack Pointer in Armv7-M systems.
///
/// In order to have the pcode execution modify the stack pointer, we always hold (or rather neglect
/// to hold) one stack pointer in the Sp register. So if the CPU is configured to use the Msp, then
/// we only store the Psp in this struct. Any reads/writes to the Msp are instead routed to the Sp
/// held in Pcode register memory.
///
/// Because of this design choice we require minimal syncing with the in-memory Sp and also hold the
/// Stack Pointer Select bit in this struct as well.
///
#[derive(Debug, Default)]
pub struct StackPointerManager {
    stored_stack_pointer: Mutex<SelectedStackPointer>,
}

impl StackPointerManager {
    /// Gets the Msp.
    pub fn get_main(&self, backend: &mut PcodeBackend) -> u32 {
        if let SelectedStackPointer::Process { main } = *self.stored_stack_pointer.lock().unwrap() {
            main
        } else {
            backend.read_register::<u32>(ArmRegister::Sp).unwrap()
        }
    }

    /// Gets the Psp.
    pub fn get_process(&self, backend: &mut PcodeBackend) -> u32 {
        if let SelectedStackPointer::Main { process } = *self.stored_stack_pointer.lock().unwrap() {
            process
        } else {
            backend.read_register::<u32>(ArmRegister::Sp).unwrap()
        }
    }

    /// Sets the Msp.
    pub fn set_main(&self, new_value: u32, backend: &mut PcodeBackend) {
        if let SelectedStackPointer::Process { main } =
            &mut *self.stored_stack_pointer.lock().unwrap()
        {
            *main = new_value;
        } else {
            backend.write_register(ArmRegister::Sp, new_value).unwrap();
        }
    }

    /// Sets the Psp.
    pub fn set_process(&self, new_value: u32, backend: &mut PcodeBackend) {
        if let SelectedStackPointer::Main { process } =
            &mut *self.stored_stack_pointer.lock().unwrap()
        {
            *process = new_value;
        } else {
            backend.write_register(ArmRegister::Sp, new_value).unwrap();
        }
    }

    /// Sets the Stack Pointer Select Bit (spsel).
    ///
    /// This will swap the Sp with the new stack pointer if the aliased stack pointer has changed. False if Msp is aliased to Sp, True if Psp is aliased to sp.
    pub fn set_stack_pointer_select(&self, process_selected: bool, cpu: &mut PcodeBackend) {
        let stored = &mut *self.stored_stack_pointer.lock().unwrap();

        if process_selected {
            if let SelectedStackPointer::Main { process } = stored {
                let main = cpu.read_register::<u32>(ArmRegister::Sp).unwrap();
                cpu.write_register(ArmRegister::Sp, *process).unwrap();

                *stored = SelectedStackPointer::Process { main }
            }
        } else if let SelectedStackPointer::Process { main } = stored {
            let process = cpu.read_register::<u32>(ArmRegister::Sp).unwrap();
            cpu.write_register(ArmRegister::Sp, *main).unwrap();

            *stored = SelectedStackPointer::Main { process }
        }
    }

    /// Gets the Stack Pointer Select Bit (spsel). False if Msp is aliased to Sp, True if Psp is
    /// aliased to sp.
    pub fn get_stack_pointer_select(&self) -> bool {
        match *self.stored_stack_pointer.lock().unwrap() {
            SelectedStackPointer::Main { process: _ } => false,
            SelectedStackPointer::Process { main: _ } => true,
        }
    }
}
