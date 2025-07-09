// SPDX-License-Identifier: BSD-2-Clause
pub mod arm {
    pub use styx_gic;
    pub use styx_nvic;
}

pub mod ppc {
    pub use styx_mpc866m;
}

// re-export an event controller that does nothing
pub use styx_core::event_controller::DummyEventController;
// re-export an event peripheral that does nothing
pub use styx_core::event_controller::DummyPeripheral;
