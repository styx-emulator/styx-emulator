// SPDX-License-Identifier: BSD-2-Clause

use std::collections::HashMap;
use std::sync::Arc;

use crate::HexagonConfigTable;
use derivative::Derivative;
use styx_core::event_controller::ExceptionNumber;
use styx_core::macros::ProcessorConfig;
use styx_core::sync::styx_async::sync::broadcast;

#[derive(Derivative)]
#[derivative(Default)]
pub struct QTimerConfig {
    /// In qemu-hexagon-testing: See qtimer.c in standalone_systests/src,
    /// and IRQ1/IRQ2 values in cmake/hexagon-standalone.cmake
    /// Firmware uses IRQ 2: TODO set this.
    // 2 on modems and 3 everywhere else
    #[derivative(Default(value = "3"))]
    pub irq: ExceptionNumber,
    #[derivative(Default(value = "19200000"))]
    pub timer_frequency: u32,
    /// The default value, 800, is possibly "accelerated"
    #[derivative(Default(value = "800"))]
    pub pcycles_per_packet: u64,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct L2VicConfig {
    /// L2Vic has multiple interrupts connected to the main DSP, and they start at 2. The
    /// Based on the IRQ, we read a different "Vid" register to get the actual interrupt number
    /// from peripheral to interrupt controller.
    #[derivative(Default(value = "2"))]
    pub vid_irq_base: u64,
    /// The fastl2vic peripheral is implemented alongside the l2vic.
    #[derivative(Default(value = "0x57e0000"))]
    pub fastl2vic_base: u64,
}

#[derive(ProcessorConfig, Derivative)]
#[derivative(Default)]
pub struct HexagonProcessorConfig {
    #[derivative(Default(value = "729600000"))]
    pub dsp_freq: u32,
    #[derivative(Default(value = "0xfc900000"))]
    pub subsystem_base: u64,
    #[derivative(Default(value = "0xd8380000"))]
    pub cfgbase: u64,
    #[derivative(Default(value = "192"))]
    pub tlb_entries: u32,
    #[derivative(Default(value = "4"))]
    pub hardware_threads: u32,

    /// Config table values. Will eventually be removed when the config is integrated into the peripherals.
    pub config_table: HashMap<HexagonConfigTable, u32>,

    /// Peripherals
    pub qtimer_config: QTimerConfig,
    pub l2vic_config: L2VicConfig,

    /// Output
    ///
    /// This is for things like semihosting output, any sort of
    /// debugging/tracing output put in shared memory between AP and CP
    /// UART, etc.
    pub semihosting_tx: Option<Arc<broadcast::Sender<u8>>>,
}
