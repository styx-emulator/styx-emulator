// SPDX-License-Identifier: BSD-2-Clause
//! Implements the Communications Processor Module (CPM)
//! as defined by the MPC8XX Family Reference Manual.
//!
//! To add more complexity to the emulation of the PowerQUICC family, the I/O
//! is brokered through the `Communication Processor Module`. Which is its own
//! RISC processor, with its own set of configurable interrupts, features, and
//! options for controlling the peripherals.
//!
//! The majority of communication with the `CPM` is performed either via the
//! `CPCR` (Communication Processor Control Register), or through shared memory
//! in one of:
//! - Dual-port system RAM
//! - Parameter RAM
//! - Dual-port extension RAM
//!
//! All peripherals have default areas for configuration in multiple places:
//! - `IMMR` registers
//! - Default Parameter RAM locations (offsets + custom options into Parameter RAM)
//! - `N` Buffer Descriptors (64 bit descriptor struct)
//!     - location is specified in the Parameter RAM for the peripheral
//!
//! Before getting into details it'd be good to provide some example communication
//! pathways between the host and the communications processor since it gets pretty
//! confusing in the manuals. So much so in fact, that the manufacturer released
//! an addendum [here](https://www.nxp.com/docs/en/application-note/AN2059.pdf),
//! which is restated here (in more accurate terms) for dead-link-avoidedness:
//!
//! # Host / CPM Interaction Example (via SCC)
//!
//! ## Types of communication
//!
//! The interactions can be split into 4 different categories:
//!
//! - Host Commands from CPU
//!   - Change state of SCC Channel
//!   - Initialize SCC Channel
//!   - Consist of microcode routines which change state of microcode
//!     or SCC state machine
//! - Buffer Descriptors
//!   - Give CPM data to transmit
//!   - Tell CPM where to store received data
//!   - Report Tx or Rx errors
//! - Event Registers
//!   - Hardware or microcode generated events
//!   - Can generate an interrupt to the CPU
//! - Configuration registers
//!   - Determine the operating mode of the SCC
//!   - Generate clock signals
//!   - Determine the physical interface
//!
//! ## User visible PRAM Debugging Tips
//! - Best two PRAM's to check are `RBPTR` and `TBPTR`, in many
//!   "problem situations," they are not pointing at the buffers at all
//! - `T_PTR` and `R_PTR` changing indicate Tx/Rx respectively
//! - `R_CNT` and `T_CNT` are set when the respective `BD` is opened
//!
//! ## What the CPM SCC Commands Really Do
//! | Opcode | Command | Description |
//! |--------|---------|-------------|
//! | 0000   | INIT RX AND TX PARAMS | see below |
//! | 0001   | INIT RX PARAMS | Copies `R_BASE` to `RBPTR` and sets `RSTATE` to zero |
//! | 0010   | INIT TX PARAMS | Copies `T_BASE` to `TBPTR` and sets `TSTATE` to zero |
//! | 0011   | ENTER HUNT MODE | Issues a command to the channel to look for an IDLE or FLAG and ignore all incoming data |
//! | 0100   | STOP TX | Tells the various Tx routines to take requests but not send anymore data |
//! | 0101   | GRACEFUL STOP TX | Tells the various Tx routines to transmit the end of the current buffer/frame and then perform STOP TX |
//! | 0110   | RESTART TX | Allows Tx routines to send data again |
//! | 0111   | CLOSE RX BD | Closes the current BD if data has been received into it, else does nothing |
//! | 1000   | SET GROUP ADDRESS | (Ethernet) Sets a hash table bit for the Ethernet logical group address recognition function. |
//! | 1001   | - | - |
//! | 1010   | RESET BCS | (Ethernet) In BISYNC mode will reset the block check sequence calculation |
//! | 1011   | - | - |
//! | 1100   | undefined | - |
//! | 1101   | undefined | - |
//! | 1110   | undefined | - |
//! | 1111   | only applicable in ATM PTP mode (manual section 38.4 -> 38.7) | - |
//!
//! ## How a Frame Gets Transmitted
//!
//! NOTE: FIFO's are 32-bits on SCC1 only, others are 16 bits, UART mode is 8-bits
//!
//! 1) CPM looks at the `BD` pointed to by `TBPTR`
//!   - if the INIT TX PARAMETERS command was not issued, `TBPTR`
//!     will probably be pointing to garbage
//! 2) CPM detects ready bit has been set
//!   - After the SCC goes idle, the CPM polls the ready bit every 128 Tx cycles
//!     for Ethernet, 64 Tx cycles for HDLC/Transparent and every character
//!     time for UART
//! 3) CPM copies buffer length to `T_CNT` (temporary count), and copies
//!    starting address to `T_PTR` (temporary pointer)
//!   - "This step is your clue that TX clocks are working!! Check parallel
//!     port pins and clocking configuration"
//! 4) CPM does an SDMA cycle to get the first 32-bits of transmit data
//!   - "You can set a special function code to see this happen on the bus.
//!     If it doesn't happen, the SDMA arbitration priority might not be high
//!     enough, check SDCR"
//! 5) CPM decrements `T_CNT` and increments `T_PTR`
//!   - This means the transmit FIFO is starting to be filled.
//!   - The `TSTATE` should no longer be zeros
//! 6) When TX FIFO contains at least 8 bytes, the idles or flags should stop
//!   being transmitted, and real data should be seen on the TXD pin
//!   - In UART mode this starts as soon as one character is in the FIFO
//!   - NOTE: the CTS pin can prevent data from transmitting if the user
//!     programmed it as a sync, and never asserted CTS
//!   - If the Time Slot Assigner (TSA) does not see a sync, then no data
//!     will transmit (N/A on MPC852T due to lack of TSA as per Appendix H)
//!   - If data still does not transmit, try internal loopback mode to
//!     eliminate the data and control pins as a source of the problem
//! 7) As soon as there is one 32-bit FIFO entry available (one character in
//!    UART mode), the SCC generates a request to the CPM Interupt Controller.
//!    The request remains asserted until the FIFO becomes full or the last byte
//!    of the frame is written to the FIFO
//!   - This is intended to provide maximum bus latency [?], minimum bus latency
//!     allowed is therefore the time it takes to fill N-4 bytes, where N is the
//!     number of bytes in the FIFO (32 for SCC1, 16 for others)
//! 8) CPM will use multiple buffers to transmit frame if needed
//!   - Make sure all buffers are "ready" before the first BD.ready bit is set,
//!     else there might be an underrun between buffers. In this case TXE is set
//!     but there is no BD in which to report the underrun [undefined behavior??]
//!   - Use the `TBPTR` to watch the CPM progress through the BD's
//! 9) After the entire frame is transmitted, the CPM will check the next BD's
//!    ready bit immediately. If 0, it will go back into Tx clock poll mode as
//!    described in step 2.
//!
//! ## How a Frame Gets Received
//!
//! 1) CPM received 32-bits [ FIFO element length ] of data from RX FIFO
//!   - this step is not observable by the user
//! 2) CPM looks at the BD pointed to by `RBPTR`
//!   - If the INIT RX PARAMETERS command was not executed, the `RBPTR`
//!     probably points to garbage
//! 3) CPM checks that the Empty bit has been set
//!   - this step is not observable by the user
//! 4) CPM copies buffer length to `R_CNT` (temporary count), and
//!    copies starting address to `R_PTR` (temporary pointer)
//!   - "This step is your clue that the RX clocks are working!!
//!     Check parallel port pins and clocking configuration"
//!   - Echo mode can be used to check the SCC hardware without involving the
//!     CPM
//! 5) CPM does an SDMA cycle to write the first 32-bits [ FIFO item len ] of
//!    Rx data
//!   - You can set a special function code to see this happen on the bus. If
//!     it doesn't happen the SDMA arbitration priority might not be high enough,
//!     check SDCR
//! 6) CPM decrements `R_CNT` and increments `R_PTR`
//!   - This means that the receive buffer is starting to be filled out. The
//!     `RSTATE` value should no longer be zeros
//! 7) As soon as there is one 32-bit entry of the Rx FIFO that is available,
//!    a request is generated to the CPM Interrupt Controller.
//!   - This is intended to provide the maximum bus latency
//!   - The minimum bus latecny allowed it therefore the time it takes to fill
//!     N-4 bytes, where N is the number of bytes in the FIFO (32 for SCC1,
//!     16 for others)
//! 8) CPM will use multiple buffers to receive a frame if needed
//!   - Use `RBPTR` to watch the CPM progress through the BD's
//!
//! NOTE: opening and closing BD's is *expensive*, very expensive
//!
//! ## SDMA Behavior
//! - The SCC SMDA channels do not burst in order to be compatible with the `68360`
//! - The SDMA channels do cycle stealing
//! - The user will never see two back-to-back SDMA cycle steal cycles
//!   (ie SCC1 Tx immediately followed by SCC2 Tx). There will always be a
//!   few clocks inbetween
//! - If the SDMA is moving a 32-bit value to a smaller port, such as 16-bits,
//!   the user will see back-to-back 16-bit cycles
//! - On Tx, the SDMA will either read 16 or 32-bits at the start of a
//!   frame depending on the starting address.
//!     - if a 16-bit read is sufficient, the SDMA will only read 16-bits
//! - It then throws away one of the bytes if it does not need all of them
//! - Then for the rest of the transfers, the SDMA will always read 32-bits at
//!   a time
//!
//! NOTE: the SDMA only reads 16-bits at a time in UART mode, and never reads 32-bits
//!
//! # CPM to Host Communication
//!
//! ## Dual-Port RAM
//!
#![cfg_attr(feature = "docimages",
cfg_attr(all(),
doc = ::embed_doc_image::embed_image!("dual_port_memory_map", "assets/dual_port_memory_map.png"),))]
#![cfg_attr(
    not(feature = "docimages"),
    doc = "**Doc images not enabled**. Compile with feature `docimages` and Rust version >= 1.54 \
           to enable."
)]
//!
//! ![dual_port_memory_map][dual_port_memory_map]
//!
//! The dual-port RAM consists of 7 Kbytes of system RAM (see Section 18.7.1, “System RAM and
//! Microcode Packages”) and 1 Kbyte of parameter RAM (see Section 18.7.3, “Parameter RAM”) and is
//! used for:
//! - Storing parameters associated with the SCCs, SMCs, SPI, I 2 C, and IDMAs (in parameter RAM
//!   only)
//! - Storing the BDs (in any unused dual-port RAM area)
//! - Storing buffers (in any unused dual-port RAM area or external memory)
//! - Storing Freescale-supplied microcode for the CP (in system RAM only)
//! - Scratch pad area for user software (in any unused dual-port RAM area)
//!
//! ## Buffer Descriptors (BD's)
//!
//! The SCCs, SMCs, SPI, IDMA, PIP, and I 2 C use buffer descriptors (BDs) to define the interface to buffers.
//! BDs can be placed in any unused area of the dual-port RAM. In general all BD's follow this structure,
//! however the specific fields details are specific to the peripheral implementation
//!
//! | BD Base Offset | Field |
//! |----------------|-------|
//! | 0x00 | Status and Control |
//! | 0x02 | Data Length (capped at 0xFFFF) |
//! | 0x04 | High-order of buffer pointer |
//! | 0x06 | Low-order of buffer pointer |
//!
//! ## Parameter RAM
//! The CPM maintains a section of dual-port RAM called the parameter RAM. It contains parameters for
//! SCC, SMC, SPI, I 2 C, and IDMA channel operation shown below, each respective area is defined in the
//! corresponding sections of the manual
//!
#![cfg_attr(feature = "docimages",
cfg_attr(all(),
doc = ::embed_doc_image::embed_image!("pram_map", "assets/pram_map.png"),))]
#![cfg_attr(
    not(feature = "docimages"),
    doc = "**Doc images not enabled**. Compile with feature `docimages` and Rust version >= 1.54 \
           to enable."
)]
//!
//! ![pram_map][pram_map]
//!
//! NOTE: The SPI and I2C PRAM areas can be relocated for use cases when ATM mode or UTOPIA interfaces
//! are being utilized. They can be relocated to other 32-byte aligned parameter areas in
//! dual-port RAM by programming their 16-bit base offsets like so:
//!
#![cfg_attr(feature = "docimages",
cfg_attr(all(),
doc = ::embed_doc_image::embed_image!("pram_reloc", "assets/pram_reloc.png"),))]
#![cfg_attr(
    not(feature = "docimages"),
    doc = "**Doc images not enabled**. Compile with feature `docimages` and Rust version >= 1.54 \
           to enable."
)]
//!
//! ![pram_reloc][pram_reloc]
//!
//! ## CPM to Host External Interrupt
//!
//! ### Example External Interrupt Service Routine Flow
//!  (sourced from an unknown header file found on google at some point)
//! The following are the steps, in order, taken by the External Interrupt
//! Table Code:
//!
//! 1) Save following Registers:  gpr0, gpr3-gpr12, CR, XER, LR, CTR
//!    on stack as necessary to preserve user state across the interrupt
//!    handler.  Save SRR0, SRR1 to provide breakpoint/debug support for
//!    Interrupt Code.
//! 2) The exception vector (0x500) is saved in register r3.
//! 3) Absolute Branch and Link to C routine to complete interrupt processing.
//! 4) Restore Registers in (1) from stack.
//! 5) Execute rfi instruction to return from supervisor-state interrupt handler.
//!
//! # CPM to Peripherals
//!
//! The CP uses the peripheral bus to communicate with the peripherals. The serial communications
//! controllers (SCCs) have separate receive and transmit FIFOs. The SCC1 receive and transmit FIFOs are
//! 32 bytes each; SCC2–SCC4 FIFOs are 16 bytes each. The serial management controllers (SMCs), serial
//! peripheral interface (SPI), and I2C are all double-buffered, creating affective FIFO sizes of two
//! characters.The parallel interface port (PIP) is a single register interface.
//!
//! ## Peripheral Prioritization on the Data Bus
//!
//! Priority | Request
//! ---------|---------
//!    1     | Reset in the `CPCR` or `!SRESET`
//!    2     | `SDMA` bus error
//!    3     | Commands issued to the `CPCR`
//!    4     | `IDMA` emulation: `!DREQ0` (default -- option 1)
//!    5     | `IDMA` emulation: `!DREQ1` (default -- option 1)
//!    6     | `SCC1 Rx`
//!    7     | `SCC1 Tx`
//!    8     | `SCC2 Rx`
//!    9     | `SCC2 Tx`
//!    10    | `SCC3 Rx`
//!    11    | `SCC3 Tx`
//!    12    | `SCC4 Rx`
//!    13    | `SCC4 Tx`
//!    14    | `IDMA` emulation: `!DREQ0` (option 2)
//!    15    | `IDMA` emulation: `!DREQ1` (option 2)
//!    16    | `SMC1 Rx`
//!    17    | `SMC1 Tx`
//!    18    | `SMC2 Rx`
//!    19    | `SMC2 Tx`
//!    20    | `SPI Rx`
//!    21    | `SPI Tx`
//!    22    | `I2C Rx`
//!    23    | `I2C Tx`
//!    24    | `PIP`
//!    25    | `RISC timer table`
//!    26    | `IDMA` emulation: `!DREQ0` (option 3)
//!    27    | `IDMA` emulation: `!DREQ1` (option 3)
//!
//! Note: all `IDMA` emulation options are configurable via `RCCR` (Section 18.6.1)
//!
use super::Mpc8xxVariants;
use derive_more::Display;
use enum_dispatch::enum_dispatch;
use styx_core::errors::StyxMachineError;
use styx_core::prelude::Peripheral;
use styx_core::sync::sync::{Arc, Weak};
use thiserror::Error;
use tracing::trace;

use super::peripherals::clocks::{PllClock, SystemControlClock};
mod cpm_inner;
pub use cpm_inner::*;

#[allow(unused_imports)]
#[cfg(feature = "docimages")]
use embed_doc_image::embed_doc_image;

#[derive(Debug, Error)]
pub enum CpmError {
    #[error("Idx `{0}`is not valid")]
    BadInitIdx(usize),
    #[error("Data size: `{0}` is not compatible with event: `{1}`")]
    EventDataSize(usize, CpmEventSelector),
    #[error("Error constructing event for `{0}`: `{1}")]
    PeripheralEventInit(&'static str, &'static str),
}

/// Events from shared memory with the emulated Host processor,
/// this trait is monomorphized into the [`CpmEventType`] enum,
/// and all implementors should also implement a pub method with
/// the signature
/// ```ignore
/// fn from_data(data: &[u8]) -> Result<Self, CpmError>;
/// ```
///
/// that can be used like so:
///
/// ```rust
/// # use styx_powerquicci_processor::communications_processor::CpmCicrEvent;
/// let evt = CpmCicrEvent::from_data(&vec![0]);
/// ```
#[enum_dispatch]
pub trait CpmEvent: PartialEq + Eq + std::fmt::Debug + std::fmt::Display {
    fn to_bytes(&self) -> Vec<u8>;
}

/// This *must* be kept in sync with the variants of [`CpmEventType`]
#[derive(Debug, Display, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub enum CpmEventSelector {
    CpmCicrEvent,
}

#[derive(PartialEq, Eq, Debug)]
#[enum_dispatch(CpmEvent)]
#[derive(Display)]
pub enum CpmEventType {
    CpmCicrEvent,
}

impl CpmEventType {
    pub fn from_data(variant: CpmEventSelector, data: &[u8]) -> Result<Self, CpmError> {
        let maybe_evt = match variant {
            CpmEventSelector::CpmCicrEvent => CpmCicrEvent::from_data(data),
        };

        match maybe_evt {
            Ok(evt) => Ok(evt.into()),
            Err(err) => Err(err),
        }
    }
}

pub trait CpmPeripheral: std::fmt::Debug + Peripheral {
    fn process_event(&self, evt: CpmEventType) -> Result<(), CpmError>;
    fn reset(&self) -> Result<(), CpmError>;
    // todo: make this logic fall into `process_event`
    fn process_cpm_opcode(&self, opcode: CpmOpcode) -> Result<(), CpmError>;
    fn new_arc(
        variant: Mpc8xxVariants,
        cpm: Weak<CommunicationsProcessorModule>,
        idx: Option<usize>,
    ) -> Result<Arc<Self>, CpmError>
    where
        Self: Sized;
}

#[derive(Debug, Display, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub enum CpmOpcode {
    InitTxRxParams,
    InitRxParams,
    InitTxParams,
    EnterHuntMode,
    StopTx,
    GracefulStopTx,
    RestartTx,
    CloseRxBd,
    InitIdma,
    StopIdma,
    SetTimer,
    SetGroupAddress,
    GciAbortRequest,
    GciTimeout,
    ResetBcs,
    Undefined,
    AtmCommand,
}

/// This is a container that wraps all of the peripherals that have
/// communication brokered through the Communications Processor Module
///
/// The CPM has its internal implementation, as well as its own interrupt
/// controller and series of timers implemented in [`CommunicationsProcessorInner`].
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct CommunicationsProcessorModule {
    weak_ref: Weak<CommunicationsProcessorModule>,
    peripherals: Vec<Arc<dyn CpmPeripheral>>,
}

unsafe impl Send for CommunicationsProcessorModule {}
unsafe impl Sync for CommunicationsProcessorModule {}

impl CommunicationsProcessorModule {
    /// All peripherals to be controlled by the Comunications Processor
    /// should go here, specifically:
    /// - SMDA / IDMA
    /// - SI
    /// - SCC
    /// - SMC
    /// - SPI
    /// - I2C
    /// - PIP
    /// - P I/O
    /// - CPM Inner Implementation:
    ///   - CPM Interrupt Controller
    ///   - CPM Proper
    ///   - CPM Timers
    fn build_peripherals(
        variant: Mpc8xxVariants,
        cpm_ref: Weak<CommunicationsProcessorModule>,
    ) -> Vec<Arc<dyn CpmPeripheral>> {
        vec![
            CommunicationsProcessorInner::new_arc(variant, cpm_ref.clone(), None).unwrap(),
            PllClock::new_arc(variant, cpm_ref.clone(), None).expect("Failed to make PllClock"),
            SystemControlClock::new_arc(variant, cpm_ref.clone(), None)
                .expect("Failed to make SystemControlClock"),
        ]
    }

    pub fn new_arc(variant: Mpc8xxVariants) -> Result<Arc<Self>, StyxMachineError> {
        trace!("CommunicationsProcessorModule::new_arc({})", variant);

        Ok(Arc::new_cyclic(|me| Self {
            weak_ref: me.clone(),
            peripherals: Self::build_peripherals(variant, me.clone()),
        }))
    }
}
