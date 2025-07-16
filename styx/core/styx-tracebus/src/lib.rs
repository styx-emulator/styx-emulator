// SPDX-License-Identifier: BSD-2-Clause
//! This crate provides abstractions for emulator execution tracing

use bitflags::bitflags;
use enum_dispatch::enum_dispatch;
use log::warn;

pub mod event_listener;

mod ipc_impl;
mod null_impl;
pub use crate::ipc_impl::{IPCTracer, TracerReader, TracerReaderOptions, SRB_TRACE_FILE_EXT};
pub use crate::null_impl::NullTracer;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use styx_macros::{styx_event, styx_event_dispatch, Traceable};
pub use styx_sync;
use styx_sync::{lazy_static, sync::atomic::AtomicU64};
use thiserror::Error;

pub extern crate log;

/// Timeout value waiting for events before the API says there are no more events
pub const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout value that informs `trace` how long to wait for an open slot
/// when the buffer is full.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_millis(100);

/// Fixed sized event size in bytes
pub const TRACE_EVENT_SIZE: usize = std::mem::size_of::<BaseTraceEvent>();

/// Type that matches binary serialization of any TraceEvent
pub type BinaryTraceEventType = [u8; TRACE_EVENT_SIZE];

// static, global variables
// don't use these directly, but rather use the macros, such as [`strace`]
lazy_static! {
    /// Global / static reference to an [`TraceProviderImpl`] trace implementation.
    pub static ref STRACE: TraceProviderImpl = tracer_from_env();

    /// Global atomic counter that keeps track of event numbers, 0..u64::MAX (ie
    /// every event that gets traced using [`strace`] gets an event number)
    // Note: technically, EVENT_NUM is not used unless #[cfg(feature = "numbered")], but
    // lazy_static does not play well with the cfg mechanism.
    pub static ref EVENT_NUM: AtomicU64 = AtomicU64::new(0);
}

/// A set of trace configuration variables.
///
/// It's meant to be
/// generic, for any implementation of a trace mechanism. In this way, its
/// a public union of all options for all trace mechanisms.
///
/// All configuration attributes are overridable by environment variables prefixed by `STRACE_`
/// > eg. [`TraceOptions::key`] becomes `STRACE_KEY`
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)] // allow default construction when we do not serialize the entire struct
pub struct TraceOptions {
    /// The trace buffer needs to be identifiable by some key - it can be
    /// specified or it will be assigned.
    pub key: Option<String>,
    /// This item is true if the key should be treated as a is a file system path
    pub key_is_path: bool,
    /// The capacity in bytes of the trace buffer.
    pub size_bytes: u32,
    /// Setting to true triggers a [`TraceError`] if the trace buffer exists.
    /// If set to false, and the key exists, the trace buffer will be attached to
    pub key_exists_ok: bool,
    /// Indicates how long to wait for a buffer-write to succeed. A timeout
    /// indicates the buffer is full and will return a [`TraceError::BufferFull`] error.
    pub send_timeout: Duration,
    /// Wait this long for a buffer read to occur. This indicates that the buffer
    /// is empty (ie there are no un-consumed events).
    pub recv_timeout: Duration,
}

/// Sets up reasonable default values for [`TraceOptions`]. These are currently
/// biased toward the `IPCTracer` trace implmentation.
impl Default for TraceOptions {
    fn default() -> Self {
        TraceOptions {
            key: None,
            key_is_path: true,
            key_exists_ok: false,
            // Memory size (bytes) of ring buffer for trace. This is the MAX
            // supported size.
            //
            // Note: SharedRingBuffer does not account for it's message overhead,
            // which is size_of [`ipmpsc::posix::Header`] + 8.
            // Subtracting 512 leaves room (size_of(posix Header)+8))
            size_bytes: u32::MAX - 512,
            send_timeout: DEFAULT_SEND_TIMEOUT,
            recv_timeout: DEFAULT_RECV_TIMEOUT,
        }
    }
}

/// Trait for implementations that can provide tracing, such as [`IPCTracer`]
#[enum_dispatch]
pub trait TraceProvider {
    /// Write/send a trace event
    /// # Returns
    /// - bool: true if the event was written to the buffer, false if
    ///   it timeed out
    /// - TraceError: if unable to write the message for a reason other than
    ///   timeout (ie buffer full)
    fn trace<T>(&self, item: &T) -> Result<bool, TraceError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Traceable;

    /// Teardown trace facility
    ///
    /// In practice, the trace buffer is 'static, but this method removes the
    /// buffer key and is essential for unit testing
    fn teardown(&self) -> Result<(), TraceError>;

    /// get the key to the provider instance
    fn key(&self) -> String;
}

/// Known `TraceProvider` implementations
#[allow(clippy::enum_variant_names)]
#[enum_dispatch(TraceProvider)]
pub enum TraceProviderImpl {
    IPCTracer,
    NullTracer,
}

/// Env-var to pick which provider backend to use
pub const STRACE_ENV_VAR: &str = "STRACE_PROVIDER";

/// Return the [TraceProvider] based on the value of environment variable `STRACE_PROVIDER`.
/// Supported values are `null` and `srb`
/// - `STRACE_PROVIDER=null` returns [NullTracer] (which essentually does nothing)
/// - `STRACE_PROVIDER=srb` returns [IPCTracer]
/// - `STRACE_PROVIDER unset`, or somthing other than srb or null, returns [IPCTracer]
///
/// Additionally, to provide fine-grained control over [`styx-trace`](crate), it is
/// possible to overide the default options as documented in [`TraceOptions`].
pub fn tracer_from_env() -> TraceProviderImpl {
    let evar = {
        if let Ok(v) = std::env::var("STRACE_PROVIDER") {
            v
        } else {
            "null".to_string()
        }
    };

    if evar == "srb" {
        // build new `TraceOptions` from env variables
        let config = envy::prefixed("STRACE_")
            .from_env::<TraceOptions>()
            .unwrap_or_default();

        // bulid the new trace provider
        match IPCTracer::new(&config) {
            Ok(v) => {
                return TraceProviderImpl::IPCTracer(v);
            }
            Err(e) => {
                // could fail, default to a [NullTracer]
                warn!("failed to init trace: {e}");
                return TraceProviderImpl::NullTracer(NullTracer::default());
            }
        }
    }

    // we default to the NULL provider
    TraceProviderImpl::NullTracer(NullTracer::default())
}

/// The default directory to store strace files. Also see [mkpath].
pub const TRACE_DIR: &str = "/tmp";

/// mkpath encapsulates where trace files/keys are located, but default
/// in `TRACE_DIR/strace_<process_id>_<uuid4>.<ext>`
/// # Args
/// - `base` - if not null, use it as the basename: `TRACE_DIR/<base>.srb` see [`TRACE_DIR`],
/// - `ext` - use ext as the extension
pub fn mkpath(base: Option<String>, ext: &str) -> String {
    let name = match base {
        Some(v) => v,
        _ => format!("strace_{}_{}", std::process::id(), uuid::Uuid::new_v4()),
    };
    format!("{TRACE_DIR}/{name}.{ext}")
}

/// Convenience macro for stracing events.
///
/// # Args
/// - **`event`** an object that implements [`Traceable`]
///   `+` [`Serialize`] `+` [`Deserialize`].
///
/// # Returns
/// - **`true`** if the message was added to trace buffer
/// - **`false`** if the buffer is full and the message could not be written, the
///   and a `log::warn!` message is logged
///
/// # Error handling and fail modes
/// - if an error occurs, a message is logged via [`log::error`]
/// - if the event does not get written because the buffer is full, a message
///   is logged using [`log::warn`] (note, this could very well turn into a
///   rolling/run-away log - something to address at some point.
///
/// # Enabling
/// Events from `strace!` are emitted using a [TraceProvider]. The default
/// behavior is to use a provider as specified in the environment variable
/// `STRACE_PROVIDER`. To provide _opt-in_ semantics, the default provider does
/// not emit events. Setting `STRACE_PROVIDER=srb` will use the
/// [IPCTracer](use crate::ipc_impl::IPCTracer) provider, which enables capturing the
/// emitted events. Anything else will use [NullTracer]. See [tracer_from_env].
///
/// # Example
///
/// ```rust
/// use styx_tracebus::{*};
/// // create an event, set values, then call the macro
/// let event = MemWriteEvent::new();
/// strace!(event);
/// # STRACE.teardown();
/// ```
#[macro_export]
macro_rules! strace {
    ( $root:expr_2021 ) => {{
        let event = {
            let mut c = $root.clone();

            // This imports from std instead of `styx_sync`, else all consumers of this
            // macro would need to directly depend on `styx_sync`
            let __event_num =
                $crate::EVENT_NUM.fetch_add(1, ::std::sync::atomic::Ordering::Acquire);

            c.event_num = __event_num;
            c
        };

        match $crate::STRACE.trace(&event) {
            Err(e) => {
                $crate::log::error!("Failed to send trace: {:?}", e)
            }
            Ok(false) => {
                // buffer full
                $crate::log::warn!("Failed to buffer event: buffer full");
            }
            Ok(true) => {}
        }
    }};
}

/// Trace for BranchEvent
///
/// ```
/// use styx_tracebus::branchevt;
/// use styx_tracebus::{TraceEventType, BranchInfo, BranchEvent, TraceProvider};
/// # let pc: u32 = 0;
/// # let new_pc: u32 = 0;
///
/// branchevt!(pc, new_pc, BranchInfo::CallC);
/// ```
#[macro_export]
macro_rules! branchevt {
    ( $pc:expr_2021, $newpc: expr_2021, $info:expr_2021 ) => {
        $crate::strace!(BranchEvent {
            etype: TraceEventType::BRANCH,
            pc: $pc,
            new_pc: $newpc,
            info: $info,
            ..Default::default()
        })
    };
}

/// Convenience macro to teardown the global static [`STRACE`](static@STRACE).
/// If teardown fails, a message is logged with [`log::error!`].
#[macro_export]
macro_rules! strace_teardown {
    () => {
        match $crate::STRACE.teardown() {
            Err(e) => $crate::log::error!("strace teardown error: {:?}", e),
            _ => (),
        }
    };
}

/// Styx base trace event
#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Traceable)]
#[repr(C)]
pub struct BaseTraceEvent {
    pub event_num: u64,
    pub etype: TraceEventType,
    pub reserved_u16: u16,
    pub pc: u32,
    pub param1: u32,
    pub param2: u32,
}

impl From<&BinaryTraceEventType> for BaseTraceEvent {
    #[inline(always)]
    fn from(buf: &BinaryTraceEventType) -> Self {
        unsafe { std::mem::transmute::<&BinaryTraceEventType, &BaseTraceEvent>(buf) }.to_owned()
    }
}

bitflags! {
    /// Supported EventTypes
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TraceEventType : u16 {
        const CTRL    =     0x0001;
        const INST_FETCH =  0x0002;
        const INST_EXEC =   0x0004;
        const MEM_READ =    0x0008;
        const MEM_WRT =     0x0010;
        const REG_READ =    0x0020;
        const REG_WRITE =   0x0040;
        const BRANCH =      0x0080;
        const INTERRUPT =   0x0100;
        const STM32 =       0x0200;
        const KINETIS21  =  0x0400;
        const POWERQUICC =  0x0800;
        const BLOCK =       0x1000;
        // const TET_RESERVED_2 =  0x2000;
        // const TET_RESERVED_3 =  0x4000;
        // const TET_RESERVED_4 =  0x8000;
        // const TET_RESERVED_5 =  0x2000;

    }
}

impl TraceEventType {
    pub fn is_match(&self, mask: TraceEventType) -> bool {
        (self.bits() & mask.bits()) == self.bits()
    }
}
// makes serde::json deserialize slightly more meaningful
bitflags_serde_shim::impl_serde_for_bitflags!(TraceEventType);

/// Bag of trace-releated errors
#[derive(Error, Debug)]
pub enum TraceError {
    #[error("Unable to attach to buffer: `{0}`")]
    AttachFailed(String),

    #[error("Unable to write item (buffer full): `{0}`")]
    BufferFull(String),

    #[error("Buffer key already exists: `{0}`")]
    BufferKeyExists(String),

    #[error("Unable to create buffer: `{0}`")]
    CreateFailed(String),

    #[error("Unable to open buffer: `{0}`")]
    OpenFailed(String),

    #[error("Unable to read item: `{0}`")]
    ReadFailed(String),

    #[error("Error: `{0}`")]
    StdIoError(String),

    #[error("Unable to teardown trace: `{0}`")]
    TeardownFailed(String),

    #[error("Unable to write item: `{0}`")]
    WriteFailed(String),
}

impl From<std::io::Error> for TraceError {
    fn from(value: std::io::Error) -> Self {
        Self::StdIoError(value.to_string())
    }
}

/// Convenience macro to construct an IPCTracer receiver to process events.
///
/// # Example
/// ```text
/// let mut rx = receiver!(keyfile.as_str());
/// loop {
///     match next_event!(rx, cargs.read_timeout) {
///         {...}
///     }
/// }
/// ```
/// ## See also
/// - [`macro@next_event`]
#[macro_export]
macro_rules! receiver {
    ($Key: expr_2021) => {
        IPCTracer::get_consumer(TracerReaderOptions::new($Key)).unwrap()
    };
}

/// Convenience macro for getting events from an [`IPCTracer`] event buffer.
///
/// Attempt to receive the next event from the receiver (Rx) with timeout (Timeout)
///
/// # Returns
/// A 3-tuple: (error_str, timed_out, event):
///
/// 0         | 1                      | 2
/// ----------|------------------------|-------------------------------
/// error_str | `String`               | non empty if an error occurred
/// timed_out | `bool`                 | true if a timeout occurred
/// event     | `Option<TraceableItem>`| Some([`TraceableItem`])
///
/// # Example
/// ```text
/// let timeout = Duration::from_millis(100);
/// let opts = TracerReaderOptions::new("/tmp/mmfile.srb");
/// let mut rx = IPCTracer::get_consumer(opts).unwrap();
/// match next_event!(rx, timeout) {
///     (_, _, Some(event)) => {...} // got an event
///     (_, true, _)        => {...} // timed out
///     (err, false, None)  => {...} // An error occurred
/// }
/// ```
/// ## See also
/// - [`macro@receiver`]
#[macro_export]
macro_rules! next_event {
    ($Rx: ident, $Timeout:expr_2021) => {
        // If timeout is zero, do a blocking `recv()`. Note that `recv()` and
        // `recv_timeout()` have different return signatures, so this match will
        // normalize the match arms to `Result<Option<T>, Err>`
        match if $Timeout.as_nanos() == 0 {
            match $Rx.zero_copy_context().recv::<BaseTraceEvent>() {
                Err(e) => Err(e),
                Ok(v) => Ok(Some(v)),
            }
        } else {
            $Rx.zero_copy_context()
                .recv_timeout::<BaseTraceEvent>($Timeout)
        } {
            Ok(non_err) => match non_err {
                Some(event) => {
                    let __specific_event: TraceableItem = event.into();
                    ("".to_string(), false, Some(__specific_event))
                }
                None => ("".to_string(), true, None),
            },
            Err(e) => (e.to_string(), false, None),
        }
    };
}

/// Instruction Types
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize, Hash)]
pub enum InsnType {
    #[default]
    Insn,
    PrefetchInsn,
    ParallelInsn,
    SpeculativeInsn,
    TransientInsn,
}

/// Interrupt Types
#[derive(
    PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize, Hash, Clone, Copy, Default,
)]
#[repr(u8)]
pub enum InterruptType {
    #[default]
    IsrEntry,
    IsrExit,
}

/// Specific types of branches used in branch events [`BranchEvent`]
#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[repr(u8)]
pub enum BranchInfo {
    #[default]
    JumpU,
    JumpC,
    CallU,
    CallC,
    RetU,
    RetC,
    InterruptU,
    InterruptC,
    ExceptionU,
    ExceptionC,
    ReturnInterruptU,
    ReturnInterruptC,
    ReturnExceptionU,
    ReturnExceptionC,
    HWLoopU,
    HWLoopC,
}

#[enum_dispatch]
pub trait Traceable {
    fn event_num(&self) -> u64;
    fn event_type(&self) -> TraceEventType;
    fn json(&self) -> String;
    fn text(&self) -> String;
    fn binary(&self) -> &BinaryTraceEventType;
}

#[styx_event_dispatch(BaseTraceEvent, Traceable)]
/// Associates each event's [`TraceEventType`] and creates
/// an [`enum_dispatch::enum_dispatch`] for [`TraceableItem`].
#[derive(Clone, Debug)]
pub enum TraceableItem {
    BlockTraceEvent(TraceEventType::BLOCK),
    BranchEvent(TraceEventType::BRANCH),
    ControlEvent(TraceEventType::CTRL),
    InsnExecEvent(TraceEventType::INST_EXEC),
    InsnFetchEvent(TraceEventType::INST_FETCH),
    InterruptEvent(TraceEventType::INTERRUPT),
    Kinetis21Event(TraceEventType::KINETIS21),
    MemReadEvent(TraceEventType::MEM_READ),
    MemWriteEvent(TraceEventType::MEM_WRT),
    PowerQuiccEvent(TraceEventType::POWERQUICC),
    RegReadEvent(TraceEventType::REG_READ),
    RegWriteEvent(TraceEventType::REG_WRITE),
    Stm32Event(TraceEventType::STM32),
}

/// Event representing entering a basic block.
#[styx_event(etype=TraceEventType::BLOCK)]
pub struct BlockTraceEvent {
    pub reserved_16: u16,
    pub pc: u32,
    pub size: u32,
    pub reserved_u32: u32,
}
/// Event representing an instruction fetch. Also see [`InsnType`].
#[styx_event(etype=TraceEventType::INST_FETCH)]
pub struct InsnFetchEvent {
    pub reserved_u8: u8,
    pub insn_type: InsnType,
    pub pc: u32,
    // LSbytes of the instruction
    pub insn: u32,
    // MSbytes of the instruction
    pub insn2: u32,
}

/// Event representing an instruction execution. Also see [`InsnType`].
#[styx_event(etype=TraceEventType::INST_EXEC)]
pub struct InsnExecEvent {
    pub reserved_u8: u8,
    pub insn_type: InsnType,
    pub pc: u32,
    // LSbytes of the instruction
    pub insn: u32,
    // MSbytes of the instruction
    pub insn2: u32,
}

/// Event representing a memory read.
#[styx_event(etype=TraceEventType::MEM_READ)]
pub struct MemReadEvent {
    /// size
    pub size_bytes: u16,
    /// program counter
    pub pc: u32,
    // address
    pub address: u32,
    // value read
    pub value: u32,
}

/// Event representing a memory write.
#[styx_event(etype=TraceEventType::MEM_WRT)]
pub struct MemWriteEvent {
    /// size
    pub size_bytes: u16,
    /// program counter
    pub pc: u32,
    // address
    pub address: u32,
    // value written
    pub value: u32,
}

/// Event representing a register read.
#[styx_event(etype=TraceEventType::REG_READ)]
pub struct RegReadEvent {
    /// register index
    pub reg_idx: u16,
    /// program counter
    pub pc: u32,
    /// value of register read
    pub value: u32,
    /// reserved u32 (0)
    pub reserved_u32: u32,
}

/// Event representing a register write.
#[styx_event(etype=TraceEventType::REG_WRITE)]
pub struct RegWriteEvent {
    /// register index
    pub reg_idx: u16,
    /// program counter
    pub pc: u32,
    /// value of register write
    pub value: u32,
    /// value before written
    pub old_value: u32,
}

/// Event representing a code branch, See also: [`BranchInfo`]
#[styx_event(etype=TraceEventType::BRANCH)]
pub struct BranchEvent {
    pub reserved_u8: u8,
    pub info: BranchInfo,
    /// program counter (before branch)
    pub pc: u32,
    /// program counter of branch
    pub new_pc: u32,
    /// empty field
    pub reserved_1: u32,
}

/// A control event. This can be used to send an event arbitrary in nature
#[styx_event(etype=TraceEventType::CTRL)]
pub struct ControlEvent {
    pub reserved_u16: u16,
    pub reserved_1: u32,
    pub reserved_2: u32,
    pub reserved_3: u32,
}

/// An event describing in interrupt action
#[styx_event(etype=TraceEventType::INTERRUPT)]
pub struct InterruptEvent {
    pub reserved_u8: u8,
    pub interrupt_type: InterruptType,
    /// interrupt number, [`i32`] as some architectures
    /// have negative interrupt numbers
    pub interrupt_num: i32,
    pub old_pc: u32,
    pub new_pc: u32,
}

/// Stm32 ...
#[styx_event(etype=TraceEventType::STM32)]
pub struct Stm32Event {
    pub reserved_u16: u16,
    pub reserved_1: u32,
    pub reserved_2: u32,
    pub reserved_3: u32,
}

/// Kinetis21 ...
#[styx_event(etype=TraceEventType::KINETIS21)]
pub struct Kinetis21Event {
    pub reserved_u16: u16,
    pub reserved_1: u32,
    pub reserved_2: u32,
    pub reserved_3: u32,
}

/// Stm32 ...
#[styx_event(etype=TraceEventType::POWERQUICC)]
pub struct PowerQuiccEvent {
    pub reserved_u16: u16,
    pub reserved_1: u32,
    pub reserved_2: u32,
    pub reserved_3: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;
    #[test]
    fn test_binary_serde_c() {
        let mut event = InsnFetchEvent::new();
        event.reserved_u8 = 0b0101_0101;
        event.pc = 0xdead_beef;
        event.insn = 0xff00_00ff;
        event.insn2 = 0xface_cafe;
        let orig_event = event.clone();
        assert_eq!(event, orig_event);

        let traceable_item = TraceableItem::InsnFetchEvent(event);
        let item_bytes = traceable_item.binary();
        assert_eq!(item_bytes.len(), std::mem::size_of::<InsnFetchEvent>());

        let deserialized_traceable_item = TraceableItem::from(unsafe {
            std::mem::transmute::<[u8; 24], BaseTraceEvent>(*item_bytes)
        });
        if let TraceableItem::InsnFetchEvent(deser_event) = deserialized_traceable_item {
            assert_eq!(deser_event, orig_event, "Incorrect deserialize");
        } else {
            panic!("Unexpected variant after deserialize")
        }
    }
    #[test_case(MemReadEvent::new().into(),
                TraceEventType::MEM_READ  ;
                "One type")]
    #[test_case(MemReadEvent::new().into(),
                TraceEventType::MEM_READ | TraceEventType::MEM_WRT ;
                "More than one type")]
    fn test_match(e: TraceableItem, mask: TraceEventType) {
        assert!(e.event_type().is_match(mask));
    }
    #[test_case(InsnExecEvent::new().into(),
                TraceEventType::MEM_READ  ;
                "One type no match")]
    #[test_case(InsnExecEvent::new().into(),
                TraceEventType::MEM_READ | TraceEventType::MEM_WRT ;
                "More than one type no match")]
    fn test_no_match(e: TraceableItem, mask: TraceEventType) {
        assert!(!e.event_type().is_match(mask));
    }
    #[test]
    fn test_type_ok() {
        assert_eq!(MemReadEvent::new().etype, TraceEventType::MEM_READ);
        assert_eq!(InsnExecEvent::new().etype, TraceEventType::INST_EXEC);
    }
}
