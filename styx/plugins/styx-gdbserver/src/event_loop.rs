// SPDX-License-Identifier: BSD-2-Clause
//! Controls I/O and event processing between with the gdb client and target processor.
//!
//! [`EmuGdbEventLoop`] implements
//! [the blocking event loop trait](https://docs.rs/gdbstub/0.6.6/gdbstub/stub/run_blocking/trait.BlockingEventLoop.html)
//! from gdbstub. It's created and used by the [GdbExecutor](crate::plugin::GdbExecutor).
use crate::target_impl::TargetImpl;
use gdbstub::common::Signal;
use gdbstub::conn::Connection;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::Target;
use num_traits::FromPrimitive;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::{net::TcpListener, os::unix::net::UnixListener};
use styx_core::cpu::TargetExitReason;
use styx_core::sync::sync::{Arc, Mutex};
use tracing::debug;

/// The variants enumerated here are the specific event that caused target
/// emulation to stop, for reasons related to debugging
#[derive(Debug, Clone)]
pub enum Event {
    /// the emulator hit a break point (`gdb break`)
    Break,
    /// A step was just executed
    DoneStep,
    /// Target Exit status propagated from the inner `CpuEngine`
    Exited(Result<TargetExitReason, TargetExitReason>),
    /// the emulator was halted for some programmatic reason
    #[allow(dead_code)] // Not currently supported
    Halted,
    /// something in styx has called Processor::cpu_stop()
    StyxStoppedCpu,
    /// the emulator hit a _read_ watch point (`gdb rwatch`)
    #[allow(dead_code)] // currently only track `WatchWrite` events
    WatchRead(u64),
    /// the emulator hit a _write_ watch point (`gdb watch`)
    WatchWrite(u64),
}

/// Variants which allow matching some [Event] or incoming gdb client data
pub enum RunEvent {
    /// some event from [Event] (target debugee event)
    Event(Event),
    /// gdb serial protocol is available for reading (event from client)
    IncomingData,
}

/// Zero-sized type that implements the event loop for [`gdbstub`]
///
/// TODO: when rust has stable const trait fn's and a stronger const system,
/// the complexity of managing the generic types will get much easier,
/// currently the event loop must be generic over the target architecture
/// implementation because the concept of a `target` in [`gdbstub`] is generic
/// over the target implmentation.
pub(crate) enum EmuGdbEventLoop<GdbArchImpl> {
    /// Workaround for type specifiers in enums
    /// <https://github.com/rust-lang/rust/issues/32739#issuecomment-627765543>
    _Foo(Infallible, PhantomData<GdbArchImpl>),
}

/// Implements
/// [the blocking event loop trait](https://docs.rs/gdbstub/0.6.6/gdbstub/stub/run_blocking/trait.BlockingEventLoop.html)
/// from gdbstub, for
/// - [TargetImpl]
/// - [Connection](GdbSerialConn)
impl<'a, GdbArchImpl> run_blocking::BlockingEventLoop for &'a EmuGdbEventLoop<GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    type Target = TargetImpl<'a, GdbArchImpl>;
    type Connection = GdbSerialConn;
    type StopReason = SingleThreadStopReason<GdbArchImpl::Usize>;

    /// Block waiting for the Cpu to stop.
    /// called by gdbstubs [run_blocking], we are here for the lifetime of
    /// the gdb client connection, either waiting for user commands or waiting
    /// for the processor to stop for some reason (finished a step, killed,
    /// stopped because of a watch point, etc.)
    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<SingleThreadStopReason<GdbArchImpl::Usize>>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        let poll_incoming_data = || {
            // gdbstub takes ownership of the underlying connection, so the `borrow_conn`
            // method is used to borrow the underlying connection back from the stub to
            // check for incoming data.
            let val = conn.peek().map(|b| b.is_some()).unwrap_or(true);

            if val {
                debug!("peek found data");
            }
            val
        };

        match target.resume(poll_incoming_data) {
            // handle + propagate the client event
            RunEvent::IncomingData => {
                debug!("event loop handling incoming data");
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;
                Ok(run_blocking::Event::IncomingData(byte))
            }

            // handle + propagate the target event
            RunEvent::Event(event) => {
                // translate emulator stop reason into GDB stop reason
                let stop_reason: SingleThreadStopReason<GdbArchImpl::Usize> = match event {
                    Event::DoneStep => SingleThreadStopReason::DoneStep,
                    Event::Halted => SingleThreadStopReason::Terminated(Signal::SIGSTOP),
                    Event::Break => SingleThreadStopReason::SwBreak(()),
                    // map styx host stopping cpu to sigint
                    Event::StyxStoppedCpu => SingleThreadStopReason::Signal(Signal::SIGINT),
                    Event::WatchWrite(addr) => SingleThreadStopReason::Watch {
                        tid: (),
                        kind: WatchKind::Write,
                        addr: FromPrimitive::from_u64(addr).unwrap(),
                    },
                    Event::WatchRead(addr) => SingleThreadStopReason::Watch {
                        tid: (),
                        kind: WatchKind::Read,
                        addr: FromPrimitive::from_u64(addr).unwrap(),
                    },
                    Event::Exited(exit_reason) => {
                        // TODO: at some point it would be nice to propagate the
                        // target exit information, for now just send exit 0 or 1
                        // if there was a success or not
                        // TODO: i think gdb has default errno like BusError
                        // etc. that we can translate our TargetExitReason into,
                        // similar to how gdb-sim does.
                        match exit_reason {
                            Ok(reason) => SingleThreadStopReason::Signal(reason.into()),
                            // XXX on `Generic FFI failure` we need to handle that and exit
                            Err(reason) => SingleThreadStopReason::Signal(reason.into()),
                        }
                    }
                };
                Ok(run_blocking::Event::TargetStopped(stop_reason))
            }
        }
    }

    fn on_interrupt(
        _target: &mut Self::Target,
    ) -> Result<Option<SingleThreadStopReason<GdbArchImpl::Usize>>, <Self::Target as Target>::Error>
    {
        // todo: this is not getting called
        tracing::info!("Stopping the cpu (Ctrl-C)");
        _target.target_cpu().stop();
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

/// Most things return DynResult
pub(crate) type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

/// GDB serial protocol connection
type GdbSerialConn = Box<dyn ConnectionExt<Error = std::io::Error>>;

pub(crate) trait WaitForConnection {
    fn wait_for_connection(&self) -> DynResult<GdbSerialConn>;
    fn bind(&self) -> DynResult<()>;
}

/// Container holding necessary metadata to initiate a listener
/// for a TCP connection
#[derive(Debug)]
pub struct TcpParameters {
    port: u16,
    bind_addr: &'static str,
    verbose: bool,
    assigned_port: Arc<Mutex<u16>>,
    listener: Arc<Mutex<Option<TcpListener>>>,
}

impl TcpParameters {
    fn sockaddr(&self) -> String {
        format!("{}:{}", self.bind_addr, self.port)
    }
}

impl WaitForConnection for TcpParameters {
    fn bind(&self) -> DynResult<()> {
        let mut listener = self.listener.lock().unwrap();

        if listener.is_some() {
            return Err("already have TcpListener")?;
        }

        let tmp_listener = TcpListener::bind(self.sockaddr())?;

        // set port assigned to use
        let port = tmp_listener.local_addr().unwrap().port();
        tracing::debug!("Got port: {}", port);
        *self.assigned_port.lock().unwrap() = port;
        tracing::debug!("Gave TcpParams port");

        *listener = Some(tmp_listener);
        Ok(())
    }

    fn wait_for_connection(&self) -> DynResult<GdbSerialConn> {
        if let Some(tcp_listener) = &*self.listener.lock().unwrap() {
            if self.verbose {
                eprintln!("Waiting for a GDB connection on {:?}...", self.sockaddr());
            }

            // once we have a stream / addr we have a connected client
            let (stream, addr) = tcp_listener.accept()?;
            if self.verbose {
                eprintln!("Debugger connected from {}", addr);
            }

            Ok(Box::new(stream))
        } else {
            Err("no TcpListener")?
        }
    }
}

/// Container holding necessary metadata to initiate a listener
/// for a UDS connection
#[derive(Debug)]
pub struct UdsParameters {
    path: &'static str,
    verbose: bool,
    listener: Arc<Mutex<Option<UnixListener>>>,
}
impl WaitForConnection for UdsParameters {
    fn bind(&self) -> DynResult<()> {
        let mut listener = self.listener.lock().unwrap();

        if listener.is_some() {
            return Err("already have UnixListener")?;
        }

        match std::fs::remove_file(self.path) {
            Ok(_) => {}
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {}
                _ => return Err(e.into()),
            },
        }

        *listener = Some(UnixListener::bind(self.path)?);

        Ok(())
    }

    fn wait_for_connection(&self) -> DynResult<GdbSerialConn> {
        if let Some(uds_listener) = &*self.listener.lock().unwrap() {
            if self.verbose {
                eprintln!("Waiting for a GDB connection on {}...", self.path);
            }

            let (stream, addr) = uds_listener.accept()?;
            if self.verbose {
                eprintln!("Debugger connected from {:?}", addr);
            }

            Ok(Box::new(stream))
        } else {
            Err("no UnixListener")?
        }
    }
}

#[derive(Debug)]
pub struct GdbPluginParams {
    pub tcp: Option<TcpParameters>,
    pub uds: Option<UdsParameters>,
    pub port_in_use: Arc<Mutex<u16>>,
}

impl WaitForConnection for GdbPluginParams {
    fn bind(&self) -> DynResult<()> {
        if let Some(uds) = &self.uds {
            uds.bind()
        } else if let Some(tcp) = &self.tcp {
            tcp.bind()?;

            // set port assigned by operating system
            let port = *tcp.assigned_port.lock().unwrap();
            tracing::debug!("GdbPluginParams got port `{}` from TcpParams", port);
            *self.port_in_use.lock().unwrap() = port;

            Ok(())
        } else {
            Err("Need either UDS or TCP parameters to function")?
        }
    }

    fn wait_for_connection(&self) -> DynResult<GdbSerialConn> {
        if let Some(uds) = &self.uds {
            uds.wait_for_connection()
        } else if let Some(tcp) = &self.tcp {
            tcp.wait_for_connection()
        } else {
            Err("Must set either TCP or UDS parameters")?
        }
    }
}

impl GdbPluginParams {
    /// Emit self with `TCP` parameters set
    pub fn tcp(bind_addr: &'static str, port: u16, verbose: bool) -> Self {
        Self {
            tcp: Some(TcpParameters {
                bind_addr,
                port,
                verbose,
                assigned_port: Arc::new(Mutex::new(port)),
                listener: Arc::new(Mutex::new(None)),
            }),
            uds: None,
            port_in_use: Arc::new(Mutex::new(port)),
        }
    }

    /// Emit self with `UDS` parameters set
    pub fn uds(path: &'static str, verbose: bool) -> Self {
        Self {
            tcp: None,
            uds: Some(UdsParameters {
                path,
                verbose,
                listener: Arc::new(Mutex::new(None)),
            }),
            port_in_use: Arc::new(Mutex::new(0)),
        }
    }
}
