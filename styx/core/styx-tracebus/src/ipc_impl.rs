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
//! A [TraceProvider] implemented using
//! [ipmpsc::SharedRingBuffer](https://docs.rs/ipmpsc/latest/ipmpsc/struct.SharedRingBuffer.html)
//!
//! This implementation supports `1..*` producers (trace emitters), but only
//! a **single consumer**.

use crate::{mkpath, BinaryTraceEventType, TraceError, TraceOptions, TraceProvider, Traceable};
use ipmpsc::{Receiver, Sender, SharedRingBuffer};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem::transmute;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

/// SharedRingBuffer trace file extension
pub const SRB_TRACE_FILE_EXT: &str = "srb";

/// Data for implmentation of the [`TraceProvider`] trait
pub struct IPCTracer {
    /// path on disk to the memory mapped file
    path: String,
    /// the sender (writer) of trace messages
    sender: Sender,
    /// options that control the configuration
    options: TraceOptions,
}

impl Debug for IPCTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // useful to know the address of the sender object and the options
        // its working from.
        f.write_fmt(format_args!(
            "IPCTracer: Sender: {:p} path: {:?}, options: {:?}",
            &self.sender, &self.path, &self.options
        ))
    }
}

impl IPCTracer {
    /// get (String) path to trace buffer file
    pub fn path(&self) -> String {
        self.path.to_string()
    }

    /// true if trace buffer file exists
    pub fn path_exists(&self) -> bool {
        Path::new(&self.path).exists()
    }

    /// Create a new tracer based on the options. See: [`TraceOptions`]
    ///
    /// This effectively returns an object that can be used to trace/write to
    /// a [`ipmpsc::SharedRingBuffer`] by either create a new buffer or attaching to an
    /// existing buffer.
    ///
    /// ## Panics
    /// - if the key exists and options.key_exists_ok is false
    /// - if any OS errors happen
    pub fn new(options: &TraceOptions) -> Result<Self, TraceError> {
        // this implementation uses a memory-mapped file as the trace buffer.
        // The key is the filename. Use it if provided, otherwise create it.
        let options_in = options.clone();
        log::debug!("options_in:  {:?}", options_in);

        let mut options_out = options_in.clone();
        let filename = match options_in.key {
            Some(s) => s,
            None => mkpath(None, SRB_TRACE_FILE_EXT),
        };

        options_out.key = Some(filename.to_string());

        let os_path = Path::new(&filename);
        let does_exist = os_path.exists();

        log::debug!("options_out: {:?}", options_out);

        if does_exist && !options.key_exists_ok {
            Err(TraceError::BufferKeyExists(filename))
        } else if !does_exist || options.key_exists_ok {
            // Create the SharedRingBuffer
            log::debug!("Creating sender from new SharedRingBuffer");
            Ok(Self {
                options: options.clone(),
                path: filename.to_owned(),
                sender: Sender::new(
                    SharedRingBuffer::create(&filename, options.size_bytes).unwrap(),
                ),
            })
        } else {
            // Open (attach to) the SharedRingBuffer
            log::debug!("Creating sender from existing SharedRingBuffer");
            Ok(Self {
                options: options.clone(),
                path: filename.to_owned(),
                sender: Sender::new(SharedRingBuffer::open(&filename).unwrap()),
            })
        }
    }
}

/// Implementation of the [`TraceProvider`] trait, built on [`SharedRingBuffer`]
impl TraceProvider for IPCTracer {
    /// Write a trace event
    fn trace<T>(&self, item: &T) -> Result<bool, TraceError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Traceable,
    {
        let bytes: &BinaryTraceEventType = unsafe { transmute(item) };
        match self.sender.send_timeout(bytes, self.options.send_timeout) {
            Err(e) => Err(TraceError::WriteFailed(format!("{:?}", e))),
            Ok(v) => Ok(v),
        }
    }

    /// teardown strace
    fn teardown(&self) -> Result<(), TraceError> {
        let p = std::path::Path::new(self.path.as_str());
        if !p.exists() && !p.is_file() {
            return Ok(());
        }

        match std::fs::remove_file(p) {
            Err(e) => Err(TraceError::TeardownFailed(format!("{:?}", e))),
            _ => Ok(()),
        }
    }

    /// Return the filepath as the buffer key
    fn key(&self) -> String {
        self.path()
    }
}

/// Helper for reading the trace events emmitted by IPCTracer
#[derive(Debug, Clone)]
pub struct TracerReaderOptions {
    pub filename: String,
}

impl TracerReaderOptions {
    /// Creates a new [`TracerReaderOptions`].
    pub fn new(filepath: &str) -> Self {
        Self {
            filename: filepath.to_string(),
        }
    }
}

/// Helper for reading events produced/emitted by [`IPCTracer`]
pub trait TracerReader {
    /// Return a [`Receiver`] that can be used to consume emitted events
    fn get_consumer(opts: TracerReaderOptions) -> Result<Receiver, TraceError>;
}

impl TracerReader for IPCTracer {
    /// Returns a reader for the IPC tracer attached to the ring buffer
    fn get_consumer(opts: TracerReaderOptions) -> Result<Receiver, TraceError> {
        log::debug!("initialize consumer trace for {} ... ", opts.filename);
        match SharedRingBuffer::open(opts.filename.as_str()) {
            Ok(smb) => Ok(Receiver::new(smb)),
            Err(e) => Err(TraceError::OpenFailed(format!(
                "Error opening strace buffer {}. Error was: {:?}",
                opts.filename, e
            ))),
        }
    }
}

/// Try to open the shared ring buffer file. On error, re-try `num_retries` times with
/// a delay of `delay` between failures.
pub fn open_srb(
    key: &str,
    num_retries: usize,
    delay: Duration,
) -> Result<SharedRingBuffer, ipmpsc::Error> {
    let mut result: Result<SharedRingBuffer, ipmpsc::Error> = SharedRingBuffer::open(key);
    for _ in 0..num_retries {
        if result.is_ok() {
            break;
        }
        sleep(delay);
        result = SharedRingBuffer::open(key);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::fs::remove_file;
    use std::thread;
    use styx_sync::sync::mpsc::channel;
    use styx_util::bytes_to_tmp_file;

    use super::*;
    use crate::{
        BaseTraceEvent, MemReadEvent, DEFAULT_RECV_TIMEOUT, DEFAULT_SEND_TIMEOUT, TRACE_EVENT_SIZE,
    };

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_named_file() {
        let foofile = mkpath(None, SRB_TRACE_FILE_EXT);
        let event = MemReadEvent {
            pc: 0xA,
            ..Default::default()
        };
        let d = IPCTracer::new(&TraceOptions {
            key: Some(foofile.clone()),
            size_bytes: 32,
            ..Default::default()
        })
        .unwrap();
        assert!(d.trace(&event).is_ok());
        let receiver = Receiver::new(SharedRingBuffer::open(foofile.as_str()).unwrap());
        assert_eq!(event, receiver.recv::<MemReadEvent>().unwrap());
        assert!(d.teardown().is_ok());
    }

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_create_and_attach() {
        // its an error to try to create a IPCTracer if it exists
        // and options.key_exists_ok is true

        // use the same fname (buffer key)
        let fname = mkpath(Some(String::from("test")), SRB_TRACE_FILE_EXT);
        // make sure the file does not pre-exist
        let ospath = Path::new(&fname);
        if ospath.exists() {
            assert!(remove_file(ospath).is_ok());
        }
        assert!(!ospath.exists());
        // use fname
        let opts = TraceOptions {
            key: Some(fname.clone()),
            key_exists_ok: false,
            ..Default::default()
        };
        let tr1 = IPCTracer::new(&opts).unwrap();
        // tracer is using the path we gave it and it now exists
        assert_eq!(tr1.path(), fname);
        assert!(tr1.path_exists());

        // assert!(IPCTracer::new(&opts).is_err());
        let mut no_clobber_opts = TraceOptions {
            key: Some(fname),
            key_exists_ok: false,
            ..Default::default()
        };
        // this is an error because the buffer exists and we told
        // it not to clobber it
        assert!(IPCTracer::new(&no_clobber_opts).is_err());

        // but this is OK
        no_clobber_opts.key_exists_ok = true;
        let tr2 = IPCTracer::new(&no_clobber_opts);
        assert!(tr2.is_ok());
        // teardown
        assert!(tr2.unwrap().teardown().is_ok());
        assert!(!tr1.path_exists());
    }

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_buffer_full_ipc_impl() {
        let ipcimpl = IPCTracer::new(&TraceOptions {
            size_bytes: 8 + TRACE_EVENT_SIZE as u32,
            ..Default::default()
        })
        .unwrap();

        let result = ipcimpl.sender.send_timeout(
            &BaseTraceEvent {
                ..Default::default()
            },
            DEFAULT_SEND_TIMEOUT,
        );

        assert!(result.as_ref().is_ok());
        assert!(result.as_ref().unwrap());

        let result = ipcimpl.sender.send_timeout(
            &BaseTraceEvent {
                ..Default::default()
            },
            DEFAULT_SEND_TIMEOUT,
        );
        assert!(result.as_ref().is_ok());
        assert!(!result.as_ref().unwrap());
        assert!(ipcimpl.teardown().is_ok());
    }

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_graceful_handler_trace_error() {
        let ipcimpl = IPCTracer::new(&TraceOptions {
            key: None,
            key_is_path: true,
            key_exists_ok: false,
            size_bytes: 8 + TRACE_EVENT_SIZE as u32,
            send_timeout: DEFAULT_SEND_TIMEOUT,
            recv_timeout: DEFAULT_RECV_TIMEOUT,
        })
        .unwrap();
        let result = ipcimpl.sender.send_timeout(
            &BaseTraceEvent {
                ..Default::default()
            },
            DEFAULT_SEND_TIMEOUT,
        );

        // This one is OK
        assert!(result.as_ref().is_ok());
        assert!(result.as_ref().unwrap());

        // this one will block/timeout
        let tevent = BaseTraceEvent {
            ..Default::default()
        };

        let didsend = match ipcimpl.sender.send_timeout(&tevent, DEFAULT_SEND_TIMEOUT) {
            Err(e) => {
                panic!("Failed to send trace: {:?}", e);
            }
            Ok(false) => {
                log::warn!("Failed to send trace: buffer full");
                false
            }
            Ok(true) => true,
        };
        assert!(!didsend);
        assert!(ipcimpl.teardown().is_ok());
    }

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_buf_full_behavior() {
        // Make a buffer large enough for 10 messages
        let n = 10;
        let sz = n * TRACE_EVENT_SIZE;

        let buf = IPCTracer::new(&TraceOptions {
            size_bytes: sz as u32,
            send_timeout: Duration::from_millis(250),
            ..Default::default()
        })
        .unwrap();
        let mut num_sent = 0;
        loop {
            let did_write = buf.trace(&BaseTraceEvent::default()).unwrap();
            if did_write {
                num_sent += 1;
            } else {
                break;
            }
        }
        log::info!(
            "\n\n+ [capacity={}] Wrote {} messages, SBR_OVER: {}\n\n",
            buf.options.size_bytes,
            num_sent,
            112
        );
        assert!(buf.teardown().is_ok());
    }

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_open_srb_with_retries() {
        // test retry works
        let srb_string = mkpath(None, SRB_TRACE_FILE_EXT);
        let srb_path = Path::new(&srb_string);
        assert!(!srb_path.exists());
        let srb_key_rthr = srb_string.clone();
        let srb_key_wthr = srb_string.clone();
        assert!(open_srb(&srb_string, 2, Duration::from_millis(1)).is_err());
        let (tx, rx) = channel();
        // no SRB file
        // Create a reader thread (rth) and a writer thread  (wthr)
        // the reader will try to open an SRB file, the writer will
        // create the SRB file
        let rthr = thread::spawn(move || {
            // no file initially
            assert!(!Path::new(&srb_key_rthr).exists());
            // this should fail
            let srb = open_srb(&srb_key_rthr, 10, Duration::from_millis(5));
            assert!(srb.is_err());
            // signal that I'm running for sure
            tx.send(1).expect("rthr cant send via mpsc");
            // try 50 times with 100 ms delay
            let srb = open_srb(&srb_key_rthr, 50, Duration::from_millis(100));
            assert!(srb.is_ok());
        });

        let wthr = thread::spawn(move || {
            // block until we get a signal from the reader
            let _ = rx.recv().expect("wthr cant reveive from mpsc");
            sleep(Duration::from_millis(50));
            // create the SRB
            assert!(!Path::new(&srb_key_wthr).exists());
            // create the srb file
            assert!(IPCTracer::new(&TraceOptions {
                key: Some(srb_key_wthr.clone()),
                size_bytes: 32,
                ..Default::default()
            })
            .is_ok());
        });
        assert!(rthr.join().is_ok());
        assert!(wthr.join().is_ok());
        assert!(srb_path.exists());
        assert!(remove_file(srb_path).is_ok());
    }

    #[test_log::test]
    #[cfg_attr(miri, ignore)]
    fn test_open_srb_with_retries_fail_case() {
        // create file with garbage bytes
        let gbg: [u8; 1024] = [0; 1024];
        let file_name = bytes_to_tmp_file(&gbg).path().display().to_string();
        // random bytes fails
        assert!(open_srb(&file_name, 0, Duration::from_millis(1)).is_err());
        // even if we keep trying
        assert!(open_srb(&file_name, 10, Duration::from_millis(1)).is_err());
        // non-existent files fail
        let srb_name = mkpath(None, SRB_TRACE_FILE_EXT);
        assert!(!Path::new(&srb_name).exists());
        assert!(open_srb(&srb_name, 5, Duration::from_millis(10)).is_err());
    }
}
