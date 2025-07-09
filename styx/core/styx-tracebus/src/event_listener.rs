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
use crate::{
    ipc_impl::open_srb, BaseTraceEvent, TraceError, TraceEventType, Traceable, TraceableItem,
};
use ipmpsc::Receiver;
use log::debug;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
pub enum ListenState {
    Cancelled,
    Error,
    #[default]
    Listening,
    MaxTimeouts,
}

#[derive(Debug)]
pub struct ListenResult {
    state: ListenState,
    pub buffer: Vec<TraceableItem>,
    mask: TraceEventType,
}

impl ListenResult {
    pub fn new(mask: TraceEventType) -> Self {
        Self {
            mask,
            buffer: vec![],
            state: ListenState::default(),
        }
    }

    pub fn event(&mut self, item: TraceableItem) -> bool {
        if item.event_type().is_match(self.mask) {
            self.buffer.push(item);
            true
        } else {
            false
        }
    }
}

pub struct BufferedEventListener {
    timeout: Duration,
    max_consecutive_timeouts: usize,
    rx: Box<Receiver>,
    mask: TraceEventType,
    cancel_token: CancellationToken,
}

impl BufferedEventListener {
    pub fn new(
        key: &str,
        mask: TraceEventType,
        timeout: Duration,
        max_consecutive_timeouts: usize,
        cancel_token: CancellationToken,
        num_retries: usize,
        delay: Duration,
    ) -> Result<Self, ipmpsc::Error> {
        let rx = Receiver::new(open_srb(key, num_retries, delay)?);
        Ok(BufferedEventListener {
            rx: Box::new(rx),
            timeout,
            max_consecutive_timeouts,
            mask,
            cancel_token,
        })
    }

    pub fn consume(&mut self) -> Result<ListenResult, TraceError> {
        let mut consecutive_timeout_count = 0;
        let mut result = ListenResult::new(self.mask);

        loop {
            if self.cancel_token.is_cancelled() {
                debug!("listener cancelled");
                result.state = ListenState::Cancelled;
                break;
            }

            match self
                .rx
                .zero_copy_context()
                .recv_timeout::<BaseTraceEvent>(self.timeout)
            {
                Err(e) => {
                    result.state = ListenState::Error;
                    return Err(TraceError::ReadFailed(e.to_string()));
                }

                Ok(Some(v)) => {
                    consecutive_timeout_count = 0;
                    result.event(v.into());
                }

                Ok(None) => {
                    // timeout
                    consecutive_timeout_count += 1;
                    if self.max_consecutive_timeouts != 0
                        && consecutive_timeout_count >= self.max_consecutive_timeouts
                    {
                        result.state = ListenState::MaxTimeouts;
                        break;
                    } else {
                        continue;
                    }
                }
            };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemReadEvent, MemWriteEvent};
    #[test]
    fn test_listen_result() {
        let mut lisres = ListenResult::new(TraceEventType::MEM_WRT);
        assert!(lisres.event(MemWriteEvent::new().into()));
        assert!(lisres.event(MemWriteEvent::new().into()));
        assert!(!lisres.event(MemReadEvent::new().into()));
        assert_eq!(lisres.buffer.len(), 2);

        let mut lisres = ListenResult::new(TraceEventType::MEM_WRT | TraceEventType::MEM_READ);
        assert!(lisres.event(MemWriteEvent::new().into()));
        assert!(lisres.event(MemWriteEvent::new().into()));
        assert!(lisres.event(MemReadEvent::new().into()));
        assert_eq!(lisres.buffer.len(), 3);
    }
}
