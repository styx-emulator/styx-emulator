// SPDX-License-Identifier: BSD-2-Clause
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
