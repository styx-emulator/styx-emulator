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
use futures::stream::StreamExt;
use std::time::Duration;
use styx_core::sync::{cell::RefCell, sync::atomic::AtomicBool};
use tokio_timerfd::Interval;

/// All types wanting to consume a clock need to implement this
/// trait
pub trait Tick {
    /// called every clock tick, implementations should perform
    /// the calculation from
    fn tick(&self);
}

pub struct TickSource {
    enabled: AtomicBool,
    #[allow(dead_code)]
    period: u64,
    #[allow(dead_code)]
    multiplier: u64,
    #[allow(dead_code)]
    divisor: u64,
    tick_count: RefCell<u64>,
    duration: std::time::Duration,
    outputs: Vec<Box<dyn Tick>>,
}

impl TickSource {
    /// Constructs a new sysclk from the provided
    /// period in Mhz
    pub fn from_hz(hz: u64) -> Self {
        let duration = TickSource::duration(hz, 1, 1);
        TickSource {
            enabled: false.into(),
            duration,
            tick_count: RefCell::new(0),
            period: hz,
            multiplier: 1,
            divisor: 1,
            outputs: Vec::new(),
        }
    }

    /// static method to resolve the parameters into a [`Duration`](`std::time::Duration`)
    fn duration(period: u64, multiplier: u32, divisor: u32) -> std::time::Duration {
        let secs = multiplier as f64 / (period * divisor as u64) as f64;
        let duration = Duration::from_secs_f64(secs);

        println!("Constructing a duration of: {:?}", duration);
        duration
    }

    /// while enabled, continuously ticks sysclk
    pub async fn run(&mut self) {
        self.enabled = true.into();
        let mut interval = Interval::new_interval(self.duration).unwrap();

        while self
            .enabled
            .load(styx_core::sync::sync::atomic::Ordering::Relaxed)
        {
            // wait
            interval.next().await.unwrap().unwrap();

            // increase self.tick_count
            *self.tick_count.borrow_mut() += 1;

            // tick all output functions
            for destination in self.outputs.iter() {
                destination.tick();
            }
        }
    }

    pub fn add_output(&mut self, child: Box<dyn Tick>) {
        self.outputs.push(child)
    }
}
