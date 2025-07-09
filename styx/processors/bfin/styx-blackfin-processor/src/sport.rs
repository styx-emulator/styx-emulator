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
//! SPORT emulation for the blackfin processor.
//!
//! The SPORT peripheral acts as just an input/output byte stream to its DMA channel. Currently no
//! SPORT configuration is done.
//!
//! Ideally, there would be a blackfin peripheral interface that could expose a sport channel so
//! that difference devices could attach peripherals as needed. Instead, the current sport channels
//! are hard coded sin waves.

use std::{f64::consts::PI, time::Duration};

use futures::{Stream, StreamExt};
use tokio::time::Instant;

use crate::dma::DmaStream;

pub async fn sport_sin_sample() -> DmaStream {
    sin_sampling_stream()
        .await
        .flat_map(|value| tokio_stream::iter(value.to_le_bytes()))
        .boxed()
}

/// Scales a float that is 0..=1 to 0..=u16::MAX
fn scale_blackfin_sin(value: f64) -> u16 {
    let value = (value * (u16::MAX as f64 / 2f64)) + (u16::MAX as f64 / 2f64);
    value as u16
}

/// Produces a stream that samples a sin wave.
///
/// Samples (produces value) every 100ms. Sin period is 10s. Range is
/// 0..=u16::MAX.
async fn sin_sampling_stream() -> impl Stream<Item = u16> {
    let sampling_hz = 10f32;
    let sampling_period = Duration::from_secs_f32(1f32 / sampling_hz);

    /// Given the period between samples, start time of the stream, and the
    /// current time, give a sin wave in spread across the rage of a u16.
    async fn calculate_sin(sampling_period: Duration, start_time: Instant, time: Instant) -> u16 {
        let time = time - start_time;
        let sin_period = sampling_period * 100;
        // amount of x per each sample
        let sin_interval = (2f64 * PI) * (sampling_period.as_secs_f64() / sin_period.as_secs_f64());

        let y_float = (time.as_secs_f64() * sin_interval).sin();
        scale_blackfin_sin(y_float)
    }

    let start_time = Instant::now();
    tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(sampling_period))
        .then(move |time| calculate_sin(sampling_period, start_time, time))
}

#[cfg(test)]
mod tests {
    use futures::{FutureExt, StreamExt};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn test_sin_sampling() {
        let mut sin = sin_sampling_stream().await.boxed();

        // first value present, starting at "0" which is dead center of u16
        let value = sin.next().now_or_never().unwrap().unwrap();
        assert_eq!(value, u16::MAX / 2);
        // no more values present because no time has passed
        let value = sin.next().now_or_never();
        assert!(value.is_none());

        // after one sampling time period
        tokio::time::advance(Duration::from_millis(101)).await;

        // next value is slightly more
        let value = sin.next().now_or_never().unwrap().unwrap();
        assert_eq!(value, 32973);
        // still only one value present since we only advanced one sampling period
        let value = sin.next().now_or_never();
        assert!(value.is_none());

        // advance 10 sampling periods
        // pretending like we haven't sampled in a while
        tokio::time::advance(Duration::from_millis(1001)).await;

        // assert no less than 10 samples...
        for _ in 0..10 {
            sin.next().now_or_never().unwrap().unwrap();
        }
        // and no more.
        let value = sin.next().now_or_never();
        assert!(value.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_dma_stream() {
        let mut sin = sport_sin_sample().await;

        let expected = u16::MAX / 2;
        let expected_bytes = expected.to_le_bytes();
        // first value present, starting at "0" which is dead center of u16
        // should be given in little endian order
        let value = sin.next().now_or_never().unwrap().unwrap();
        assert_eq!(value, expected_bytes[0]);
        let value = sin.next().now_or_never().unwrap().unwrap();
        assert_eq!(value, expected_bytes[1]);
    }
}
