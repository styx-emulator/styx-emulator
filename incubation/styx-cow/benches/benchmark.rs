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
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use styx_cow::Cow;

fn non_cow(size: usize) -> (Vec<u8>, Vec<u8>) {
    let mut region = vec![0_u8; size];

    region[size - 1] = 1;

    let mut region2 = region.clone();

    region2[size - 1] = 10;

    (region, region2)
}

fn cow(size: usize) -> (Cow, Cow) {
    let mut region = Cow::new(size).unwrap();

    region.get_data_mut()[size - 1] = 1;

    let mut region2 = region.try_clone().unwrap();

    region2.get_data_mut()[size - 1] = 10;

    (region, region2)
}

pub fn criterion_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("copy perf");
    static KB: usize = 1024;
    static GB: usize = 1000 * 1000 * 1000;

    // benchmark from KB -> 4GB
    for size in [
        KB,
        2 * KB,
        4 * KB,
        8 * KB,
        16 * KB,
        32 * KB,
        64 * KB,
        GB / 2,
        GB,
        2 * GB,
        4 * GB,
    ]
    .iter()
    {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("old method", size), size, |b, &size| {
            b.iter(|| {
                let (_a, _b) = black_box(non_cow(size));
            });
        });
        group.bench_with_input(BenchmarkId::new("new method", size), size, |b, &size| {
            b.iter(|| {
                let (mut x, mut y) = black_box(cow(size));
                x.get_data_mut()[size - 1] = 0;
                y.get_data_mut()[size - 1] = 1;
            });
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);
