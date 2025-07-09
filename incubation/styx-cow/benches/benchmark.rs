// SPDX-License-Identifier: BSD-2-Clause
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
