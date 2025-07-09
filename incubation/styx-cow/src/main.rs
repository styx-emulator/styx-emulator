// SPDX-License-Identifier: BSD-2-Clause
use styx_cow::Cow;

use std::time::Instant;

const SIZE: usize = 1024 * 1024;

use criterion::black_box;

#[inline(never)]
fn cow() -> (Cow, Cow) {
    let mut region = Cow::new(SIZE).unwrap();

    region.get_data_mut()[SIZE - 1] = 1;

    let mut new_region = region.try_clone().unwrap();

    new_region.get_data_mut()[SIZE - 1] = 10;

    (region, new_region)
}

#[inline(never)]
fn copy() -> (Vec<u8>, Vec<u8>) {
    let mut region = vec![0_u8; SIZE];
    region[SIZE - 1] = 1;

    let mut new_region = region.clone();

    new_region[SIZE - 1] = 10;

    (region, new_region)
}

fn main() {
    let mut t = Instant::now();
    let (a, b) = black_box(cow());
    println!("cow elapsed: {:?}", t.elapsed());

    t = Instant::now();
    let (x, y) = black_box(copy());
    println!("non cow elapsed: {:?}", t.elapsed());

    println!("{:?}, {:?}, {:?}, {:?}", a.len(), b.len(), x.len(), y.len());
}
