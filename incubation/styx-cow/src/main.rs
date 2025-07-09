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
