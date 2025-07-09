// SPDX-License-Identifier: BSD-2-Clause
#![cfg(all(shuttle, test))]

use styx_sync::shuttle;
use styx_sync::sync::atomic::AtomicUsize;
use styx_sync::sync::atomic::Ordering::SeqCst;
use styx_sync::sync::{Arc, Mutex};
use styx_sync::thread;

#[test]
fn test_shuttle_concurrent_logic() {
    shuttle::check_random(
        || {
            let lock = Arc::new(Mutex::new(0u64));
            let lock2 = lock.clone();

            thread::spawn(move || {
                *lock.lock().unwrap() = 1;
            });

            assert_eq!(0, *lock2.lock().unwrap());
        },
        100,
    );
}
