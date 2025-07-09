// SPDX-License-Identifier: BSD-2-Clause
use std::fs::{copy, remove_file};
use std::path::Path;
/// strace performance benchmark
use std::time::{Duration, Instant};
use styx_tracebus::*;

macro_rules! timeit {
    ($Ctx: expr, ($root:expr), $N: ident) => {{
        eprint!("{:20} {}: ", $Ctx, $N);
        let __epoch = Instant::now();
        let rslt = { $root };
        let __dur = __epoch.elapsed();
        let __rate = $N as f64 / __dur.as_secs_f64();
        eprintln!(
            "~{:?} secs, rate: {} events/sec",
            __dur.as_secs(),
            __rate as u64
        );
        rslt
    }};
}

#[derive(Clone, Copy, Debug)]
pub enum ConsumeBehavior {
    // just consume it
    CONSUME = 1,
    // consume and cast to specific type
    CAST = 2,
    // consume, cast, and process as JSON
    JSON = 3,
    // consume, cast, and process as TEXT
    TEXT = 4,
}

fn main() {
    // use the shared ring  buffer implementation
    std::env::set_var(STRACE_ENV_VAR, "srb");
    let goal_n = 100_000_000;
    let key = timeit!("produce", (produce(goal_n)), goal_n);
    let srb_path = std::path::Path::new(&key);
    let temp_path_str = format!("/tmp/{}b.srb", std::process::id());
    let temp_path = Path::new(&temp_path_str);

    let cases: Vec<ConsumeBehavior> = vec![
        ConsumeBehavior::CONSUME,
        ConsumeBehavior::CAST,
        ConsumeBehavior::JSON,
        ConsumeBehavior::TEXT,
    ];
    cases.iter().for_each(|behavior| {
        match copy(srb_path, temp_path) {
            Ok(_) => (),
            Err(e) => {
                eprintln!(
                    "copy({}, {}) failed: {}",
                    srb_path.display(),
                    temp_path.display(),
                    e
                );
                std::process::exit(1);
            }
        };

        let ctx = format!("{:?}", *behavior);
        let n_consumed = timeit!(ctx, (consume(&temp_path_str, *behavior)), goal_n);
        assert_eq!(n_consumed, goal_n);
    });

    remove_file(temp_path).unwrap();
    strace_teardown!();
}

/// produced n events
fn produce(n: u64) -> String {
    for _ in 0..n {
        strace!(ControlEvent::new());
    }
    styx_trace::STRACE.key()
}

/// consume all available events
fn consume(key: &str, behavior: ConsumeBehavior) -> u64 {
    let tmout = Duration::from_millis(500);
    let mut rx = receiver!(key);
    let mut num_consumed = 0;
    let mut received_item = true;
    while received_item {
        received_item = match rx.zero_copy_context().recv_timeout::<BaseTraceEvent>(tmout) {
            Ok(non_err) => match non_err {
                Some(event) => {
                    match behavior {
                        ConsumeBehavior::CONSUME => {}
                        ConsumeBehavior::CAST => {
                            let _ = TraceableItem::from(event);
                        }
                        ConsumeBehavior::JSON => {
                            let _ = TraceableItem::from(event).json();
                        }
                        ConsumeBehavior::TEXT => {
                            let _ = TraceableItem::from(event).text();
                        }
                    }
                    num_consumed += 1;
                    true
                }
                None => false,
            },

            Err(e) => panic!("error consuming trace: {:?}", e),
        };
    }
    num_consumed
}
