// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::backend::BitPattern;
#[test]
pub fn test_bitpattern() {
    styx_util::logging::init_logging();

    let p = BitPattern::new("10010110000sssssPP0100vv---ddddd");
    assert!(p.mask == 0b11111111111000000011110000000000);
    assert!(p.output == 0b10010110000000000001000000000000);
}
