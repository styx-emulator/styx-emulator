// SPDX-License-Identifier: BSD-2-Clause
//! Provides the `gdb-xml` as serialized bytes for consumption
//!
//! Remember that [`include_bytes!`] works off of the location of the current source file
pub const AARCH64_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/aarch64-core.xml");
pub const AARCH64_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/aarch64-fpu.xml");
pub const AARCH64_PAUTH: &[u8] = include_bytes!("../../../../data/gdb-xml/aarch64-pauth.xml");
pub const ARM_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/arm-core.xml");
pub const ARM_M_PROFILE: &[u8] = include_bytes!("../../../../data/gdb-xml/arm-m-profile.xml");
pub const ARM_M_PROFILE_MVE: &[u8] =
    include_bytes!("../../../../data/gdb-xml/arm-m-profile-mve.xml");
pub const ARM_NEON: &[u8] = include_bytes!("../../../../data/gdb-xml/arm-neon.xml");
pub const ARM_VFP_SYSREGS: &[u8] = include_bytes!("../../../../data/gdb-xml/arm-vfp-sysregs.xml");
pub const ARM_VFP: &[u8] = include_bytes!("../../../../data/gdb-xml/arm-vfp.xml");
pub const ARM_VFP3: &[u8] = include_bytes!("../../../../data/gdb-xml/arm-vfp3.xml");
pub const AVR_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/avr-cpu.xml");
pub const COLDFIRE_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/cf-core.xml");
pub const COLDFIRE_FP: &[u8] = include_bytes!("../../../../data/gdb-xml/cf-fp.xml");
pub const HEXAGON_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/hexagon-core.xml");
pub const HEXAGON_HVX: &[u8] = include_bytes!("../../../../data/gdb-xml/hexagon-hvx.xml");
pub const I386_32: &[u8] = include_bytes!("../../../../data/gdb-xml/i386-32bit.xml");
pub const I386_64: &[u8] = include_bytes!("../../../../data/gdb-xml/i386-64bit.xml");
pub const LOONGARCH_32: &[u8] = include_bytes!("../../../../data/gdb-xml/loongarch-base32.xml");
pub const LOONGARCH_64: &[u8] = include_bytes!("../../../../data/gdb-xml/loongarch-base64.xml");
pub const LOONGARCH_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/loongarch-fpu.xml");
pub const M68K_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/m68k-core.xml");
pub const M68K_FP: &[u8] = include_bytes!("../../../../data/gdb-xml/m68k-fp.xml");
pub const MICROBLAZE_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/microblaze-core.xml");
pub const MICROBLAZE_STACK_PROTECT: &[u8] =
    include_bytes!("../../../../data/gdb-xml/microblaze-stack-protect.xml");
pub const MIPS_CPU: &[u8] = include_bytes!("../../../../data/gdb-xml/mips-cpu.xml");
pub const MIPS_DSP: &[u8] = include_bytes!("../../../../data/gdb-xml/mips-dsp.xml");
pub const MIPS_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/mips-fpu.xml");
pub const MIPS64_CPU: &[u8] = include_bytes!("../../../../data/gdb-xml/mips64-cpu.xml");
pub const MIPS64_DSP: &[u8] = include_bytes!("../../../../data/gdb-xml/mips64-dsp.xml");
pub const MIPS64_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/mips64-fpu.xml");
pub const POWER_ALTIVEC: &[u8] = include_bytes!("../../../../data/gdb-xml/power-altivec.xml");
pub const POWER_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/power-core.xml");
pub const POWER_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/power-fpu.xml");
pub const POWER_SPE: &[u8] = include_bytes!("../../../../data/gdb-xml/power-spe.xml");
pub const POWER_VSX: &[u8] = include_bytes!("../../../../data/gdb-xml/power-vsx.xml");
pub const POWER64_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/power64-core.xml");
pub const RISCV_32_CPU: &[u8] = include_bytes!("../../../../data/gdb-xml/riscv-32bit-cpu.xml");
pub const RISCV_32_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/riscv-32bit-fpu.xml");
pub const RISCV_32_VIRTUAL: &[u8] =
    include_bytes!("../../../../data/gdb-xml/riscv-32bit-virtual.xml");
pub const RISCV_64_CPU: &[u8] = include_bytes!("../../../../data/gdb-xml/riscv-64bit-cpu.xml");
pub const RISCV_64_FPU: &[u8] = include_bytes!("../../../../data/gdb-xml/riscv-64bit-fpu.xml");
pub const RISCV_64_VIRTUAL: &[u8] =
    include_bytes!("../../../../data/gdb-xml/riscv-64bit-virtual.xml");
pub const RX_CORE: &[u8] = include_bytes!("../../../../data/gdb-xml/rx-core.xml");
pub const S390_ACR: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-acr.xml");
pub const S390_CR: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-cr.xml");
pub const S390_FPR: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-fpr.xml");
pub const S390_GS: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-gs.xml");
pub const S390_VIRT_KVM: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-virt-kvm.xml");
pub const S390_VIRT: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-virt.xml");
pub const S390_VX: &[u8] = include_bytes!("../../../../data/gdb-xml/s390-vx.xml");
pub const S390_CORE64: &[u8] = include_bytes!("../../../../data/gdb-xml/s390x-core64.xml");
pub const BLACKFIN: &[u8] = include_bytes!("../../../../data/gdb-xml/blackfin.xml");
pub const SH1: &[u8] = include_bytes!("../../../../data/gdb-xml/sh1.xml");
pub const SH1_DSP: &[u8] = include_bytes!("../../../../data/gdb-xml/sh1-dsp.xml");
pub const SH2: &[u8] = include_bytes!("../../../../data/gdb-xml/sh2.xml");
pub const SH2A: &[u8] = include_bytes!("../../../../data/gdb-xml/sh2a.xml");
pub const SH2A_NOFPU: &[u8] = include_bytes!("../../../../data/gdb-xml/sh2a-nofpu.xml");
pub const SH2E: &[u8] = include_bytes!("../../../../data/gdb-xml/sh2e.xml");
pub const SH3: &[u8] = include_bytes!("../../../../data/gdb-xml/sh3.xml");
pub const SH3E: &[u8] = include_bytes!("../../../../data/gdb-xml/sh3e.xml");
pub const SH3_DSP: &[u8] = include_bytes!("../../../../data/gdb-xml/sh3-dsp.xml");
pub const SH4: &[u8] = include_bytes!("../../../../data/gdb-xml/sh4.xml");
// sh4a == sh4
pub const SH4A: &[u8] = include_bytes!("../../../../data/gdb-xml/sh4.xml");
pub const SH4_NOFPU: &[u8] = include_bytes!("../../../../data/gdb-xml/sh4-nofpu.xml");
// sh4a == sh4
pub const SH4A_NOFPU: &[u8] = include_bytes!("../../../../data/gdb-xml/sh4-nofpu.xml");
pub const SH4AL_DSP: &[u8] = include_bytes!("../../../../data/gdb-xml/sh4al-dsp.xml");
// MSP430
pub const MSP430: &[u8] = include_bytes!("../../../../data/gdb-xml/msp430.xml");
pub const MSP430X: &[u8] = include_bytes!("../../../../data/gdb-xml/msp430x.xml");
