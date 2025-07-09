#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#ifndef u128
typedef unsigned __int128 u128;
#endif /* u128 */

#ifndef i128
typedef __int128 i128;
#endif /* i128 */

/* This tracks `styx_core::memory::MemoryPermissions`
 * XXX: add `styx_core::memory` to get exported by the bindings
 */
typedef uint32_t Internal;


/**
 * All of the supported emulator backends
 */
typedef enum StyxBackend {
  /**
   * A backend that uses Unicorn to emulate the system
   */
  STYX_BACKEND_UNICORN,
  /**
   * A backend which uses PCode to emulate the system
   */
  STYX_BACKEND_PCODE,
} StyxBackend;

/**
 * The behavior an emulator should use in case of exceptional behavior
 */
typedef enum StyxExceptionBehavior {
  STYX_EXCEPTION_BEHAVIOR_PANIC,
  STYX_EXCEPTION_BEHAVIOR_RAISE,
  STYX_EXCEPTION_BEHAVIOR_TARGET_HANDLE,
  STYX_EXCEPTION_BEHAVIOR_PAUSE,
} StyxExceptionBehavior;

typedef enum StyxFFIErrorKind {
  STYX_FFI_ERROR_KIND_NULL_OUTPUT,
  STYX_FFI_ERROR_KIND_NULL_INPUT,
  STYX_FFI_ERROR_KIND_NULL_ARRAY,
  STYX_FFI_ERROR_KIND_NULL_STRING,
  STYX_FFI_ERROR_KIND_ALLOCATION_ERROR,
  STYX_FFI_ERROR_KIND_INVALID_ARRAY_LENGTH,
  STYX_FFI_ERROR_KIND_INVALID_STRING_LENGTH,
  STYX_FFI_ERROR_KIND_INVALID_STRING,
  STYX_FFI_ERROR_KIND_ADD_HOOK,
  STYX_FFI_ERROR_KIND_MMU_OP,
  STYX_FFI_ERROR_KIND_READ_REGISTER,
  STYX_FFI_ERROR_KIND_WRITE_REGISTER,
  STYX_FFI_ERROR_KIND_TRY_FROM_INT,
  STYX_FFI_ERROR_KIND_TRY_NEW_ARBITRARY_INT,
  STYX_FFI_ERROR_KIND_UNKNOWN,
} StyxFFIErrorKind;

typedef enum StyxRegister {
  STYX_REGISTER_ARM_APSR,
  STYX_REGISTER_ARM_CPSR,
  STYX_REGISTER_ARM_FPEXC,
  STYX_REGISTER_ARM_FPSCR,
  STYX_REGISTER_ARM_FPSID,
  STYX_REGISTER_ARM_MVFR0,
  STYX_REGISTER_ARM_MVFR1,
  STYX_REGISTER_ARM_ITSTATE,
  STYX_REGISTER_ARM_LR,
  STYX_REGISTER_ARM_PC,
  STYX_REGISTER_ARM_SP,
  STYX_REGISTER_ARM_SPSR,
  STYX_REGISTER_ARM_D0,
  STYX_REGISTER_ARM_D1,
  STYX_REGISTER_ARM_D2,
  STYX_REGISTER_ARM_D3,
  STYX_REGISTER_ARM_D4,
  STYX_REGISTER_ARM_D5,
  STYX_REGISTER_ARM_D6,
  STYX_REGISTER_ARM_D7,
  STYX_REGISTER_ARM_D8,
  STYX_REGISTER_ARM_D9,
  STYX_REGISTER_ARM_D10,
  STYX_REGISTER_ARM_D11,
  STYX_REGISTER_ARM_D12,
  STYX_REGISTER_ARM_D13,
  STYX_REGISTER_ARM_D14,
  STYX_REGISTER_ARM_D15,
  STYX_REGISTER_ARM_D16,
  STYX_REGISTER_ARM_D17,
  STYX_REGISTER_ARM_D18,
  STYX_REGISTER_ARM_D19,
  STYX_REGISTER_ARM_D20,
  STYX_REGISTER_ARM_D21,
  STYX_REGISTER_ARM_D22,
  STYX_REGISTER_ARM_D23,
  STYX_REGISTER_ARM_D24,
  STYX_REGISTER_ARM_D25,
  STYX_REGISTER_ARM_D26,
  STYX_REGISTER_ARM_D27,
  STYX_REGISTER_ARM_D28,
  STYX_REGISTER_ARM_D29,
  STYX_REGISTER_ARM_D30,
  STYX_REGISTER_ARM_D31,
  STYX_REGISTER_ARM_Q0,
  STYX_REGISTER_ARM_Q1,
  STYX_REGISTER_ARM_Q2,
  STYX_REGISTER_ARM_Q3,
  STYX_REGISTER_ARM_Q4,
  STYX_REGISTER_ARM_Q5,
  STYX_REGISTER_ARM_Q6,
  STYX_REGISTER_ARM_Q7,
  STYX_REGISTER_ARM_Q8,
  STYX_REGISTER_ARM_Q9,
  STYX_REGISTER_ARM_Q10,
  STYX_REGISTER_ARM_Q11,
  STYX_REGISTER_ARM_Q12,
  STYX_REGISTER_ARM_Q13,
  STYX_REGISTER_ARM_Q14,
  STYX_REGISTER_ARM_Q15,
  STYX_REGISTER_ARM_R0,
  STYX_REGISTER_ARM_R1,
  STYX_REGISTER_ARM_R2,
  STYX_REGISTER_ARM_R3,
  STYX_REGISTER_ARM_R4,
  STYX_REGISTER_ARM_R5,
  STYX_REGISTER_ARM_R6,
  STYX_REGISTER_ARM_R7,
  STYX_REGISTER_ARM_R8,
  STYX_REGISTER_ARM_R9,
  STYX_REGISTER_ARM_R10,
  STYX_REGISTER_ARM_R11,
  STYX_REGISTER_ARM_R12,
  STYX_REGISTER_ARM_S0,
  STYX_REGISTER_ARM_S1,
  STYX_REGISTER_ARM_S2,
  STYX_REGISTER_ARM_S3,
  STYX_REGISTER_ARM_S4,
  STYX_REGISTER_ARM_S5,
  STYX_REGISTER_ARM_S6,
  STYX_REGISTER_ARM_S7,
  STYX_REGISTER_ARM_S8,
  STYX_REGISTER_ARM_S9,
  STYX_REGISTER_ARM_S10,
  STYX_REGISTER_ARM_S11,
  STYX_REGISTER_ARM_S12,
  STYX_REGISTER_ARM_S13,
  STYX_REGISTER_ARM_S14,
  STYX_REGISTER_ARM_S15,
  STYX_REGISTER_ARM_S16,
  STYX_REGISTER_ARM_S17,
  STYX_REGISTER_ARM_S18,
  STYX_REGISTER_ARM_S19,
  STYX_REGISTER_ARM_S20,
  STYX_REGISTER_ARM_S21,
  STYX_REGISTER_ARM_S22,
  STYX_REGISTER_ARM_S23,
  STYX_REGISTER_ARM_S24,
  STYX_REGISTER_ARM_S25,
  STYX_REGISTER_ARM_S26,
  STYX_REGISTER_ARM_S27,
  STYX_REGISTER_ARM_S28,
  STYX_REGISTER_ARM_S29,
  STYX_REGISTER_ARM_S30,
  STYX_REGISTER_ARM_S31,
  STYX_REGISTER_ARM_IPSR,
  STYX_REGISTER_ARM_MSP,
  STYX_REGISTER_ARM_PSP,
  STYX_REGISTER_ARM_CONTROL,
  STYX_REGISTER_ARM_IAPSR,
  STYX_REGISTER_ARM_EAPSR,
  STYX_REGISTER_ARM_XPSR,
  STYX_REGISTER_ARM_EPSR,
  STYX_REGISTER_ARM_IEPSR,
  STYX_REGISTER_ARM_PRIMASK,
  STYX_REGISTER_ARM_BASEPRI,
  STYX_REGISTER_ARM_FAULTMASK,
  STYX_REGISTER_ARM_SB,
  STYX_REGISTER_ARM_SL,
  STYX_REGISTER_ARM_FP,
  STYX_REGISTER_ARM_IP,
  STYX_REGISTER_ARM_R13,
  STYX_REGISTER_ARM_R14,
  STYX_REGISTER_ARM_R15,
  STYX_REGISTER_PPC32_R0,
  STYX_REGISTER_PPC32_R1,
  STYX_REGISTER_PPC32_R2,
  STYX_REGISTER_PPC32_R3,
  STYX_REGISTER_PPC32_R4,
  STYX_REGISTER_PPC32_R5,
  STYX_REGISTER_PPC32_R6,
  STYX_REGISTER_PPC32_R7,
  STYX_REGISTER_PPC32_R8,
  STYX_REGISTER_PPC32_R9,
  STYX_REGISTER_PPC32_R10,
  STYX_REGISTER_PPC32_R11,
  STYX_REGISTER_PPC32_R12,
  STYX_REGISTER_PPC32_R13,
  STYX_REGISTER_PPC32_R14,
  STYX_REGISTER_PPC32_R15,
  STYX_REGISTER_PPC32_R16,
  STYX_REGISTER_PPC32_R17,
  STYX_REGISTER_PPC32_R18,
  STYX_REGISTER_PPC32_R19,
  STYX_REGISTER_PPC32_R20,
  STYX_REGISTER_PPC32_R21,
  STYX_REGISTER_PPC32_R22,
  STYX_REGISTER_PPC32_R23,
  STYX_REGISTER_PPC32_R24,
  STYX_REGISTER_PPC32_R25,
  STYX_REGISTER_PPC32_R26,
  STYX_REGISTER_PPC32_R27,
  STYX_REGISTER_PPC32_R28,
  STYX_REGISTER_PPC32_R29,
  STYX_REGISTER_PPC32_R30,
  STYX_REGISTER_PPC32_R31,
  STYX_REGISTER_PPC32_PC,
  STYX_REGISTER_PPC32_MSR,
  STYX_REGISTER_PPC32_CR0,
  STYX_REGISTER_PPC32_CR1,
  STYX_REGISTER_PPC32_CR2,
  STYX_REGISTER_PPC32_CR3,
  STYX_REGISTER_PPC32_CR4,
  STYX_REGISTER_PPC32_CR5,
  STYX_REGISTER_PPC32_CR6,
  STYX_REGISTER_PPC32_CR7,
  STYX_REGISTER_PPC32_CR,
  STYX_REGISTER_PPC32_LR,
  STYX_REGISTER_PPC32_CTR,
  STYX_REGISTER_PPC32_XER,
  STYX_REGISTER_PPC32_TBL_R,
  STYX_REGISTER_PPC32_TBU_R,
  STYX_REGISTER_PPC32_TBL_W,
  STYX_REGISTER_PPC32_TBU_W,
  STYX_REGISTER_PPC32_TCR,
  STYX_REGISTER_PPC32_TSR,
  STYX_REGISTER_PPC32_PIT,
  STYX_REGISTER_PPC32_DBSR,
  STYX_REGISTER_PPC32_DBCR0,
  STYX_REGISTER_PPC32_DBCR1,
  STYX_REGISTER_PPC32_DAC1,
  STYX_REGISTER_PPC32_DAC2,
  STYX_REGISTER_PPC32_DVC1,
  STYX_REGISTER_PPC32_DVC2,
  STYX_REGISTER_PPC32_IAC1,
  STYX_REGISTER_PPC32_IAC2,
  STYX_REGISTER_PPC32_IAC3,
  STYX_REGISTER_PPC32_IAC4,
  STYX_REGISTER_PPC32_ICDBR,
  STYX_REGISTER_PPC32_DCCR,
  STYX_REGISTER_PPC32_DCWR,
  STYX_REGISTER_PPC32_ICCR,
  STYX_REGISTER_PPC32_SGR,
  STYX_REGISTER_PPC32_SLER,
  STYX_REGISTER_PPC32_SU0R,
  STYX_REGISTER_PPC32_CCR0,
  STYX_REGISTER_PPC32_SPRG0,
  STYX_REGISTER_PPC32_SPRG1,
  STYX_REGISTER_PPC32_SPRG2,
  STYX_REGISTER_PPC32_SPRG3,
  STYX_REGISTER_PPC32_SPRG4,
  STYX_REGISTER_PPC32_SPRG5,
  STYX_REGISTER_PPC32_SPRG6,
  STYX_REGISTER_PPC32_SPRG7,
  STYX_REGISTER_PPC32_EVPR,
  STYX_REGISTER_PPC32_ESR,
  STYX_REGISTER_PPC32_DEAR,
  STYX_REGISTER_PPC32_SRR0,
  STYX_REGISTER_PPC32_SRR1,
  STYX_REGISTER_PPC32_SRR2,
  STYX_REGISTER_PPC32_SRR3,
  STYX_REGISTER_PPC32_PID,
  STYX_REGISTER_PPC32_ZPR,
  STYX_REGISTER_PPC32_PVR,
  STYX_REGISTER_PPC32_FPR0,
  STYX_REGISTER_PPC32_FPR1,
  STYX_REGISTER_PPC32_FPR2,
  STYX_REGISTER_PPC32_FPR3,
  STYX_REGISTER_PPC32_FPR4,
  STYX_REGISTER_PPC32_FPR5,
  STYX_REGISTER_PPC32_FPR6,
  STYX_REGISTER_PPC32_FPR7,
  STYX_REGISTER_PPC32_FPR8,
  STYX_REGISTER_PPC32_FPR9,
  STYX_REGISTER_PPC32_FPR10,
  STYX_REGISTER_PPC32_FPR11,
  STYX_REGISTER_PPC32_FPR12,
  STYX_REGISTER_PPC32_FPR13,
  STYX_REGISTER_PPC32_FPR14,
  STYX_REGISTER_PPC32_FPR15,
  STYX_REGISTER_PPC32_FPR16,
  STYX_REGISTER_PPC32_FPR17,
  STYX_REGISTER_PPC32_FPR18,
  STYX_REGISTER_PPC32_FPR19,
  STYX_REGISTER_PPC32_FPR20,
  STYX_REGISTER_PPC32_FPR21,
  STYX_REGISTER_PPC32_FPR22,
  STYX_REGISTER_PPC32_FPR23,
  STYX_REGISTER_PPC32_FPR24,
  STYX_REGISTER_PPC32_FPR25,
  STYX_REGISTER_PPC32_FPR26,
  STYX_REGISTER_PPC32_FPR27,
  STYX_REGISTER_PPC32_FPR28,
  STYX_REGISTER_PPC32_FPR29,
  STYX_REGISTER_PPC32_FPR30,
  STYX_REGISTER_PPC32_FPR31,
  STYX_REGISTER_PPC32_FPSCR,
  STYX_REGISTER_BLACKFIN_PC,
  STYX_REGISTER_BLACKFIN_R0,
  STYX_REGISTER_BLACKFIN_R1,
  STYX_REGISTER_BLACKFIN_R2,
  STYX_REGISTER_BLACKFIN_R3,
  STYX_REGISTER_BLACKFIN_R4,
  STYX_REGISTER_BLACKFIN_R5,
  STYX_REGISTER_BLACKFIN_R6,
  STYX_REGISTER_BLACKFIN_R7,
  STYX_REGISTER_BLACKFIN_P0,
  STYX_REGISTER_BLACKFIN_P1,
  STYX_REGISTER_BLACKFIN_P2,
  STYX_REGISTER_BLACKFIN_P3,
  STYX_REGISTER_BLACKFIN_P4,
  STYX_REGISTER_BLACKFIN_P5,
  STYX_REGISTER_BLACKFIN_SP,
  STYX_REGISTER_BLACKFIN_FP,
  STYX_REGISTER_BLACKFIN_I0,
  STYX_REGISTER_BLACKFIN_I1,
  STYX_REGISTER_BLACKFIN_I2,
  STYX_REGISTER_BLACKFIN_I3,
  STYX_REGISTER_BLACKFIN_L0,
  STYX_REGISTER_BLACKFIN_L1,
  STYX_REGISTER_BLACKFIN_L2,
  STYX_REGISTER_BLACKFIN_L3,
  STYX_REGISTER_BLACKFIN_B0,
  STYX_REGISTER_BLACKFIN_B1,
  STYX_REGISTER_BLACKFIN_B2,
  STYX_REGISTER_BLACKFIN_B3,
  STYX_REGISTER_BLACKFIN_M0,
  STYX_REGISTER_BLACKFIN_M1,
  STYX_REGISTER_BLACKFIN_M2,
  STYX_REGISTER_BLACKFIN_M3,
  STYX_REGISTER_BLACKFIN_A0,
  STYX_REGISTER_BLACKFIN_A0X,
  STYX_REGISTER_BLACKFIN_A0W,
  STYX_REGISTER_BLACKFIN_A1X,
  STYX_REGISTER_BLACKFIN_A1W,
  STYX_REGISTER_BLACKFIN_A1,
  STYX_REGISTER_BLACKFIN_LC0,
  STYX_REGISTER_BLACKFIN_LC1,
  STYX_REGISTER_BLACKFIN_LT0,
  STYX_REGISTER_BLACKFIN_LT1,
  STYX_REGISTER_BLACKFIN_LB0,
  STYX_REGISTER_BLACKFIN_LB1,
  STYX_REGISTER_BLACKFIN_ASTAT,
  STYX_REGISTER_BLACKFIN_C_CFLAG,
  STYX_REGISTER_BLACKFIN_A_ZFLAG,
  STYX_REGISTER_BLACKFIN_A_NFLAG,
  STYX_REGISTER_BLACKFIN_A_QFLAG,
  STYX_REGISTER_BLACKFIN_RND_MODFLAG,
  STYX_REGISTER_BLACKFIN_AC0FLAG,
  STYX_REGISTER_BLACKFIN_AC1FLAG,
  STYX_REGISTER_BLACKFIN_AV0FLAG,
  STYX_REGISTER_BLACKFIN_AV0_SFLAG,
  STYX_REGISTER_BLACKFIN_AV1FLAG,
  STYX_REGISTER_BLACKFIN_AV1_SFLAG,
  STYX_REGISTER_BLACKFIN_VFLAG,
  STYX_REGISTER_BLACKFIN_V_SFLAG,
  STYX_REGISTER_BLACKFIN_RETI,
  STYX_REGISTER_BLACKFIN_RETN,
  STYX_REGISTER_BLACKFIN_RETX,
  STYX_REGISTER_BLACKFIN_RETE,
  STYX_REGISTER_BLACKFIN_RETS,
  STYX_REGISTER_SUPER_H_R0,
  STYX_REGISTER_SUPER_H_R1,
  STYX_REGISTER_SUPER_H_R2,
  STYX_REGISTER_SUPER_H_R3,
  STYX_REGISTER_SUPER_H_R4,
  STYX_REGISTER_SUPER_H_R5,
  STYX_REGISTER_SUPER_H_R6,
  STYX_REGISTER_SUPER_H_R7,
  STYX_REGISTER_SUPER_H_R8,
  STYX_REGISTER_SUPER_H_R9,
  STYX_REGISTER_SUPER_H_R10,
  STYX_REGISTER_SUPER_H_R11,
  STYX_REGISTER_SUPER_H_R12,
  STYX_REGISTER_SUPER_H_R13,
  STYX_REGISTER_SUPER_H_R14,
  STYX_REGISTER_SUPER_H_R15,
  STYX_REGISTER_SUPER_H_PC,
  STYX_REGISTER_SUPER_H_PR,
  STYX_REGISTER_SUPER_H_GBR,
  STYX_REGISTER_SUPER_H_VBR,
  STYX_REGISTER_SUPER_H_MACH,
  STYX_REGISTER_SUPER_H_MACL,
  STYX_REGISTER_SUPER_H_SR,
  STYX_REGISTER_SUPER_H_FPUL,
  STYX_REGISTER_SUPER_H_FPSCR,
  STYX_REGISTER_SUPER_H_FR0,
  STYX_REGISTER_SUPER_H_FR1,
  STYX_REGISTER_SUPER_H_FR2,
  STYX_REGISTER_SUPER_H_FR3,
  STYX_REGISTER_SUPER_H_FR4,
  STYX_REGISTER_SUPER_H_FR5,
  STYX_REGISTER_SUPER_H_FR6,
  STYX_REGISTER_SUPER_H_FR7,
  STYX_REGISTER_SUPER_H_FR8,
  STYX_REGISTER_SUPER_H_FR9,
  STYX_REGISTER_SUPER_H_FR10,
  STYX_REGISTER_SUPER_H_FR11,
  STYX_REGISTER_SUPER_H_FR12,
  STYX_REGISTER_SUPER_H_FR13,
  STYX_REGISTER_SUPER_H_FR14,
  STYX_REGISTER_SUPER_H_FR15,
  STYX_REGISTER_SUPER_H_IBCR,
  STYX_REGISTER_SUPER_H_IBNR,
  STYX_REGISTER_SUPER_H_TBR,
  STYX_REGISTER_SUPER_H_DR0,
  STYX_REGISTER_SUPER_H_DR2,
  STYX_REGISTER_SUPER_H_DR4,
  STYX_REGISTER_SUPER_H_DR6,
  STYX_REGISTER_SUPER_H_DR8,
  STYX_REGISTER_SUPER_H_DR10,
  STYX_REGISTER_SUPER_H_DR12,
  STYX_REGISTER_SUPER_H_DR14,
  STYX_REGISTER_SUPER_H_DSR,
  STYX_REGISTER_SUPER_H_A0G,
  STYX_REGISTER_SUPER_H_A0,
  STYX_REGISTER_SUPER_H_A1G,
  STYX_REGISTER_SUPER_H_A1,
  STYX_REGISTER_SUPER_H_M0,
  STYX_REGISTER_SUPER_H_M1,
  STYX_REGISTER_SUPER_H_X0,
  STYX_REGISTER_SUPER_H_X1,
  STYX_REGISTER_SUPER_H_Y0,
  STYX_REGISTER_SUPER_H_Y1,
  STYX_REGISTER_SUPER_H_MOD,
  STYX_REGISTER_SUPER_H_RS,
  STYX_REGISTER_SUPER_H_RE,
  STYX_REGISTER_SUPER_H_BANK,
  STYX_REGISTER_SUPER_H_R0B,
  STYX_REGISTER_SUPER_H_R1B,
  STYX_REGISTER_SUPER_H_R2B,
  STYX_REGISTER_SUPER_H_R3B,
  STYX_REGISTER_SUPER_H_R4B,
  STYX_REGISTER_SUPER_H_R5B,
  STYX_REGISTER_SUPER_H_R6B,
  STYX_REGISTER_SUPER_H_R7B,
  STYX_REGISTER_SUPER_H_R8B,
  STYX_REGISTER_SUPER_H_R9B,
  STYX_REGISTER_SUPER_H_R10B,
  STYX_REGISTER_SUPER_H_R11B,
  STYX_REGISTER_SUPER_H_R12B,
  STYX_REGISTER_SUPER_H_R13B,
  STYX_REGISTER_SUPER_H_R14B,
  STYX_REGISTER_SUPER_H_PCB,
  STYX_REGISTER_SUPER_H_PRB,
  STYX_REGISTER_SUPER_H_GBRB,
  STYX_REGISTER_SUPER_H_VBRB,
  STYX_REGISTER_SUPER_H_MACHB,
  STYX_REGISTER_SUPER_H_MACLB,
  STYX_REGISTER_SUPER_H_IVNB,
  STYX_REGISTER_SUPER_H_SSR,
  STYX_REGISTER_SUPER_H_SPC,
  STYX_REGISTER_SUPER_H_R0B0,
  STYX_REGISTER_SUPER_H_R1B0,
  STYX_REGISTER_SUPER_H_R2B0,
  STYX_REGISTER_SUPER_H_R3B0,
  STYX_REGISTER_SUPER_H_R4B0,
  STYX_REGISTER_SUPER_H_R5B0,
  STYX_REGISTER_SUPER_H_R6B0,
  STYX_REGISTER_SUPER_H_R7B0,
  STYX_REGISTER_SUPER_H_R0B1,
  STYX_REGISTER_SUPER_H_R1B1,
  STYX_REGISTER_SUPER_H_R2B1,
  STYX_REGISTER_SUPER_H_R3B1,
  STYX_REGISTER_SUPER_H_R4B1,
  STYX_REGISTER_SUPER_H_R5B1,
  STYX_REGISTER_SUPER_H_R6B1,
  STYX_REGISTER_SUPER_H_R7B1,
  STYX_REGISTER_SUPER_H_FV0,
  STYX_REGISTER_SUPER_H_FV4,
  STYX_REGISTER_SUPER_H_FV8,
  STYX_REGISTER_SUPER_H_FV12,
  STYX_REGISTER_MIPS64_R0,
  STYX_REGISTER_MIPS64_R1,
  STYX_REGISTER_MIPS64_R2,
  STYX_REGISTER_MIPS64_R3,
  STYX_REGISTER_MIPS64_R4,
  STYX_REGISTER_MIPS64_R5,
  STYX_REGISTER_MIPS64_R6,
  STYX_REGISTER_MIPS64_R7,
  STYX_REGISTER_MIPS64_R8,
  STYX_REGISTER_MIPS64_R9,
  STYX_REGISTER_MIPS64_R10,
  STYX_REGISTER_MIPS64_R11,
  STYX_REGISTER_MIPS64_R12,
  STYX_REGISTER_MIPS64_R13,
  STYX_REGISTER_MIPS64_R14,
  STYX_REGISTER_MIPS64_R15,
  STYX_REGISTER_MIPS64_R16,
  STYX_REGISTER_MIPS64_R17,
  STYX_REGISTER_MIPS64_R18,
  STYX_REGISTER_MIPS64_R19,
  STYX_REGISTER_MIPS64_R20,
  STYX_REGISTER_MIPS64_R21,
  STYX_REGISTER_MIPS64_R22,
  STYX_REGISTER_MIPS64_R23,
  STYX_REGISTER_MIPS64_R24,
  STYX_REGISTER_MIPS64_R25,
  STYX_REGISTER_MIPS64_R26,
  STYX_REGISTER_MIPS64_R27,
  STYX_REGISTER_MIPS64_R28,
  STYX_REGISTER_MIPS64_R29,
  STYX_REGISTER_MIPS64_R30,
  STYX_REGISTER_MIPS64_R31,
  STYX_REGISTER_MIPS64_HI,
  STYX_REGISTER_MIPS64_LO,
  STYX_REGISTER_MIPS64_PC,
  STYX_REGISTER_MIPS64_F0,
  STYX_REGISTER_MIPS64_F1,
  STYX_REGISTER_MIPS64_F2,
  STYX_REGISTER_MIPS64_F3,
  STYX_REGISTER_MIPS64_F4,
  STYX_REGISTER_MIPS64_F5,
  STYX_REGISTER_MIPS64_F6,
  STYX_REGISTER_MIPS64_F7,
  STYX_REGISTER_MIPS64_F8,
  STYX_REGISTER_MIPS64_F9,
  STYX_REGISTER_MIPS64_F10,
  STYX_REGISTER_MIPS64_F11,
  STYX_REGISTER_MIPS64_F12,
  STYX_REGISTER_MIPS64_F13,
  STYX_REGISTER_MIPS64_F14,
  STYX_REGISTER_MIPS64_F15,
  STYX_REGISTER_MIPS64_F16,
  STYX_REGISTER_MIPS64_F17,
  STYX_REGISTER_MIPS64_F18,
  STYX_REGISTER_MIPS64_F19,
  STYX_REGISTER_MIPS64_F20,
  STYX_REGISTER_MIPS64_F21,
  STYX_REGISTER_MIPS64_F22,
  STYX_REGISTER_MIPS64_F23,
  STYX_REGISTER_MIPS64_F24,
  STYX_REGISTER_MIPS64_F25,
  STYX_REGISTER_MIPS64_F26,
  STYX_REGISTER_MIPS64_F27,
  STYX_REGISTER_MIPS64_F28,
  STYX_REGISTER_MIPS64_F29,
  STYX_REGISTER_MIPS64_F30,
  STYX_REGISTER_MIPS64_F31,
  STYX_REGISTER_MIPS64_FIR,
  STYX_REGISTER_MIPS64_FCCR,
  STYX_REGISTER_MIPS64_FEXR,
  STYX_REGISTER_MIPS64_FENR,
  STYX_REGISTER_MIPS64_FCSR,
  STYX_REGISTER_MIPS64_AC0,
  STYX_REGISTER_MIPS64_AC1,
  STYX_REGISTER_MIPS64_AC2,
  STYX_REGISTER_MIPS64_AC3,
  STYX_REGISTER_MIPS64_HI0,
  STYX_REGISTER_MIPS64_HI1,
  STYX_REGISTER_MIPS64_HI2,
  STYX_REGISTER_MIPS64_HI3,
  STYX_REGISTER_MIPS64_LO0,
  STYX_REGISTER_MIPS64_LO1,
  STYX_REGISTER_MIPS64_LO2,
  STYX_REGISTER_MIPS64_LO3,
  STYX_REGISTER_MIPS64_DSP_CONTROL,
  STYX_REGISTER_MIPS64_MPL0,
  STYX_REGISTER_MIPS64_MPL1,
  STYX_REGISTER_MIPS64_MPL2,
  STYX_REGISTER_MIPS64_P0,
  STYX_REGISTER_MIPS64_P1,
  STYX_REGISTER_MIPS64_P2,
  STYX_REGISTER_MIPS64_CRC_IV,
  STYX_REGISTER_MIPS64_CRC_POLY,
  STYX_REGISTER_MIPS64_CRC_LEN,
  STYX_REGISTER_MIPS64_GFM_MUL,
  STYX_REGISTER_MIPS64_GFM_RES_INP,
  STYX_REGISTER_MIPS64_GFM_POLY,
  STYX_REGISTER_MIPS64_HASH_DAT,
  STYX_REGISTER_MIPS64_HASH_IV,
  STYX_REGISTER_MIPS64_THREE_DES_KEY,
  STYX_REGISTER_MIPS64_THREE_DESIV,
  STYX_REGISTER_MIPS64_THREE_DES_RESULT,
  STYX_REGISTER_MIPS64_AES_KEY,
  STYX_REGISTER_MIPS64_AES_KEY_LEN,
  STYX_REGISTER_MIPS64_AES_IV,
  STYX_REGISTER_MIPS64_AES_RES_INP,
  STYX_REGISTER_MIPS64_CVMSEG_LM,
} StyxRegister;

/**
 * A CPU that Styx supports emulation for.
 */
typedef enum StyxTarget {
  STYX_TARGET_CYCLONE_V,
  STYX_TARGET_MPC8XX,
  STYX_TARGET_PPC4XX,
  STYX_TARGET_KINETIS21,
  STYX_TARGET_STM32F107,
  STYX_TARGET_STM32F405,
  STYX_TARGET_BF512,
  STYX_TARGET_RAW,
  STYX_TARGET_SUPER_H2A,
} StyxTarget;

typedef char *StyxFFIErrorMsg_t;

typedef struct StyxFFIError {
  enum StyxFFIErrorKind kind;
  void *data;
} StyxFFIError;

typedef struct StyxFFIError *StyxFFIErrorPtr;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxHookToken_t;

typedef OpaquePointer_StyxHookToken_t StyxHookToken;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxProcessorCore_t;

typedef OpaquePointer_StyxProcessorCore_t StyxProcessorCore;

typedef void (*StyxHook_CodeCallback)(StyxProcessorCore cpu);

typedef struct StyxHook_Code {
  uint64_t start;
  uint64_t end;
  StyxHook_CodeCallback callback;
} StyxHook_Code;

typedef void *StyxHookUserData;

typedef void (*StyxHook_CodeDataCallback)(StyxProcessorCore, StyxHookUserData);

typedef struct StyxHook_CodeData {
  uint64_t start;
  uint64_t end;
  StyxHook_CodeDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_CodeData;

typedef void (*StyxHook_BlockCallback)(StyxProcessorCore cpu, uint64_t addr, uint32_t size);

typedef struct StyxHook_Block {
  StyxHook_BlockCallback callback;
} StyxHook_Block;

typedef void (*StyxHook_BlockDataCallback)(StyxProcessorCore,
                                           uint64_t addr,
                                           uint32_t size,
                                           StyxHookUserData);

typedef struct StyxHook_BlockData {
  StyxHook_BlockDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_BlockData;

typedef const uint8_t *ArrayPtr_u8;

typedef void (*StyxHook_MemoryWriteCallback)(StyxProcessorCore cpu,
                                             uint64_t addr,
                                             uint32_t size,
                                             ArrayPtr_u8 data);

typedef struct StyxHook_MemoryWrite {
  uint64_t start;
  uint64_t end;
  StyxHook_MemoryWriteCallback callback;
} StyxHook_MemoryWrite;

typedef void (*StyxHook_MemoryWriteDataCallback)(StyxProcessorCore,
                                                 uint64_t addr,
                                                 uint32_t size,
                                                 ArrayPtr_u8 data,
                                                 StyxHookUserData);

typedef struct StyxHook_MemoryWriteData {
  uint64_t start;
  uint64_t end;
  StyxHook_MemoryWriteDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_MemoryWriteData;

typedef uint8_t *ArrayPtrMut_u8;

typedef void (*StyxHook_MemoryReadCallback)(StyxProcessorCore cpu,
                                            uint64_t addr,
                                            uint32_t size,
                                            ArrayPtrMut_u8 data);

typedef struct StyxHook_MemoryRead {
  uint64_t start;
  uint64_t end;
  StyxHook_MemoryReadCallback callback;
} StyxHook_MemoryRead;

typedef void (*StyxHook_MemoryReadDataCallback)(StyxProcessorCore,
                                                uint64_t addr,
                                                uint32_t size,
                                                ArrayPtrMut_u8 data,
                                                StyxHookUserData);

typedef struct StyxHook_MemoryReadData {
  uint64_t start;
  uint64_t end;
  StyxHook_MemoryReadDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_MemoryReadData;

typedef void (*StyxHook_InterruptCallback)(StyxProcessorCore cpu, int32_t intno);

typedef struct StyxHook_Interrupt {
  StyxHook_InterruptCallback callback;
} StyxHook_Interrupt;

typedef void (*StyxHook_InterruptDataCallback)(StyxProcessorCore, int32_t intno, StyxHookUserData);

typedef struct StyxHook_InterruptData {
  StyxHook_InterruptDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_InterruptData;

typedef struct CBool {
  int _0;
} CBool;

typedef struct CBool (*StyxHook_InvalidInstructionCallback)(StyxProcessorCore cpu);

typedef struct StyxHook_InvalidInstruction {
  StyxHook_InvalidInstructionCallback callback;
} StyxHook_InvalidInstruction;

typedef struct CBool (*StyxHook_InvalidInstructionDataCallback)(StyxProcessorCore, StyxHookUserData);

typedef struct StyxHook_InvalidInstructionData {
  StyxHook_InvalidInstructionDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_InvalidInstructionData;

/**
 * standard section memory permissions
 */
typedef struct MemoryPermissions {
  Internal _0;
} MemoryPermissions;

/**
 * memory fault information
 *
 * NULL if the fault is a read fault
 * Non-Null uint8_t* if the fault is a write fault
 */
typedef ArrayPtr_u8 MemFaultData;

typedef struct CBool (*StyxHook_ProtectionFaultCallback)(StyxProcessorCore cpu,
                                                         uint64_t addr,
                                                         uint32_t size,
                                                         struct MemoryPermissions region_perms,
                                                         MemFaultData fault_data);

typedef struct StyxHook_ProtectionFault {
  uint64_t start;
  uint64_t end;
  StyxHook_ProtectionFaultCallback callback;
} StyxHook_ProtectionFault;

typedef struct CBool (*StyxHook_ProtectionFaultDataCallback)(StyxProcessorCore,
                                                             uint64_t addr,
                                                             uint32_t size,
                                                             struct MemoryPermissions region_perms,
                                                             MemFaultData fault_data,
                                                             StyxHookUserData);

typedef struct StyxHook_ProtectionFaultData {
  uint64_t start;
  uint64_t end;
  StyxHook_ProtectionFaultDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_ProtectionFaultData;

typedef struct CBool (*StyxHook_UnmappedFaultCallback)(StyxProcessorCore cpu,
                                                       uint64_t addr,
                                                       uint32_t size,
                                                       MemFaultData fault_data);

typedef struct StyxHook_UnmappedFault {
  uint64_t start;
  uint64_t end;
  StyxHook_UnmappedFaultCallback callback;
} StyxHook_UnmappedFault;

typedef struct CBool (*StyxHook_UnmappedFaultDataCallback)(StyxProcessorCore,
                                                           uint64_t addr,
                                                           uint32_t size,
                                                           MemFaultData fault_data,
                                                           StyxHookUserData);

typedef struct StyxHook_UnmappedFaultData {
  uint64_t start;
  uint64_t end;
  StyxHook_UnmappedFaultDataCallback callback;
  StyxHookUserData userdata;
} StyxHook_UnmappedFaultData;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxRegister_ArmCoProcessorDesc_t;

typedef OpaquePointer_StyxRegister_ArmCoProcessorDesc_t StyxRegister_ArmCoProcessorDesc;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxRegister_Ppc32SprDesc_t;

typedef OpaquePointer_StyxRegister_Ppc32SprDesc_t StyxRegister_Ppc32SprDesc;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxExecutor_t;

typedef OpaquePointer_StyxExecutor_t StyxExecutor;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxLoader_t;

typedef OpaquePointer_StyxLoader_t StyxLoader;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxPlugin_t;

typedef OpaquePointer_StyxPlugin_t StyxPlugin;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxProcessorBuilder_t;

typedef OpaquePointer_StyxProcessorBuilder_t StyxProcessorBuilder;

typedef const char *CStrPtr;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxProcessor_t;

typedef OpaquePointer_StyxProcessor_t StyxProcessor;

/**
 * A "safe" pointer type for managing styx resources across the FFI boundary
 *
 * This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
 * macro to create a wrapper type for this object
 */
typedef void *OpaquePointer_StyxEmulationReport_t;

typedef OpaquePointer_StyxEmulationReport_t StyxEmulationReport;

StyxFFIErrorMsg_t StyxFFIErrorMsg(struct StyxFFIError error);

void StyxFFIErrorMsg_free(StyxFFIErrorMsg_t msg);

void StyxFFIErrorPtr_free(StyxFFIErrorPtr *result);

/**
 * free the hook token's handle
 */
void StyxHookToken_free(StyxHookToken *ptr);

void StyxProcessorCore_free(StyxProcessorCore *ptr);

StyxFFIErrorPtr StyxProcessorCore_add_code_hook(StyxProcessorCore this_,
                                                struct StyxHook_Code hook,
                                                StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_code_data_hook(StyxProcessorCore this_,
                                                     struct StyxHook_CodeData hook,
                                                     StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_block_hook(StyxProcessorCore this_,
                                                 struct StyxHook_Block hook,
                                                 StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_block_data_hook(StyxProcessorCore this_,
                                                      struct StyxHook_BlockData hook,
                                                      StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_memory_write_hook(StyxProcessorCore this_,
                                                        struct StyxHook_MemoryWrite hook,
                                                        StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_memory_write_data_hook(StyxProcessorCore this_,
                                                             struct StyxHook_MemoryWriteData hook,
                                                             StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_memory_read_hook(StyxProcessorCore this_,
                                                       struct StyxHook_MemoryRead hook,
                                                       StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_memory_read_data_hook(StyxProcessorCore this_,
                                                            struct StyxHook_MemoryReadData hook,
                                                            StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_interrupt_hook(StyxProcessorCore this_,
                                                     struct StyxHook_Interrupt hook,
                                                     StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_interrupt_data_hook(StyxProcessorCore this_,
                                                          struct StyxHook_InterruptData hook,
                                                          StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_invalid_instruction_hook(StyxProcessorCore this_,
                                                               struct StyxHook_InvalidInstruction hook,
                                                               StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_invalid_instruction_data_hook(StyxProcessorCore this_,
                                                                    struct StyxHook_InvalidInstructionData hook,
                                                                    StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_protection_fault_hook(StyxProcessorCore this_,
                                                            struct StyxHook_ProtectionFault hook,
                                                            StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_protection_fault_data_hook(StyxProcessorCore this_,
                                                                 struct StyxHook_ProtectionFaultData hook,
                                                                 StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_unmapped_fault_hook(StyxProcessorCore this_,
                                                          struct StyxHook_UnmappedFault hook,
                                                          StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_add_unmapped_fault_data_hook(StyxProcessorCore this_,
                                                               struct StyxHook_UnmappedFaultData hook,
                                                               StyxHookToken *out);

StyxFFIErrorPtr StyxProcessorCore_pc(StyxProcessorCore this_, uint64_t *out);

/**
 * write memory from a pre-allocated buffer
 *
 * # Parameters
 *  - `bytes` must be of size >= `size`
 */
StyxFFIErrorPtr StyxProcessorCore_write_data(StyxProcessorCore this_,
                                             uint64_t address,
                                             uint32_t size,
                                             ArrayPtr_u8 bytes);

/**
 * read memory into a pre-allocated buffer
 *
 * # Parameters
 *  - `out` must be of size >= `size`
 */
StyxFFIErrorPtr StyxProcessorCore_read_data(StyxProcessorCore this_,
                                            uint64_t address,
                                            uint32_t size,
                                            ArrayPtrMut_u8 out);

/**
 * read an integer-based (no special registers) register, no matter what the size, to a u128
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_any(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    u128 *out);

/**
 * read an 8-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u8(StyxProcessorCore this_,
                                                   enum StyxRegister register_,
                                                   uint8_t *out);

/**
 * read a 16-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u16(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    uint16_t *out);

/**
 * read a 32-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u32(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    uint32_t *out);

/**
 * read a 40-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u40(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    uint64_t *out);

/**
 * read a 64-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u64(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    uint64_t *out);

/**
 * read an 80-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u80(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    u128 *out);

/**
 * read a 128-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_read_register_u128(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     u128 *out);

/**
 * write an integer-based (no special registers) register, no matter what the size, to a u128
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_any(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     u128 value);

/**
 * read an 8-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u8(StyxProcessorCore this_,
                                                    enum StyxRegister register_,
                                                    uint8_t value);

/**
 * read a 16-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u16(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     uint16_t value);

/**
 * read a 32-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u32(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     uint32_t value);

/**
 * read a 40-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u40(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     uint64_t value);

/**
 * read a 64-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u64(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     uint64_t value);

/**
 * read an 80-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u80(StyxProcessorCore this_,
                                                     enum StyxRegister register_,
                                                     u128 value);

/**
 * read a 128-bit register
 */
StyxFFIErrorPtr StyxProcessorCore_write_register_u128(StyxProcessorCore this_,
                                                      enum StyxRegister register_,
                                                      u128 value);

StyxFFIErrorPtr StyxRegister_ArmCoProcessorDesc_new(uint32_t coproc,
                                                    uint32_t crn,
                                                    uint32_t crm,
                                                    uint32_t opcode1,
                                                    uint32_t opcode2,
                                                    struct CBool security_state,
                                                    StyxRegister_ArmCoProcessorDesc *out);

void StyxRegister_ArmCoProcessorDesc_free(StyxRegister_ArmCoProcessorDesc *ptr);

StyxFFIErrorPtr StyxRegister_Ppc32SprDesc_new(uint16_t index, StyxRegister_Ppc32SprDesc *out);

void StyxRegister_Ppc32SprDesc_free(StyxRegister_Ppc32SprDesc *ptr);

void StyxExecutor_free(StyxExecutor *e);

/**
 * Creates a default Executor
 */
StyxFFIErrorPtr StyxExecutor_Executor_default(StyxExecutor *out);

void StyxLoader_free(StyxLoader *ptr);

StyxFFIErrorPtr StyxLoader_BlackfinLdrloader_new(StyxLoader *out);

StyxFFIErrorPtr StyxLoader_ElfLoader_new(StyxLoader *out);

StyxFFIErrorPtr StyxLoader_RawLoader_new(StyxLoader *out);

void StyxPlugin_free(StyxPlugin *ptr);

StyxFFIErrorPtr StyxPlugin_StyxTracePlugin_default(StyxPlugin *out);

StyxFFIErrorPtr StyxPlugin_ProcessorTracingPlugin_default(StyxPlugin *out);

/**
 * Create a new, default processor builder
 */
StyxFFIErrorPtr StyxProcessorBuilder_new(StyxProcessorBuilder *out);

void StyxProcessorBuilder_free(StyxProcessorBuilder *out);

StyxFFIErrorPtr StyxProcessorBuilder_set_target_program(StyxProcessorBuilder this_,
                                                        CStrPtr path,
                                                        uint32_t path_len);

StyxFFIErrorPtr StyxProcessorBuilder_set_input_bytes(StyxProcessorBuilder this_,
                                                     ArrayPtr_u8 bytes,
                                                     uint32_t len);

/**
 * Specify what the processor should do in case of an exception
 */
StyxFFIErrorPtr StyxProcessorBuilder_set_exception_behavior(StyxProcessorBuilder this_,
                                                            enum StyxExceptionBehavior behavior);

/**
 * Set the inter-processor communication (IPC) port for this processor (this should be unique). A
 * value of zero chooses an open port.
 */
StyxFFIErrorPtr StyxProcessorBuilder_set_ipc_port(StyxProcessorBuilder this_, uint16_t ipc_port);

StyxFFIErrorPtr StyxProcessorBuilder_add_plugin(StyxProcessorBuilder this_, StyxPlugin plugin);

StyxFFIErrorPtr StyxProcessorBuilder_set_executor(StyxProcessorBuilder this_,
                                                  StyxExecutor executor);

StyxFFIErrorPtr StyxProcessorBuilder_set_loader(StyxProcessorBuilder this_, StyxLoader loader);

/**
 * Set which backend the processor should use
 */
StyxFFIErrorPtr StyxProcessorBuilder_set_backend(StyxProcessorBuilder this_,
                                                 enum StyxBackend backend);

StyxFFIErrorPtr StyxProcessorBuilder_build(StyxProcessorBuilder this_,
                                           enum StyxTarget target,
                                           StyxProcessor *out);

StyxFFIErrorPtr StyxProcessorBuilder_add_code_hook(StyxProcessorBuilder this_,
                                                   struct StyxHook_Code hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_code_data_hook(StyxProcessorBuilder this_,
                                                        struct StyxHook_CodeData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_block_hook(StyxProcessorBuilder this_,
                                                    struct StyxHook_Block hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_block_data_hook(StyxProcessorBuilder this_,
                                                         struct StyxHook_BlockData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_memory_write_hook(StyxProcessorBuilder this_,
                                                           struct StyxHook_MemoryWrite hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_memory_write_data_hook(StyxProcessorBuilder this_,
                                                                struct StyxHook_MemoryWriteData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_memory_read_hook(StyxProcessorBuilder this_,
                                                          struct StyxHook_MemoryRead hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_memory_read_data_hook(StyxProcessorBuilder this_,
                                                               struct StyxHook_MemoryReadData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_interrupt_hook(StyxProcessorBuilder this_,
                                                        struct StyxHook_Interrupt hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_interrupt_data_hook(StyxProcessorBuilder this_,
                                                             struct StyxHook_InterruptData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_invalid_instruction_hook(StyxProcessorBuilder this_,
                                                                  struct StyxHook_InvalidInstruction hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_invalid_instruction_data_hook(StyxProcessorBuilder this_,
                                                                       struct StyxHook_InvalidInstructionData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_protection_fault_hook(StyxProcessorBuilder this_,
                                                               struct StyxHook_ProtectionFault hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_protection_fault_data_hook(StyxProcessorBuilder this_,
                                                                    struct StyxHook_ProtectionFaultData hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_unmapped_fault_hook(StyxProcessorBuilder this_,
                                                             struct StyxHook_UnmappedFault hook);

StyxFFIErrorPtr StyxProcessorBuilder_add_unmapped_fault_data_hook(StyxProcessorBuilder this_,
                                                                  struct StyxHook_UnmappedFaultData hook);

/**
 * disposes the processor handle
 */
void StyxProcessor_free(StyxProcessor *this_);

/**
 * Start the processor's emulation process, blocking on the current thread until the processor
 * exits.
 */
StyxFFIErrorPtr StyxProcessor_start_blocking(StyxProcessor processor, StyxEmulationReport *report);

/**
 * Start the processor's emulation process, blocking on the current thread until the processor
 * exits. Provide a limit to number of instructions to execute and milliseconds of wall execution
 * time. 0 for either of these values disables that timeout. 0 for both values will run until the
 * processor exits.
 */
StyxFFIErrorPtr StyxProcessor_start_blocking_constraints(StyxProcessor processor,
                                                         uint64_t instr,
                                                         uint64_t millis,
                                                         StyxEmulationReport *report);

void StyxEmulationReport_free(StyxEmulationReport *out);

uint64_t StyxEmulationReport_instructions(StyxEmulationReport this_);

/**
 * Initialize styx logging, this only has effect if you also add the StyxPlugin_StyxTracePlugin
 */
StyxFFIErrorPtr Styx_init_logging(uint32_t level_len, CStrPtr level);

#pragma GCC diagnostic pop
