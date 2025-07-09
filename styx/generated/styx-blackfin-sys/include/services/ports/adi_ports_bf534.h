/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            Port Configuration module header file for the System Services Library.

*********************************************************************************/


#ifndef __ADI_PORTS_H__
#define __ADI_PORTS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

#include <services/services.h>

#if !defined(__ADSP_BRAEMAR__)
#error "PORTS module not supported for the current processor family"
#endif

/* ****************************************************************************
 * RESULT CODES
 * ****************************************************************************
 */
enum {
    ADI_PORTS_RESULT_SUCCESS=0,                         // Generic success
    ADI_PORTS_RESULT_FAILED=1,                          // Generic failure

    ADI_PORTS_RESULT_START=ADI_PORTS_ENUMERATION_START, // insure this order remains
    ADI_PORTS_RESULT_BAD_DIRECTIVE,                     // (0x90001) A directive is invalid for the specified peripheral
    ADI_PORTS_RESULT_NULL_ARRAY                         // (0x90002) Array passed is NULL
};

typedef u32 ADI_PORTS_RESULT;


/* ****************************************************************************
 * FLAG PIN DEFINITIONS
 * ****************************************************************************
 */

#define ADI_PORTS_PORT_POS              (16)
#define ADI_PORTS_PIN_POS               (8)
#define ADI_PORTS_SHIFT_POS             (4)
#define ADI_PORTS_MASK_POS              (2)
#define ADI_PORTS_CMD_POS               (0)

#define ADI_PORTS_PORT_MASK             (0xFFFF0000)
#define ADI_PORTS_PIN_MASK              (0x0000FF00)
#define ADI_PORTS_SHIFT_MASK            (0x000000F0)
#define ADI_PORTS_MASK_MASK             (0x0000000C)
#define ADI_PORTS_CMD_MASK              (0x00000003)

#define ADI_PORTS_SET_PORT(PORT)            (( PORT << ADI_PORTS_PORT_POS ) & ADI_PORTS_PORT_MASK )
#define ADI_PORTS_SET_PIN(PIN)              (( PIN << ADI_PORTS_PIN_POS ) & ADI_PORTS_PIN_MASK )
#define ADI_PORTS_SET_SHIFT(SHIFT)          (( SHIFT << ADI_PORTS_SHIFT_POS ) &ADI_PORTS_SHIFT_MASK )
#define ADI_PORTS_SET_MASK(MASK)            (( MASK << ADI_PORTS_MASK_POS ) & ADI_PORTS_MASK_MASK )
#define ADI_PORTS_SET_CMD(CMD)              (( CMD << ADI_PORTS_CMD_POS ) & ADI_PORTS_CMD_MASK )

#define ADI_PORTS_GET_PORT(VALUE)           ( (VALUE & ADI_PORTS_PORT_MASK) >> ADI_PORTS_PORT_POS )
#define ADI_PORTS_GET_PIN(VALUE)            ( (VALUE & ADI_PORTS_PIN_MASK) >> ADI_PORTS_PIN_POS )
#define ADI_PORTS_GET_SHIFT(VALUE)          ( (VALUE & ADI_PORTS_SHIFT_MASK) >> ADI_PORTS_SHIFT_POS )
#define ADI_PORTS_GET_MASK(VALUE)           ( (VALUE & ADI_PORTS_MASK_MASK) >> ADI_PORTS_MASK_POS )
#define ADI_PORTS_GET_CMD(VALUE)            ( (VALUE & ADI_PORTS_CMD_MASK) >> ADI_PORTS_CMD_POS )

#define ADI_PORTS_GET_MUX_MASK(VALUE) ( ADI_PORTS_GET_MASK(VALUE) << ADI_PORTS_GET_SHIFT(VALUE) )

// macro to create a mask that can be used to check against the flag's registers
#define ADI_PORTS_GET_PIN_MASK(VALUE)   (1 << ADI_PORTS_GET_PIN(VALUE))

#define ADI_PORTS_PIN_ENUM_VALUE(FLAG,MASK,SHIFT,CMD) \
    ( ADI_PORTS_SET_PORT(ADI_FLAG_GET_PORT(FLAG)) )  | \
    ( ADI_PORTS_SET_PIN(ADI_FLAG_GET_BIT(FLAG)) )  | \
    ( ADI_PORTS_SET_SHIFT(SHIFT) ) | \
    ( ADI_PORTS_SET_MASK(MASK) )  | \
    ( ADI_PORTS_SET_CMD(CMD) )


enum {
    ADI_PORTS_SHIFT_PJSE=0,
    ADI_PORTS_SHIFT_PJCE=1,
    ADI_PORTS_SHIFT_PFDE=3,
    ADI_PORTS_SHIFT_PFTE,
    ADI_PORTS_SHIFT_PFS6E,
    ADI_PORTS_SHIFT_PFS5E,
    ADI_PORTS_SHIFT_PFS4E,
    ADI_PORTS_SHIFT_PFFE,
    ADI_PORTS_SHIFT_PGSE,
    ADI_PORTS_SHIFT_PGRE,
    ADI_PORTS_SHIFT_PGTE
};

enum {
    ADI_PORTS_MUX_CMD_NONE=0,
    ADI_PORTS_MUX_CMD_SET,
    ADI_PORTS_MUX_CMD_CLR
};

#define ADI_PORTS_RESVD 0


// Since Port J pins cannot be used as GPIO there are no
// PORTJ_FER registers. The 0xff00 offset in the following
// is fictitious
#define ADI_PORTS_PJ4  ADI_FLAG_CREATE_FLAG_ID(4,   0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ5  ADI_FLAG_CREATE_FLAG_ID(5,   0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ6  ADI_FLAG_CREATE_FLAG_ID(6,   0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ7  ADI_FLAG_CREATE_FLAG_ID(7,   0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ8  ADI_FLAG_CREATE_FLAG_ID(8,   0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ9  ADI_FLAG_CREATE_FLAG_ID(9,   0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ10 ADI_FLAG_CREATE_FLAG_ID(10,  0x00ff, 0,  0,  0)
#define ADI_PORTS_PJ11 ADI_FLAG_CREATE_FLAG_ID(11,  0x00ff, 0,  0,  0)

// the following macro can be used to identify a PORTJ pin
//#define ADI_PORTS_IS_PORTJ(F) ((F&0xff00)==0xff00)

enum {
    // Pin configuration data for PPI
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_PPI_FS1   = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF9,       0,      0,                    ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PPI_FS2   = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF8,       0,      0,                    ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PPI_FS3   = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF7,       1,      ADI_PORTS_SHIFT_PFFE, ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_PPI_CLK   = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF15,      0,      0,                    ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PPI_D0    = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG0,       0,      0,                    ADI_PORTS_MUX_CMD_NONE ),

    // pin configuration data for SPI
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_SPI_SPISS = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF14,      0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPI_SCK   = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF13,      0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPI_MOSI  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF11,      0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPI_MISO  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF12,      0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPI_SSEL1 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF10,      0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPI_SSEL2 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ11,     1,  ADI_PORTS_SHIFT_PJSE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPI_SSEL3 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ10,     1,  ADI_PORTS_SHIFT_PJSE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPI_SSEL4 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF6,       1,  ADI_PORTS_SHIFT_PFS4E,  ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPI_SSEL5 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF5,       1,  ADI_PORTS_SHIFT_PFS5E,  ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPI_SSEL6 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF4,       1,  ADI_PORTS_SHIFT_PFS6E,  ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPI_SSEL7 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ5,      2,  ADI_PORTS_SHIFT_PJCE,   ADI_PORTS_MUX_CMD_SET ),

    // pin configuration data for SPORT0
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_SPORT0_RSCLK = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ6,   0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPORT0_RFS = ADI_PORTS_PIN_ENUM_VALUE(   ADI_PORTS_PJ7,   0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPORT0_DRPRI = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ8,   0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPORT0_DRSEC = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ4,   3,  ADI_PORTS_SHIFT_PJCE,   ADI_PORTS_MUX_CMD_CLR  ),
    ADI_PORTS_SPORT0_TSCLK = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ9,   1,  ADI_PORTS_SHIFT_PJSE,   ADI_PORTS_MUX_CMD_CLR  ),
    ADI_PORTS_SPORT0_TFS = ADI_PORTS_PIN_ENUM_VALUE(   ADI_PORTS_PJ10,  0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_SPORT0_DTPRI = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ11,  0,  ADI_PORTS_SHIFT_PJSE,   ADI_PORTS_MUX_CMD_CLR  ),
    ADI_PORTS_SPORT0_DTSEC = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ5,   3,  ADI_PORTS_SHIFT_PJCE,   ADI_PORTS_MUX_CMD_CLR  ),

    // pin configuration data for SPORT1
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_SPORT1_RSCLK = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG10,   1,  ADI_PORTS_SHIFT_PGRE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_RFS = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PG11,   1,  ADI_PORTS_SHIFT_PGRE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_DRPRI = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG12,   1,  ADI_PORTS_SHIFT_PGRE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_DRSEC = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG8,    1,  ADI_PORTS_SHIFT_PGSE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_TSCLK = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG13,   1,  ADI_PORTS_SHIFT_PGTE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_TFS = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PG14,   1,  ADI_PORTS_SHIFT_PGTE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_DTPRI = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG15,   1,  ADI_PORTS_SHIFT_PGTE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_SPORT1_DTSEC = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG9,    1,  ADI_PORTS_SHIFT_PGSE,   ADI_PORTS_MUX_CMD_SET ),

    // pin configuration data for UART0
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_UART0_TX = ADI_PORTS_PIN_ENUM_VALUE(  ADI_FLAG_PF0,       1,  ADI_PORTS_SHIFT_PFDE,   ADI_PORTS_MUX_CMD_CLR),
    ADI_PORTS_UART0_RX = ADI_PORTS_PIN_ENUM_VALUE(  ADI_FLAG_PF1,       1,  ADI_PORTS_SHIFT_PFDE,   ADI_PORTS_MUX_CMD_CLR),

    // pin configuration data for UART1
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_UART1_TX = ADI_PORTS_PIN_ENUM_VALUE(  ADI_FLAG_PF2,       1,  ADI_PORTS_SHIFT_PFTE,   ADI_PORTS_MUX_CMD_CLR),
    ADI_PORTS_UART1_RX = ADI_PORTS_PIN_ENUM_VALUE(  ADI_FLAG_PF3,       1,  ADI_PORTS_SHIFT_PFTE,   ADI_PORTS_MUX_CMD_CLR),

    // pin configuration data for CAN
    //                                                  port,pin,    mask,  shift,                  cmd
    ADI_PORTS_CAN_TX = ADI_PORTS_PIN_ENUM_VALUE(    ADI_PORTS_PJ5,      1,  ADI_PORTS_SHIFT_PJCE,   ADI_PORTS_MUX_CMD_SET),
    ADI_PORTS_CAN_RX = ADI_PORTS_PIN_ENUM_VALUE(    ADI_PORTS_PJ4,      1,  ADI_PORTS_SHIFT_PJCE,   ADI_PORTS_MUX_CMD_SET),

    // pin configuration data for Timers
    //                                                  port,pin,        mask,  shift,                  cmd
    ADI_PORTS_TIMER_TMR_CLK = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF15,      0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TMR0 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF9,        0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TMR1 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF8,        0,  0,                      ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TMR2 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF7,        1,  ADI_PORTS_SHIFT_PFFE,   ADI_PORTS_MUX_CMD_CLR ),
    ADI_PORTS_TIMER_TMR3 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF6,        1,  ADI_PORTS_SHIFT_PFS4E,  ADI_PORTS_MUX_CMD_CLR ),
    ADI_PORTS_TIMER_TMR4 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF5,        1,  ADI_PORTS_SHIFT_PFS5E,  ADI_PORTS_MUX_CMD_CLR ),
    ADI_PORTS_TIMER_TMR5 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF4,        1,  ADI_PORTS_SHIFT_PFS6E,  ADI_PORTS_MUX_CMD_CLR ),
    ADI_PORTS_TIMER_TMR6 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF3,        1,  ADI_PORTS_SHIFT_PFTE,   ADI_PORTS_MUX_CMD_SET ),
    ADI_PORTS_TIMER_TMR7 = ADI_PORTS_PIN_ENUM_VALUE(   ADI_FLAG_PF2,        1,  ADI_PORTS_SHIFT_PFTE,   ADI_PORTS_MUX_CMD_SET ),
#if 0
    // These are really NOPs as far as port control is concerned
    ADI_PORTS_TIMER_TACLK0 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF14,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK1 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ9,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK2 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ6,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK3 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ7,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK4 = ADI_PORTS_PIN_ENUM_VALUE( ADI_PORTS_PJ8,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK5 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH12,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK6 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH13,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_TIMER_TACLK7 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH14,       0,  0,  ADI_PORTS_MUX_CMD_NONE ),

    ADI_PORTS_TIMER_TACI0 = ADI_PORTS_PIN_ENUM_VALUE(  ADI_PORTS_PJ4,       1,  ADI_PORTS_SHIFT_PJCE,   ADI_PORTS_MUX_CMD_SET),
    ADI_PORTS_TIMER_TACI1 = ADI_PORTS_PIN_ENUM_VALUE(  ADI_FLAG_PF1,        1,  ADI_PORTS_SHIFT_PFDE,   ADI_PORTS_MUX_CMD_CLR ),
    ADI_PORTS_TIMER_TACI6 = ADI_PORTS_PIN_ENUM_VALUE(  ADI_FLAG_PF3,        1,  ADI_PORTS_SHIFT_PFTE,   ADI_PORTS_MUX_CMD_CLR ),
#endif
    // pin configuration data for gpio flags
    //                                                  port,pin,   mask,   shift,                  cmd
    ADI_PORTS_PF0  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF0,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF1  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF1,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF2  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF2,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF3  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF3,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF4  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF4,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF5  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF5,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF6  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF6,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF7  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF7,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF8  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF8,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF9  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF9,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF10 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF10,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF11 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF11,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF12 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF12,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF13 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF13,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF14 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF14,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PF15 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PF15,   0,      0, ADI_PORTS_MUX_CMD_NONE ),

    ADI_PORTS_PG0  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG0,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG1  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG1,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG2  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG2,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG3  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG3,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG4  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG4,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG5  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG5,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG6  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG6,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG7  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG7,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG8  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG8,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG9  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG9,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG10 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG10,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG11 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG11,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG12 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG12,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG13 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG13,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG14 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG14,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PG15 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PG15,   0,      0, ADI_PORTS_MUX_CMD_NONE ),

    ADI_PORTS_PH0  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH0,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH1  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH1,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH2  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH2,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH3  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH3,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH4  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH4,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH5  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH5,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH6  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH6,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH7  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH7,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH8  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH8,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH9  = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH9,    0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH10 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH10,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH11 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH11,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH12 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH12,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH13 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH13,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH14 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH14,   0,      0, ADI_PORTS_MUX_CMD_NONE ),
    ADI_PORTS_PH15 = ADI_PORTS_PIN_ENUM_VALUE( ADI_FLAG_PH15,   0,      0, ADI_PORTS_MUX_CMD_NONE )
};


/* ****************************************************************************
 * DIRECTIVE CODES
 * ( Some directive values are synonyms for the above flag configuration values)
 * ****************************************************************************
 */

enum {

    ADI_PORTS_DIR_PPI_BASE,                     // Enable pins for basic PPI operation
    ADI_PORTS_DIR_PPI_FS3,                      // Enable pin for 3rd PPI frame sync

    ADI_PORTS_DIR_SPI_BASE,                     // Enable pins for basic SPI operation
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_1 = ADI_PORTS_SPI_SSEL1,         // Enable pins for SPI Slave Select 1
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_2 = ADI_PORTS_SPI_SSEL2,         // Enable pins for SPI Slave Select 2
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_3 = ADI_PORTS_SPI_SSEL3,         // Enable pins for SPI Slave Select 3
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_4 = ADI_PORTS_SPI_SSEL4,         // Enable pins for SPI Slave Select 4
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_5 = ADI_PORTS_SPI_SSEL5,         // Enable pins for SPI Slave Select 5
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_6 = ADI_PORTS_SPI_SSEL6,         // Enable pins for SPI Slave Select 6
    ADI_PORTS_DIR_SPI_SLAVE_SELECT_7 = ADI_PORTS_SPI_SSEL7,         // Enable pins for SPI Slave Select 7

    ADI_PORTS_DIR_SPORT0_BASE_RX,               // Enable pins for basic SPORT RX0 operation
    ADI_PORTS_DIR_SPORT0_BASE_TX,               // Enable pins for basic SPORT TX0 operation
    ADI_PORTS_DIR_SPORT0_RXSE,                  // Enable pin for SPORT0 RX secondary data
    ADI_PORTS_DIR_SPORT0_TXSE,                  // Enable pin for SPORT0 TX secondary data
    ADI_PORTS_DIR_SPORT1_BASE_RX,               // Enable pins for basic SPORT1 RX operation
    ADI_PORTS_DIR_SPORT1_BASE_TX,               // Enable pins for basic SPORT1 TX operation
    ADI_PORTS_DIR_SPORT1_RXSE = ADI_PORTS_SPORT1_DRSEC,                 // Enable pin for SPORT1 RX secondary data
    ADI_PORTS_DIR_SPORT1_TXSE = ADI_PORTS_SPORT1_DTSEC,                 // Enable pin for SPORT1 TX secondary data

    ADI_PORTS_DIR_UART0_RX = ADI_PORTS_UART0_RX,                        // Enable pins for UART0 RX operation
    ADI_PORTS_DIR_UART0_TX = ADI_PORTS_UART0_TX,                        // Enable pins for UART0 TX operation
    ADI_PORTS_DIR_UART1_RX = ADI_PORTS_UART1_RX,                        // Enable pins for UART1 RX operation
    ADI_PORTS_DIR_UART1_TX = ADI_PORTS_UART1_TX,                        // Enable pins for UART1 TX operation

    ADI_PORTS_DIR_CAN_RX = ADI_PORTS_CAN_RX,                            // Enable pins for CAN RX operation
    ADI_PORTS_DIR_CAN_TX = ADI_PORTS_CAN_TX,                            // Enable pins for CAN TX operation

    ADI_PORTS_DIR_TMR_CLK = ADI_PORTS_TIMER_TMR_CLK,
    ADI_PORTS_DIR_TMR_0 = ADI_PORTS_TIMER_TMR0,
    ADI_PORTS_DIR_TMR_1 = ADI_PORTS_TIMER_TMR1,
    ADI_PORTS_DIR_TMR_2 = ADI_PORTS_TIMER_TMR2,
    ADI_PORTS_DIR_TMR_3 = ADI_PORTS_TIMER_TMR3,
    ADI_PORTS_DIR_TMR_4 = ADI_PORTS_TIMER_TMR4,
    ADI_PORTS_DIR_TMR_5 = ADI_PORTS_TIMER_TMR5,
    ADI_PORTS_DIR_TMR_6 = ADI_PORTS_TIMER_TMR6,
    ADI_PORTS_DIR_TMR_7 = ADI_PORTS_TIMER_TMR7,

#if 0
    ADI_PORTS_DIR_TACLK_0 = ADI_PORTS_TIMER_TACLK0,
    ADI_PORTS_DIR_TACLK_1 = ADI_PORTS_TIMER_TACLK1,
    ADI_PORTS_DIR_TACLK_2 = ADI_PORTS_TIMER_TACLK2,
    ADI_PORTS_DIR_TACLK_3 = ADI_PORTS_TIMER_TACLK3,
    ADI_PORTS_DIR_TACLK_4 = ADI_PORTS_TIMER_TACLK4,
    ADI_PORTS_DIR_TACLK_5 = ADI_PORTS_TIMER_TACLK5,
    ADI_PORTS_DIR_TACLK_6 = ADI_PORTS_TIMER_TACLK6,
    ADI_PORTS_DIR_TACLK_7 = ADI_PORTS_TIMER_TACLK7,

    ADI_PORTS_DIR_TACI_0 = ADI_PORTS_TIMER_TACI0,
    ADI_PORTS_DIR_TACI_1 = ADI_PORTS_TIMER_TACI1,
    ADI_PORTS_DIR_TACI_6 = ADI_PORTS_TIMER_TACI6,
#endif

    ADI_PORTS_DIR_GPIO_PF0 = ADI_PORTS_PF0,          // Enable PF0 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF1 = ADI_PORTS_PF1,          // Enable PF1 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF2 = ADI_PORTS_PF2,          // Enable PF2 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF3 = ADI_PORTS_PF3,          // Enable PF3 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF4 = ADI_PORTS_PF4,          // Enable PF4 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF5 = ADI_PORTS_PF5,          // Enable PF5 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF6 = ADI_PORTS_PF6,          // Enable PF6 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF7 = ADI_PORTS_PF7,          // Enable PF7 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF8 = ADI_PORTS_PF8,          // Enable PF8 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF9 = ADI_PORTS_PF9,          // Enable PF9 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF10 = ADI_PORTS_PF10,        // Enable PF10 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF11 = ADI_PORTS_PF11,        // Enable PF11 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF12 = ADI_PORTS_PF12,        // Enable PF12 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF13 = ADI_PORTS_PF13,        // Enable PF13 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF14 = ADI_PORTS_PF14,        // Enable PF14 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PF15 = ADI_PORTS_PF15,        // Enable PF15 pin for GPIO use

    ADI_PORTS_DIR_GPIO_PG0 = ADI_PORTS_PG0,          // Enable PG0 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG1 = ADI_PORTS_PG1,          // Enable PG1 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG2 = ADI_PORTS_PG2,          // Enable PG2 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG3 = ADI_PORTS_PG3,          // Enable PG3 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG4 = ADI_PORTS_PG4,          // Enable PG4 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG5 = ADI_PORTS_PG5,          // Enable PG5 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG6 = ADI_PORTS_PG6,          // Enable PG6 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG7 = ADI_PORTS_PG7,          // Enable PG7 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG8 = ADI_PORTS_PG8,          // Enable PG8 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG9 = ADI_PORTS_PG9,          // Enable PG9 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG10 = ADI_PORTS_PG10,        // Enable PG10 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG11 = ADI_PORTS_PG11,        // Enable PG11 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG12 = ADI_PORTS_PG12,        // Enable PG12 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG13 = ADI_PORTS_PG13,        // Enable PG13 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG14 = ADI_PORTS_PG14,        // Enable PG14 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PG15 = ADI_PORTS_PG15,        // Enable PG15 pin for GPIO use

    ADI_PORTS_DIR_GPIO_PH0 = ADI_PORTS_PH0,          // Enable PH0 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH1 = ADI_PORTS_PH1,          // Enable PH1 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH2 = ADI_PORTS_PH2,          // Enable PH2 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH3 = ADI_PORTS_PH3,          // Enable PH3 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH4 = ADI_PORTS_PH4,          // Enable PH4 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH5 = ADI_PORTS_PH5,          // Enable PH5 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH6 = ADI_PORTS_PH6,          // Enable PH6 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH7 = ADI_PORTS_PH7,          // Enable PH7 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH8 = ADI_PORTS_PH8,          // Enable PH8 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH9 = ADI_PORTS_PH9,          // Enable PH9 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH10 = ADI_PORTS_PH10,        // Enable PH10 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH11 = ADI_PORTS_PH11,        // Enable PH11 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH12 = ADI_PORTS_PH12,        // Enable PH12 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH13 = ADI_PORTS_PH13,        // Enable PH13 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH14 = ADI_PORTS_PH14,        // Enable PH14 pin for GPIO use
    ADI_PORTS_DIR_GPIO_PH15 = ADI_PORTS_PH15         // Enable PH15 pin for GPIO use
};

/* ****************************************************************************
 * PROFILE structure
 * contains values of PORTx_FER & PORT_MUX registers.
 * ****************************************************************************
 */

typedef struct {
    u16 portf_fer;
    u16 portg_fer;
    u16 porth_fer;
    u16 port_mux;
} ADI_PORTS_PROFILE;

/////////////////
// API functions
/////////////////

#ifdef __cplusplus
extern "C" {
#endif


ADI_PORTS_RESULT
adi_ports_Init(             // initializes the ports service
    void    *pCriticalRegionArg             // parameter for critical region function
);

ADI_PORTS_RESULT
adi_ports_Terminate(            // terminates the Ports service
    void
);


ADI_PORTS_RESULT
adi_ports_EnablePPI(        // Enables the pins for PPI
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );
ADI_PORTS_RESULT
adi_ports_EnableSPI(        // Enables the pins for SPI
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );

ADI_PORTS_RESULT
adi_ports_EnableSPORT(      // Enables the pins for SPORT
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );

ADI_PORTS_RESULT
adi_ports_EnableUART(       // Enables the pins for UART
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );

ADI_PORTS_RESULT
adi_ports_EnableCAN(        // Enables the pins for CAN
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );

ADI_PORTS_RESULT
adi_ports_EnableTimer(      // Enables the pins for GP Timer
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );

ADI_PORTS_RESULT
adi_ports_EnableGPIO(       // Enables the pins for GPIO
                   u32 *Directives,         // array of directives
                   u32 nDirectives,         // number of directives
                   u32 Enable               // Enable(1)/Disable(0) flag
                   );

ADI_PORTS_RESULT
adi_ports_GetProfile(       // Retrieves the profile information
                   ADI_PORTS_PROFILE *profile           // profile structure
                   );

ADI_PORTS_RESULT
adi_ports_SetProfile(       // Applies a profile
                   ADI_PORTS_PROFILE *profile           // profile structure
                   );

ADI_PORTS_RESULT
adi_ports_ClearProfile(     // Clears a profile
                   ADI_PORTS_PROFILE *profile           // profile structure
                   );

#ifdef __cplusplus
}
#endif

/* ***********************************************************************************************

Examples

(A) PPI (for 16 bit data width and whatever PPI_CONTROL infers)

{
    u32 PPIPins[] = {
        ADI_PORTS_PPI_BASE,
    };
    adi_ports_EnablePPI(0, (void*)PPIPins, sizeof(PPIPins), 1);
}

  ***********************************************************************************************/

#endif // Not ASM

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_PORTS_H__ */
