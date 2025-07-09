/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the header file for the Programmable flags module ot the
            System Services Library.

*********************************************************************************/

#ifndef __ADI_FLAG_H__
#define __ADI_FLAG_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)


/*********************************************************************
* Macros for the memory usage of the Flag Manager
*********************************************************************/

#if defined(__ADSP_MOAB__)
#define ADI_FLAG_CALLBACK_MEMORY        (32)        // amount of memory (in bytes) needed for each callback
#else
#define ADI_FLAG_CALLBACK_MEMORY        (20)        // amount of memory (in bytes) needed for each callback
#endif

/*********************************************************************

Various macros used by the flag manager

Application code does not use these macros but rather are used by the
flag manager to control the flags.  Applications only need to use the
enumeration values, such as ADI_FLAG_PF0.

*********************************************************************/
/*
Flag ID enumerations are concatenations of several pieces of information
for the flag. A flag ID enumerator consists of:

    o bit 0-7   - port number (starting at 0 and incrementing by 1) (range 0-255)
    o bit 8-11  - PINTx, mask indicating which PINTx regs the flag can use (ie. 0x5 -> PINT0 and PINT2)
    o bit 12-15 - PINTxByte, mask indicating which bytes within PINTx regs the flag can use (ie. 0x5 -> byte0 and byte2)
    o bit 16-19 - bit within the flag registers for the given flag (range 0-15)
    o bit 20-23 - not used
    o bit 24-27 - value to write into pINTx_ASSIGN (range 0-15)
    o bit 28-31 - not used

NOTE: Edinburgh, Braemar, Teton, Stirling, Brodie, Kookaburra, Mockingbird and Moy families
only use the "port number" and "bit with the flag registers" fields.
The Moab family uses all fields.

Macros are provided to create the actual flag ID enumerator and to
extract each of the fields within the value.
*/


// macro to create the flag ID
#define ADI_FLAG_CREATE_FLAG_ID(Bit,Port,PINTx,PINTxByte,Value)  (((Value) << 24) | ((Bit) << 16) | ((PINTxByte) << 12) | ((PINTx) << 8) | (Port))

// macros to get the individual field values
#define ADI_FLAG_GET_VALUE(FlagID)      ((((u32)FlagID) >> 24) & 0xf)
#define ADI_FLAG_GET_BIT(FlagID)        ((((u32)FlagID) >> 16) & 0xf)
#define ADI_FLAG_GET_PINTXBYTE(FlagID)  ((((u32)FlagID) >> 12) & 0xf)
#define ADI_FLAG_GET_PINTX(FlagID)      ((((u32)FlagID) >>  8) & 0xf)
#define ADI_FLAG_GET_PORT(FlagID)       ((((u32)FlagID)      ) & 0xff)

// macro to create a mask that can be used to check against the flag's registers
#define ADI_FLAG_GET_MASK(FlagID)   (1 << ADI_FLAG_GET_BIT(FlagID))



/*********************************************************************
* Flag IDs
*********************************************************************/

/********************
    Edinburgh
********************/

#if defined(__ADSP_EDINBURGH__)     // flag IDs for BF531, BF532, BF533

typedef enum ADI_FLAG_ID {
    ADI_FLAG_PF0        = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0,  0,  0), // pf0
    ADI_FLAG_PF1        = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0,  0,  0), // pf1
    ADI_FLAG_PF2        = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0,  0,  0), // pf2
    ADI_FLAG_PF3        = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0,  0,  0), // pf3
    ADI_FLAG_PF4        = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0,  0,  0), // pf4
    ADI_FLAG_PF5        = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0,  0,  0), // pf5
    ADI_FLAG_PF6        = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0,  0,  0), // pf6
    ADI_FLAG_PF7        = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0,  0,  0), // pf7
    ADI_FLAG_PF8        = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0,  0,  0), // pf8
    ADI_FLAG_PF9        = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0,  0,  0), // pf9
    ADI_FLAG_PF10       = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0,  0,  0), // pf10
    ADI_FLAG_PF11       = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0,  0,  0), // pf12
    ADI_FLAG_PF12       = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0,  0,  0), // pf13
    ADI_FLAG_PF13       = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0,  0,  0), // pf14
    ADI_FLAG_PF14       = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0,  0,  0), // pf15
    ADI_FLAG_PF15       = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0,  0,  0), // pf16

    ADI_FLAG_UNDEFINED  = -1                                            // invalid flagID

} ADI_FLAG_ID;

#endif


/********************
    Braemar
********************/

#if defined(__ADSP_BRAEMAR__)   // flag IDs for BF534, BF536, BF537

typedef enum ADI_FLAG_ID {
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0,  0,  0), // pf0
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0,  0,  0), // pf1
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0,  0,  0), // pf2
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0,  0,  0), // pf3
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0,  0,  0), // pf4
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0,  0,  0), // pf5
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0,  0,  0), // pf6
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0,  0,  0), // pf7
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0,  0,  0), // pf8
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0,  0,  0), // pf9
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0,  0,  0), // pf10
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0,  0,  0), // pf11
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0,  0,  0), // pf12
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0,  0,  0), // pf13
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0,  0,  0), // pf14
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0,  0,  0), // pf15

    ADI_FLAG_PG0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0,  0,  0), // pg0
    ADI_FLAG_PG1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0,  0,  0), // pg1
    ADI_FLAG_PG2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0,  0,  0), // pg2
    ADI_FLAG_PG3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0,  0,  0), // pg3
    ADI_FLAG_PG4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0,  0,  0), // pg4
    ADI_FLAG_PG5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0,  0,  0), // pg5
    ADI_FLAG_PG6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0,  0,  0), // pg6
    ADI_FLAG_PG7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0,  0,  0), // pg7
    ADI_FLAG_PG8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0,  0,  0), // pg8
    ADI_FLAG_PG9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0,  0,  0), // pg9
    ADI_FLAG_PG10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0,  0,  0), // pg10
    ADI_FLAG_PG11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0,  0,  0), // pg11
    ADI_FLAG_PG12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0,  0,  0), // pg12
    ADI_FLAG_PG13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0,  0,  0), // pg13
    ADI_FLAG_PG14   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0,  0,  0), // pg14
    ADI_FLAG_PG15   = ADI_FLAG_CREATE_FLAG_ID(15,   1,  0,  0,  0), // pg15

    ADI_FLAG_PH0    = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0,  0,  0), // ph0
    ADI_FLAG_PH1    = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0,  0,  0), // ph1
    ADI_FLAG_PH2    = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0,  0,  0), // ph2
    ADI_FLAG_PH3    = ADI_FLAG_CREATE_FLAG_ID(3,    2,  0,  0,  0), // ph3
    ADI_FLAG_PH4    = ADI_FLAG_CREATE_FLAG_ID(4,    2,  0,  0,  0), // ph4
    ADI_FLAG_PH5    = ADI_FLAG_CREATE_FLAG_ID(5,    2,  0,  0,  0), // ph5
    ADI_FLAG_PH6    = ADI_FLAG_CREATE_FLAG_ID(6,    2,  0,  0,  0), // ph6
    ADI_FLAG_PH7    = ADI_FLAG_CREATE_FLAG_ID(7,    2,  0,  0,  0), // ph7
    ADI_FLAG_PH8    = ADI_FLAG_CREATE_FLAG_ID(8,    2,  0,  0,  0), // ph8
    ADI_FLAG_PH9    = ADI_FLAG_CREATE_FLAG_ID(9,    2,  0,  0,  0), // ph9
    ADI_FLAG_PH10   = ADI_FLAG_CREATE_FLAG_ID(10,   2,  0,  0,  0), // ph10
    ADI_FLAG_PH11   = ADI_FLAG_CREATE_FLAG_ID(11,   2,  0,  0,  0), // ph11
    ADI_FLAG_PH12   = ADI_FLAG_CREATE_FLAG_ID(12,   2,  0,  0,  0), // ph12
    ADI_FLAG_PH13   = ADI_FLAG_CREATE_FLAG_ID(13,   2,  0,  0,  0), // ph13
    ADI_FLAG_PH14   = ADI_FLAG_CREATE_FLAG_ID(14,   2,  0,  0,  0), // ph14
    ADI_FLAG_PH15   = ADI_FLAG_CREATE_FLAG_ID(15,   2,  0,  0,  0), // ph15

    ADI_FLAG_UNDEFINED  = -1                                        // invalid flagID

} ADI_FLAG_ID;

#endif


/********************
    Teton
********************/

#if defined(__ADSP_TETON__)     // flag IDs for BF561

typedef enum ADI_FLAG_ID {
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0,  0,  0), // pf0
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0,  0,  0), // pf1
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0,  0,  0), // pf2
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0,  0,  0), // pf3
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0,  0,  0), // pf4
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0,  0,  0), // pf5
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0,  0,  0), // pf6
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0,  0,  0), // pf7
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0,  0,  0), // pf8
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0,  0,  0), // pf9
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0,  0,  0), // pf10
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0,  0,  0), // pf11
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0,  0,  0), // pf12
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0,  0,  0), // pf13
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0,  0,  0), // pf14
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0,  0,  0), // pf15

    ADI_FLAG_PF16   = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0,  0,  0), // pf16
    ADI_FLAG_PF17   = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0,  0,  0), // pf17
    ADI_FLAG_PF18   = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0,  0,  0), // pf18
    ADI_FLAG_PF19   = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0,  0,  0), // pf19
    ADI_FLAG_PF20   = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0,  0,  0), // pf20
    ADI_FLAG_PF21   = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0,  0,  0), // pf21
    ADI_FLAG_PF22   = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0,  0,  0), // pf22
    ADI_FLAG_PF23   = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0,  0,  0), // pf23
    ADI_FLAG_PF24   = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0,  0,  0), // pf24
    ADI_FLAG_PF25   = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0,  0,  0), // pf25
    ADI_FLAG_PF26   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0,  0,  0), // pf26
    ADI_FLAG_PF27   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0,  0,  0), // pf27
    ADI_FLAG_PF28   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0,  0,  0), // pf28
    ADI_FLAG_PF29   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0,  0,  0), // pf29
    ADI_FLAG_PF30   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0,  0,  0), // pf30
    ADI_FLAG_PF31   = ADI_FLAG_CREATE_FLAG_ID(15,   1,  0,  0,  0), // pf31

    ADI_FLAG_PF32   = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0,  0,  0), // pf32
    ADI_FLAG_PF33   = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0,  0,  0), // pf33
    ADI_FLAG_PF34   = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0,  0,  0), // pf34
    ADI_FLAG_PF35   = ADI_FLAG_CREATE_FLAG_ID(3,    2,  0,  0,  0), // pf35
    ADI_FLAG_PF36   = ADI_FLAG_CREATE_FLAG_ID(4,    2,  0,  0,  0), // pf36
    ADI_FLAG_PF37   = ADI_FLAG_CREATE_FLAG_ID(5,    2,  0,  0,  0), // pf37
    ADI_FLAG_PF38   = ADI_FLAG_CREATE_FLAG_ID(6,    2,  0,  0,  0), // pf38
    ADI_FLAG_PF39   = ADI_FLAG_CREATE_FLAG_ID(7,    2,  0,  0,  0), // pf39
    ADI_FLAG_PF40   = ADI_FLAG_CREATE_FLAG_ID(8,    2,  0,  0,  0), // pf40
    ADI_FLAG_PF41   = ADI_FLAG_CREATE_FLAG_ID(9,    2,  0,  0,  0), // pf41
    ADI_FLAG_PF42   = ADI_FLAG_CREATE_FLAG_ID(10,   2,  0,  0,  0), // pf42
    ADI_FLAG_PF43   = ADI_FLAG_CREATE_FLAG_ID(11,   2,  0,  0,  0), // pf43
    ADI_FLAG_PF44   = ADI_FLAG_CREATE_FLAG_ID(12,   2,  0,  0,  0), // pf44
    ADI_FLAG_PF45   = ADI_FLAG_CREATE_FLAG_ID(13,   2,  0,  0,  0), // pf45
    ADI_FLAG_PF46   = ADI_FLAG_CREATE_FLAG_ID(14,   2,  0,  0,  0), // pf46
    ADI_FLAG_PF47   = ADI_FLAG_CREATE_FLAG_ID(15,   2,  0,  0,  0), // pf47

    ADI_FLAG_UNDEFINED  = -1                                        // invalid flagID

} ADI_FLAG_ID;

#endif


/********************
    Stirling
********************/

#if defined(__ADSP_STIRLING__)  // flag IDs for BF538 and BF539

typedef enum ADI_FLAG_ID {
    // port c flags cannot generate interrupts
    ADI_FLAG_PC0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0,  0,  0), // port c flag0
    ADI_FLAG_PC1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0,  0,  0), // port c flag1
    /* PC 2,3 unused */
    ADI_FLAG_PC4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0,  0,  0), // port c flag4
    ADI_FLAG_PC5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0,  0,  0), // port c flag5
    ADI_FLAG_PC6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0,  0,  0), // port c flag6
    ADI_FLAG_PC7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0,  0,  0), // port c flag7
    ADI_FLAG_PC8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0,  0,  0), // port c flag8
    ADI_FLAG_PC9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0,  0,  0), // port c flag9
    /* PC 10-15 unused */
    // port d flags cannot generate interrupts
    ADI_FLAG_PD0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0,  0,  0), // port d flag0
    ADI_FLAG_PD1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0,  0,  0), // port d flag1
    ADI_FLAG_PD2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0,  0,  0), // port d flag2
    ADI_FLAG_PD3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0,  0,  0), // port d flag3
    ADI_FLAG_PD4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0,  0,  0), // port d flag4
    ADI_FLAG_PD5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0,  0,  0), // port d flag5
    ADI_FLAG_PD6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0,  0,  0), // port d flag6
    ADI_FLAG_PD7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0,  0,  0), // port d flag7
    ADI_FLAG_PD8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0,  0,  0), // port d flag8
    ADI_FLAG_PD9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0,  0,  0), // port d flag9
    ADI_FLAG_PD10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0,  0,  0), // port d flag10
    ADI_FLAG_PD11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0,  0,  0), // port d flag11
    ADI_FLAG_PD12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0,  0,  0), // port d flag12
    ADI_FLAG_PD13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0,  0,  0), // port d flag13
    /* PD 14,15 unused */

    // port e flags cannot generate interrupts
    ADI_FLAG_PE0    = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0,  0,  0), // port e flag0
    ADI_FLAG_PE1    = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0,  0,  0), // port e flag1
    ADI_FLAG_PE2    = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0,  0,  0), // port e flag2
    ADI_FLAG_PE3    = ADI_FLAG_CREATE_FLAG_ID(3,    2,  0,  0,  0), // port e flag3
    ADI_FLAG_PE4    = ADI_FLAG_CREATE_FLAG_ID(4,    2,  0,  0,  0), // port e flag4
    ADI_FLAG_PE5    = ADI_FLAG_CREATE_FLAG_ID(5,    2,  0,  0,  0), // port e flag5
    ADI_FLAG_PE6    = ADI_FLAG_CREATE_FLAG_ID(6,    2,  0,  0,  0), // port e flag6
    ADI_FLAG_PE7    = ADI_FLAG_CREATE_FLAG_ID(7,    2,  0,  0,  0), // port e flag7
    ADI_FLAG_PE8    = ADI_FLAG_CREATE_FLAG_ID(8,    2,  0,  0,  0), // port e flag8
    ADI_FLAG_PE9    = ADI_FLAG_CREATE_FLAG_ID(9,    2,  0,  0,  0), // port e flag9
    ADI_FLAG_PE10   = ADI_FLAG_CREATE_FLAG_ID(10,   2,  0,  0,  0), // port e flag10
    ADI_FLAG_PE11   = ADI_FLAG_CREATE_FLAG_ID(11,   2,  0,  0,  0), // port e flag11
    ADI_FLAG_PE12   = ADI_FLAG_CREATE_FLAG_ID(12,   2,  0,  0,  0), // port e flag12
    ADI_FLAG_PE13   = ADI_FLAG_CREATE_FLAG_ID(13,   2,  0,  0,  0), // port e flag13
    ADI_FLAG_PE14   = ADI_FLAG_CREATE_FLAG_ID(14,   2,  0,  0,  0), // port e flag14
    ADI_FLAG_PE15   = ADI_FLAG_CREATE_FLAG_ID(15,   2,  0,  0,  0), // port e flag15

    // port f flags can generate interrupts
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    3,  0,  0,  0), // port f flag0
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    3,  0,  0,  0), // port f flag1
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    3,  0,  0,  0), // port f flag2
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    3,  0,  0,  0), // port f flag3
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    3,  0,  0,  0), // port f flag4
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    3,  0,  0,  0), // port f flag5
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    3,  0,  0,  0), // port f flag6
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    3,  0,  0,  0), // port f flag7
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    3,  0,  0,  0), // port f flag8
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    3,  0,  0,  0), // port f flag9
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   3,  0,  0,  0), // port f flag10
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   3,  0,  0,  0), // port f flag11
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   3,  0,  0,  0), // port f flag12
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   3,  0,  0,  0), // port f flag13
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   3,  0,  0,  0), // port f flag14
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   3,  0,  0,  0), // port f flag15

    ADI_FLAG_UNDEFINED  = -1                                        // invalid flagID

} ADI_FLAG_ID;

#endif


/********************
    Moab
********************/

#if defined(__ADSP_MOAB__) // flag IDs for BF54x processors

typedef enum ADI_FLAG_ID {

    // port a flags can only generate interrupts ADI_INT_PINT0 and ADI_INT_PINT1
    ADI_FLAG_PA0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0x3,  0x5,  0), // port a flag0
    ADI_FLAG_PA1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0x3,  0x5,  0), // port a flag1
    ADI_FLAG_PA2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0x3,  0x5,  0), // port a flag2
    ADI_FLAG_PA3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0x3,  0x5,  0), // port a flag3
    ADI_FLAG_PA4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0x3,  0x5,  0), // port a flag4
    ADI_FLAG_PA5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0x3,  0x5,  0), // port a flag5
    ADI_FLAG_PA6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0x3,  0x5,  0), // port a flag6
    ADI_FLAG_PA7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0x3,  0x5,  0), // port a flag7
    ADI_FLAG_PA8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0x3,  0xa,  0), // port a flag8
    ADI_FLAG_PA9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0x3,  0xa,  0), // port a flag9
    ADI_FLAG_PA10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0x3,  0xa,  0), // port a flag10
    ADI_FLAG_PA11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0x3,  0xa,  0), // port a flag11
    ADI_FLAG_PA12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0x3,  0xa,  0), // port a flag12
    ADI_FLAG_PA13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0x3,  0xa,  0), // port a flag13
    ADI_FLAG_PA14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0x3,  0xa,  0), // port a flag14
    ADI_FLAG_PA15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0x3,  0xa,  0), // port a flag15

    // port b flags can only generate interrupts ADI_INT_PINT0 and ADI_INT_PINT1
    ADI_FLAG_PB0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0x3,  0x5,  1), // port b flag0
    ADI_FLAG_PB1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0x3,  0x5,  1), // port b flag1
    ADI_FLAG_PB2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0x3,  0x5,  1), // port b flag2
    ADI_FLAG_PB3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0x3,  0x5,  1), // port b flag3
    ADI_FLAG_PB4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0x3,  0x5,  1), // port b flag4
    ADI_FLAG_PB5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0x3,  0x5,  1), // port b flag5
    ADI_FLAG_PB6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0x3,  0x5,  1), // port b flag6
    ADI_FLAG_PB7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0x3,  0x5,  1), // port b flag7
    ADI_FLAG_PB8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0x3,  0xa,  1), // port b flag8
    ADI_FLAG_PB9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0x3,  0xa,  1), // port b flag9
    ADI_FLAG_PB10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0x3,  0xa,  1), // port b flag10
    ADI_FLAG_PB11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0x3,  0xa,  1), // port b flag11
    ADI_FLAG_PB12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0x3,  0xa,  1), // port b flag12
    ADI_FLAG_PB13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0x3,  0xa,  1), // port b flag13
    ADI_FLAG_PB14   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0x3,  0xa,  1), // port b flag14

    // port c flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PC0    = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0xc,  0x5,  0), // port c flag0
    ADI_FLAG_PC1    = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0xc,  0x5,  0), // port c flag1
    ADI_FLAG_PC2    = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0xc,  0x5,  0), // port c flag2
    ADI_FLAG_PC3    = ADI_FLAG_CREATE_FLAG_ID(3,    2,  0xc,  0x5,  0), // port c flag3
    ADI_FLAG_PC4    = ADI_FLAG_CREATE_FLAG_ID(4,    2,  0xc,  0x5,  0), // port c flag4
    ADI_FLAG_PC5    = ADI_FLAG_CREATE_FLAG_ID(5,    2,  0xc,  0x5,  0), // port c flag5
    ADI_FLAG_PC6    = ADI_FLAG_CREATE_FLAG_ID(6,    2,  0xc,  0x5,  0), // port c flag6
    ADI_FLAG_PC7    = ADI_FLAG_CREATE_FLAG_ID(7,    2,  0xc,  0x5,  0), // port c flag7
    ADI_FLAG_PC8    = ADI_FLAG_CREATE_FLAG_ID(8,    2,  0xc,  0xa,  0), // port c flag8
    ADI_FLAG_PC9    = ADI_FLAG_CREATE_FLAG_ID(9,    2,  0xc,  0xa,  0), // port c flag9
    ADI_FLAG_PC10   = ADI_FLAG_CREATE_FLAG_ID(10,   2,  0xc,  0xa,  0), // port c flag10
    ADI_FLAG_PC11   = ADI_FLAG_CREATE_FLAG_ID(11,   2,  0xc,  0xa,  0), // port c flag11
    ADI_FLAG_PC12   = ADI_FLAG_CREATE_FLAG_ID(12,   2,  0xc,  0xa,  0), // port c flag12
    ADI_FLAG_PC13   = ADI_FLAG_CREATE_FLAG_ID(13,   2,  0xc,  0xa,  0), // port c flag13

    // port d flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PD0    = ADI_FLAG_CREATE_FLAG_ID(0,    3,  0xc,  0x5,  1), // port d flag0
    ADI_FLAG_PD1    = ADI_FLAG_CREATE_FLAG_ID(1,    3,  0xc,  0x5,  1), // port d flag1
    ADI_FLAG_PD2    = ADI_FLAG_CREATE_FLAG_ID(2,    3,  0xc,  0x5,  1), // port d flag2
    ADI_FLAG_PD3    = ADI_FLAG_CREATE_FLAG_ID(3,    3,  0xc,  0x5,  1), // port d flag3
    ADI_FLAG_PD4    = ADI_FLAG_CREATE_FLAG_ID(4,    3,  0xc,  0x5,  1), // port d flag4
    ADI_FLAG_PD5    = ADI_FLAG_CREATE_FLAG_ID(5,    3,  0xc,  0x5,  1), // port d flag5
    ADI_FLAG_PD6    = ADI_FLAG_CREATE_FLAG_ID(6,    3,  0xc,  0x5,  1), // port d flag6
    ADI_FLAG_PD7    = ADI_FLAG_CREATE_FLAG_ID(7,    3,  0xc,  0x5,  1), // port d flag7
    ADI_FLAG_PD8    = ADI_FLAG_CREATE_FLAG_ID(8,    3,  0xc,  0xa,  1), // port d flag8
    ADI_FLAG_PD9    = ADI_FLAG_CREATE_FLAG_ID(9,    3,  0xc,  0xa,  1), // port d flag9
    ADI_FLAG_PD10   = ADI_FLAG_CREATE_FLAG_ID(10,   3,  0xc,  0xa,  1), // port d flag10
    ADI_FLAG_PD11   = ADI_FLAG_CREATE_FLAG_ID(11,   3,  0xc,  0xa,  1), // port d flag11
    ADI_FLAG_PD12   = ADI_FLAG_CREATE_FLAG_ID(12,   3,  0xc,  0xa,  1), // port d flag12
    ADI_FLAG_PD13   = ADI_FLAG_CREATE_FLAG_ID(13,   3,  0xc,  0xa,  1), // port d flag13
    ADI_FLAG_PD14   = ADI_FLAG_CREATE_FLAG_ID(14,   3,  0xc,  0xa,  1), // port d flag14
    ADI_FLAG_PD15   = ADI_FLAG_CREATE_FLAG_ID(15,   3,  0xc,  0xa,  1), // port d flag15

    // port e flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PE0    = ADI_FLAG_CREATE_FLAG_ID(0,    4,  0xc,  0x5,  2), // port e flag0
    ADI_FLAG_PE1    = ADI_FLAG_CREATE_FLAG_ID(1,    4,  0xc,  0x5,  2), // port e flag1
    ADI_FLAG_PE2    = ADI_FLAG_CREATE_FLAG_ID(2,    4,  0xc,  0x5,  2), // port e flag2
    ADI_FLAG_PE3    = ADI_FLAG_CREATE_FLAG_ID(3,    4,  0xc,  0x5,  2), // port e flag3
    ADI_FLAG_PE4    = ADI_FLAG_CREATE_FLAG_ID(4,    4,  0xc,  0x5,  2), // port e flag4
    ADI_FLAG_PE5    = ADI_FLAG_CREATE_FLAG_ID(5,    4,  0xc,  0x5,  2), // port e flag5
    ADI_FLAG_PE6    = ADI_FLAG_CREATE_FLAG_ID(6,    4,  0xc,  0x5,  2), // port e flag6
    ADI_FLAG_PE7    = ADI_FLAG_CREATE_FLAG_ID(7,    4,  0xc,  0x5,  2), // port e flag7
    ADI_FLAG_PE8    = ADI_FLAG_CREATE_FLAG_ID(8,    4,  0xc,  0xa,  2), // port e flag8
    ADI_FLAG_PE9    = ADI_FLAG_CREATE_FLAG_ID(9,    4,  0xc,  0xa,  2), // port e flag9
    ADI_FLAG_PE10   = ADI_FLAG_CREATE_FLAG_ID(10,   4,  0xc,  0xa,  2), // port e flag10
    ADI_FLAG_PE11   = ADI_FLAG_CREATE_FLAG_ID(11,   4,  0xc,  0xa,  2), // port e flag11
    ADI_FLAG_PE12   = ADI_FLAG_CREATE_FLAG_ID(12,   4,  0xc,  0xa,  2), // port e flag12
    ADI_FLAG_PE13   = ADI_FLAG_CREATE_FLAG_ID(13,   4,  0xc,  0xa,  2), // port e flag13
    ADI_FLAG_PE14   = ADI_FLAG_CREATE_FLAG_ID(14,   4,  0xc,  0xa,  2), // port e flag14
    ADI_FLAG_PE15   = ADI_FLAG_CREATE_FLAG_ID(15,   4,  0xc,  0xa,  2), // port e flag15

    // port f flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    5,  0xc,  0x5,  3), // port f flag0
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    5,  0xc,  0x5,  3), // port f flag1
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    5,  0xc,  0x5,  3), // port f flag2
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    5,  0xc,  0x5,  3), // port f flag3
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    5,  0xc,  0x5,  3), // port f flag4
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    5,  0xc,  0x5,  3), // port f flag5
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    5,  0xc,  0x5,  3), // port f flag6
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    5,  0xc,  0x5,  3), // port f flag7
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    5,  0xc,  0xa,  3), // port f flag8
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    5,  0xc,  0xa,  3), // port f flag9
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   5,  0xc,  0xa,  3), // port f flag10
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   5,  0xc,  0xa,  3), // port f flag11
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   5,  0xc,  0xa,  3), // port f flag12
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   5,  0xc,  0xa,  3), // port f flag13
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   5,  0xc,  0xa,  3), // port f flag14
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   5,  0xc,  0xa,  3), // port f flag15

    // port g flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PG0    = ADI_FLAG_CREATE_FLAG_ID(0,    6,  0xc,  0x5,  4), // port g flag0
    ADI_FLAG_PG1    = ADI_FLAG_CREATE_FLAG_ID(1,    6,  0xc,  0x5,  4), // port g flag1
    ADI_FLAG_PG2    = ADI_FLAG_CREATE_FLAG_ID(2,    6,  0xc,  0x5,  4), // port g flag2
    ADI_FLAG_PG3    = ADI_FLAG_CREATE_FLAG_ID(3,    6,  0xc,  0x5,  4), // port g flag3
    ADI_FLAG_PG4    = ADI_FLAG_CREATE_FLAG_ID(4,    6,  0xc,  0x5,  4), // port g flag4
    ADI_FLAG_PG5    = ADI_FLAG_CREATE_FLAG_ID(5,    6,  0xc,  0x5,  4), // port g flag5
    ADI_FLAG_PG6    = ADI_FLAG_CREATE_FLAG_ID(6,    6,  0xc,  0x5,  4), // port g flag6
    ADI_FLAG_PG7    = ADI_FLAG_CREATE_FLAG_ID(7,    6,  0xc,  0x5,  4), // port g flag7
    ADI_FLAG_PG8    = ADI_FLAG_CREATE_FLAG_ID(8,    6,  0xc,  0xa,  4), // port g flag8
    ADI_FLAG_PG9    = ADI_FLAG_CREATE_FLAG_ID(9,    6,  0xc,  0xa,  4), // port g flag9
    ADI_FLAG_PG10   = ADI_FLAG_CREATE_FLAG_ID(10,   6,  0xc,  0xa,  4), // port g flag10
    ADI_FLAG_PG11   = ADI_FLAG_CREATE_FLAG_ID(11,   6,  0xc,  0xa,  4), // port g flag11
    ADI_FLAG_PG12   = ADI_FLAG_CREATE_FLAG_ID(12,   6,  0xc,  0xa,  4), // port g flag12
    ADI_FLAG_PG13   = ADI_FLAG_CREATE_FLAG_ID(13,   6,  0xc,  0xa,  4), // port g flag13
    ADI_FLAG_PG14   = ADI_FLAG_CREATE_FLAG_ID(14,   6,  0xc,  0xa,  4), // port g flag14
    ADI_FLAG_PG15   = ADI_FLAG_CREATE_FLAG_ID(15,   6,  0xc,  0xa,  4), // port g flag15

    // port h flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PH0    = ADI_FLAG_CREATE_FLAG_ID(0,    7,  0xc,  0x5,  5), // port h flag0
    ADI_FLAG_PH1    = ADI_FLAG_CREATE_FLAG_ID(1,    7,  0xc,  0x5,  5), // port h flag1
    ADI_FLAG_PH2    = ADI_FLAG_CREATE_FLAG_ID(2,    7,  0xc,  0x5,  5), // port h flag2
    ADI_FLAG_PH3    = ADI_FLAG_CREATE_FLAG_ID(3,    7,  0xc,  0x5,  5), // port h flag3
    ADI_FLAG_PH4    = ADI_FLAG_CREATE_FLAG_ID(4,    7,  0xc,  0x5,  5), // port h flag4
    ADI_FLAG_PH5    = ADI_FLAG_CREATE_FLAG_ID(5,    7,  0xc,  0x5,  5), // port h flag5
    ADI_FLAG_PH6    = ADI_FLAG_CREATE_FLAG_ID(6,    7,  0xc,  0x5,  5), // port h flag6
    ADI_FLAG_PH7    = ADI_FLAG_CREATE_FLAG_ID(7,    7,  0xc,  0x5,  5), // port h flag7
    ADI_FLAG_PH8    = ADI_FLAG_CREATE_FLAG_ID(8,    7,  0xc,  0xa,  5), // port h flag8
    ADI_FLAG_PH9    = ADI_FLAG_CREATE_FLAG_ID(9,    7,  0xc,  0xa,  5), // port h flag9
    ADI_FLAG_PH10   = ADI_FLAG_CREATE_FLAG_ID(10,   7,  0xc,  0xa,  5), // port h flag10
    ADI_FLAG_PH11   = ADI_FLAG_CREATE_FLAG_ID(11,   7,  0xc,  0xa,  5), // port h flag11
    ADI_FLAG_PH12   = ADI_FLAG_CREATE_FLAG_ID(12,   7,  0xc,  0xa,  5), // port h flag12
    ADI_FLAG_PH13   = ADI_FLAG_CREATE_FLAG_ID(13,   7,  0xc,  0xa,  5), // port h flag13

    // port i flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PI0    = ADI_FLAG_CREATE_FLAG_ID(0,    8,  0xc,  0x5,  6), // port i flag0
    ADI_FLAG_PI1    = ADI_FLAG_CREATE_FLAG_ID(1,    8,  0xc,  0x5,  6), // port i flag1
    ADI_FLAG_PI2    = ADI_FLAG_CREATE_FLAG_ID(2,    8,  0xc,  0x5,  6), // port i flag2
    ADI_FLAG_PI3    = ADI_FLAG_CREATE_FLAG_ID(3,    8,  0xc,  0x5,  6), // port i flag3
    ADI_FLAG_PI4    = ADI_FLAG_CREATE_FLAG_ID(4,    8,  0xc,  0x5,  6), // port i flag4
    ADI_FLAG_PI5    = ADI_FLAG_CREATE_FLAG_ID(5,    8,  0xc,  0x5,  6), // port i flag5
    ADI_FLAG_PI6    = ADI_FLAG_CREATE_FLAG_ID(6,    8,  0xc,  0x5,  6), // port i flag6
    ADI_FLAG_PI7    = ADI_FLAG_CREATE_FLAG_ID(7,    8,  0xc,  0x5,  6), // port i flag7
    ADI_FLAG_PI8    = ADI_FLAG_CREATE_FLAG_ID(8,    8,  0xc,  0xa,  6), // port i flag8
    ADI_FLAG_PI9    = ADI_FLAG_CREATE_FLAG_ID(9,    8,  0xc,  0xa,  6), // port i flag9
    ADI_FLAG_PI10   = ADI_FLAG_CREATE_FLAG_ID(10,   8,  0xc,  0xa,  6), // port i flag10
    ADI_FLAG_PI11   = ADI_FLAG_CREATE_FLAG_ID(11,   8,  0xc,  0xa,  6), // port i flag11
    ADI_FLAG_PI12   = ADI_FLAG_CREATE_FLAG_ID(12,   8,  0xc,  0xa,  6), // port i flag12
    ADI_FLAG_PI13   = ADI_FLAG_CREATE_FLAG_ID(13,   8,  0xc,  0xa,  6), // port i flag13
    ADI_FLAG_PI14   = ADI_FLAG_CREATE_FLAG_ID(14,   8,  0xc,  0xa,  6), // port i flag14
    ADI_FLAG_PI15   = ADI_FLAG_CREATE_FLAG_ID(15,   8,  0xc,  0xa,  6), // port i flag15

    // port j flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PJ0    = ADI_FLAG_CREATE_FLAG_ID(0,    9,  0xc,  0x5,  7), // port j flag0
    ADI_FLAG_PJ1    = ADI_FLAG_CREATE_FLAG_ID(1,    9,  0xc,  0x5,  7), // port j flag1
    ADI_FLAG_PJ2    = ADI_FLAG_CREATE_FLAG_ID(2,    9,  0xc,  0x5,  7), // port j flag2
    ADI_FLAG_PJ3    = ADI_FLAG_CREATE_FLAG_ID(3,    9,  0xc,  0x5,  7), // port j flag3
    ADI_FLAG_PJ4    = ADI_FLAG_CREATE_FLAG_ID(4,    9,  0xc,  0x5,  7), // port j flag4
    ADI_FLAG_PJ5    = ADI_FLAG_CREATE_FLAG_ID(5,    9,  0xc,  0x5,  7), // port j flag5
    ADI_FLAG_PJ6    = ADI_FLAG_CREATE_FLAG_ID(6,    9,  0xc,  0x5,  7), // port j flag6
    ADI_FLAG_PJ7    = ADI_FLAG_CREATE_FLAG_ID(7,    9,  0xc,  0x5,  7), // port j flag7
    ADI_FLAG_PJ8    = ADI_FLAG_CREATE_FLAG_ID(8,    9,  0xc,  0xa,  7), // port j flag8
    ADI_FLAG_PJ9    = ADI_FLAG_CREATE_FLAG_ID(9,    9,  0xc,  0xa,  7), // port j flag9
    ADI_FLAG_PJ10   = ADI_FLAG_CREATE_FLAG_ID(10,   9,  0xc,  0xa,  7), // port j flag10
    ADI_FLAG_PJ11   = ADI_FLAG_CREATE_FLAG_ID(11,   9,  0xc,  0xa,  7), // port j flag11
    ADI_FLAG_PJ12   = ADI_FLAG_CREATE_FLAG_ID(12,   9,  0xc,  0xa,  7), // port j flag12
    ADI_FLAG_PJ13   = ADI_FLAG_CREATE_FLAG_ID(13,   9,  0xc,  0xa,  7), // port j flag13

    ADI_FLAG_UNDEFINED  = -1                                            // invalid flagID

} ADI_FLAG_ID;

#endif



/********************
    Kookaburra/Mockingbird
********************/

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)   // flag IDs for BF52x processors

typedef enum ADI_FLAG_ID {

    // port f flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0xc,  0x5,  3), // port f flag0
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0xc,  0x5,  3), // port f flag1
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0xc,  0x5,  3), // port f flag2
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0xc,  0x5,  3), // port f flag3
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0xc,  0x5,  3), // port f flag4
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0xc,  0x5,  3), // port f flag5
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0xc,  0x5,  3), // port f flag6
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0xc,  0x5,  3), // port f flag7
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0xc,  0xa,  3), // port f flag8
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0xc,  0xa,  3), // port f flag9
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0xc,  0xa,  3), // port f flag10
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0xc,  0xa,  3), // port f flag11
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0xc,  0xa,  3), // port f flag12
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0xc,  0xa,  3), // port f flag13
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0xc,  0xa,  3), // port f flag14
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0xc,  0xa,  3), // port f flag15

    // port g flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PG0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0xc,  0x5,  4), // port g flag0
    ADI_FLAG_PG1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0xc,  0x5,  4), // port g flag1
    ADI_FLAG_PG2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0xc,  0x5,  4), // port g flag2
    ADI_FLAG_PG3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0xc,  0x5,  4), // port g flag3
    ADI_FLAG_PG4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0xc,  0x5,  4), // port g flag4
    ADI_FLAG_PG5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0xc,  0x5,  4), // port g flag5
    ADI_FLAG_PG6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0xc,  0x5,  4), // port g flag6
    ADI_FLAG_PG7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0xc,  0x5,  4), // port g flag7
    ADI_FLAG_PG8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0xc,  0xa,  4), // port g flag8
    ADI_FLAG_PG9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0xc,  0xa,  4), // port g flag9
    ADI_FLAG_PG10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0xc,  0xa,  4), // port g flag10
    ADI_FLAG_PG11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0xc,  0xa,  4), // port g flag11
    ADI_FLAG_PG12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0xc,  0xa,  4), // port g flag12
    ADI_FLAG_PG13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0xc,  0xa,  4), // port g flag13
    ADI_FLAG_PG14   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0xc,  0xa,  4), // port g flag14
    ADI_FLAG_PG15   = ADI_FLAG_CREATE_FLAG_ID(15,   1,  0xc,  0xa,  4), // port g flag15

    // port h flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PH0    = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0xc,  0x5,  5), // port h flag0
    ADI_FLAG_PH1    = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0xc,  0x5,  5), // port h flag1
    ADI_FLAG_PH2    = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0xc,  0x5,  5), // port h flag2
    ADI_FLAG_PH3    = ADI_FLAG_CREATE_FLAG_ID(3,    2,  0xc,  0x5,  5), // port h flag3
    ADI_FLAG_PH4    = ADI_FLAG_CREATE_FLAG_ID(4,    2,  0xc,  0x5,  5), // port h flag4
    ADI_FLAG_PH5    = ADI_FLAG_CREATE_FLAG_ID(5,    2,  0xc,  0x5,  5), // port h flag5
    ADI_FLAG_PH6    = ADI_FLAG_CREATE_FLAG_ID(6,    2,  0xc,  0x5,  5), // port h flag6
    ADI_FLAG_PH7    = ADI_FLAG_CREATE_FLAG_ID(7,    2,  0xc,  0x5,  5), // port h flag7
    ADI_FLAG_PH8    = ADI_FLAG_CREATE_FLAG_ID(8,    2,  0xc,  0xa,  5), // port h flag8
    ADI_FLAG_PH9    = ADI_FLAG_CREATE_FLAG_ID(9,    2,  0xc,  0xa,  5), // port h flag9
    ADI_FLAG_PH10   = ADI_FLAG_CREATE_FLAG_ID(10,   2,  0xc,  0xa,  5), // port h flag10
    ADI_FLAG_PH11   = ADI_FLAG_CREATE_FLAG_ID(11,   2,  0xc,  0xa,  5), // port h flag11
    ADI_FLAG_PH12   = ADI_FLAG_CREATE_FLAG_ID(12,   2,  0xc,  0xa,  5), // port h flag12
    ADI_FLAG_PH13   = ADI_FLAG_CREATE_FLAG_ID(13,   2,  0xc,  0xa,  5), // port h flag13
    ADI_FLAG_PH14   = ADI_FLAG_CREATE_FLAG_ID(14,   2,  0xc,  0xa,  5), // port h flag14
    ADI_FLAG_PH15   = ADI_FLAG_CREATE_FLAG_ID(15,   2,  0xc,  0xa,  5), // port h flag15

    // port j does not have gpio

    ADI_FLAG_UNDEFINED  = -1                                            // invalid flagID

} ADI_FLAG_ID;

#endif


/********************
    Brodie
********************/

#if defined(__ADSP_BRODIE__)  // flag IDs for BF51x processors

/* Note that Brodie is like Kookaburra and Mockingbird, except PortH is only 8-bits */

typedef enum ADI_FLAG_ID {

    // port f flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0xc,  0x5,  3), // port f flag0
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0xc,  0x5,  3), // port f flag1
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0xc,  0x5,  3), // port f flag2
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0xc,  0x5,  3), // port f flag3
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0xc,  0x5,  3), // port f flag4
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0xc,  0x5,  3), // port f flag5
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0xc,  0x5,  3), // port f flag6
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0xc,  0x5,  3), // port f flag7
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0xc,  0xa,  3), // port f flag8
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0xc,  0xa,  3), // port f flag9
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0xc,  0xa,  3), // port f flag10
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0xc,  0xa,  3), // port f flag11
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0xc,  0xa,  3), // port f flag12
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0xc,  0xa,  3), // port f flag13
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0xc,  0xa,  3), // port f flag14
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0xc,  0xa,  3), // port f flag15

    // port g flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PG0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0xc,  0x5,  4), // port g flag0
    ADI_FLAG_PG1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0xc,  0x5,  4), // port g flag1
    ADI_FLAG_PG2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0xc,  0x5,  4), // port g flag2
    ADI_FLAG_PG3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0xc,  0x5,  4), // port g flag3
    ADI_FLAG_PG4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0xc,  0x5,  4), // port g flag4
    ADI_FLAG_PG5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0xc,  0x5,  4), // port g flag5
    ADI_FLAG_PG6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0xc,  0x5,  4), // port g flag6
    ADI_FLAG_PG7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0xc,  0x5,  4), // port g flag7
    ADI_FLAG_PG8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0xc,  0xa,  4), // port g flag8
    ADI_FLAG_PG9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0xc,  0xa,  4), // port g flag9
    ADI_FLAG_PG10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0xc,  0xa,  4), // port g flag10
    ADI_FLAG_PG11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0xc,  0xa,  4), // port g flag11
    ADI_FLAG_PG12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0xc,  0xa,  4), // port g flag12
    ADI_FLAG_PG13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0xc,  0xa,  4), // port g flag13
    ADI_FLAG_PG14   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0xc,  0xa,  4), // port g flag14
    ADI_FLAG_PG15   = ADI_FLAG_CREATE_FLAG_ID(15,   1,  0xc,  0xa,  4), // port g flag15

    // port h flags can only generate interrupts ADI_INT_PINT2 and ADI_INT_PINT3
    ADI_FLAG_PH0    = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0xc,  0x5,  5), // port h flag0
    ADI_FLAG_PH1    = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0xc,  0x5,  5), // port h flag1
    ADI_FLAG_PH2    = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0xc,  0x5,  5), // port h flag2
    ADI_FLAG_PH3    = ADI_FLAG_CREATE_FLAG_ID(3,    2,  0xc,  0x5,  5), // port h flag3
    ADI_FLAG_PH4    = ADI_FLAG_CREATE_FLAG_ID(4,    2,  0xc,  0x5,  5), // port h flag4
    ADI_FLAG_PH5    = ADI_FLAG_CREATE_FLAG_ID(5,    2,  0xc,  0x5,  5), // port h flag5
    ADI_FLAG_PH6    = ADI_FLAG_CREATE_FLAG_ID(6,    2,  0xc,  0x5,  5), // port h flag6
    ADI_FLAG_PH7    = ADI_FLAG_CREATE_FLAG_ID(7,    2,  0xc,  0x5,  5), // port h flag7

    // no bits 8:15 for PortH on Brodie

    ADI_FLAG_UNDEFINED  = -1                                            // invalid flagID

} ADI_FLAG_ID;

#endif

/********************
    Moy (ADSP-BF50x)
********************/

#if defined(__ADSP_MOY__)  /* Flag IDs for BF50x processors */

/* Moy has three ports - Port F, G and H.
** Port F & G each offer 16-GPIOs, Port H offers 3 GPIOs
*/

typedef enum ADI_FLAG_ID
{
    /* Port F flags can only generate interrupts ADI_INT_PORTF_INTA and ADI_INT_PORTF_INTB */
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0,  0,  0), /* PF0  */
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0,  0,  0), /* PF1  */
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0,  0,  0), /* PF2  */
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0,  0,  0), /* PF3  */
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0,  0,  0), /* PF4  */
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0,  0,  0), /* PF5  */
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0,  0,  0), /* PF6  */
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0,  0,  0), /* PF7  */
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0,  0,  0), /* PF8  */
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0,  0,  0), /* PF9  */
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0,  0,  0), /* PF10 */
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0,  0,  0), /* PF11 */
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0,  0,  0), /* PF12 */
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0,  0,  0), /* PF13 */
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0,  0,  0), /* PF14 */
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0,  0,  0), /* PF15 */

    /* Port G flags can only generate interrupts ADI_INT_PORTG_INTA and ADI_INT_PORTG_INTB */
    ADI_FLAG_PG0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0,  0,  0), /* PG0  */
    ADI_FLAG_PG1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0,  0,  0), /* PG1  */
    ADI_FLAG_PG2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0,  0,  0), /* PG2  */
    ADI_FLAG_PG3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0,  0,  0), /* PG3  */
    ADI_FLAG_PG4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0,  0,  0), /* PG4  */
    ADI_FLAG_PG5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0,  0,  0), /* PG5  */
    ADI_FLAG_PG6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0,  0,  0), /* PG6  */
    ADI_FLAG_PG7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0,  0,  0), /* PG7  */
    ADI_FLAG_PG8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0,  0,  0), /* PG8  */
    ADI_FLAG_PG9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0,  0,  0), /* PG9  */
    ADI_FLAG_PG10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0,  0,  0), /* PG10 */
    ADI_FLAG_PG11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0,  0,  0), /* PG11 */
    ADI_FLAG_PG12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0,  0,  0), /* PG12 */
    ADI_FLAG_PG13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0,  0,  0), /* PG13 */
    ADI_FLAG_PG14   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0,  0,  0), /* PG14 */
    ADI_FLAG_PG15   = ADI_FLAG_CREATE_FLAG_ID(15,   1,  0,  0,  0), /* PG15 */

    /* Port H flags can only generate interrupts ADI_INT_PORTH_INTA and ADI_INT_PORTH_INTB */
    ADI_FLAG_PH0    = ADI_FLAG_CREATE_FLAG_ID(0,    2,  0,  0,  0), /* PH0  */
    ADI_FLAG_PH1    = ADI_FLAG_CREATE_FLAG_ID(1,    2,  0,  0,  0), /* PH1  */
    ADI_FLAG_PH2    = ADI_FLAG_CREATE_FLAG_ID(2,    2,  0,  0,  0), /* PH2  */

    ADI_FLAG_UNDEFINED  = -1                                        /* invalid flagID */

} ADI_FLAG_ID;

#endif

/********************
    Delta (ADSP-BF59x)
********************/

#if defined(__ADSP_DELTA__)  /* Flag IDs for BF59x processors */

/* Delta has two ports - Port F and G.
** Port F & G each offer 16-GPIOs
*/

typedef enum ADI_FLAG_ID
{
    /* Port F flags can only generate interrupts ADI_INT_PORTF_INTA and ADI_INT_PORTF_INTB */
    ADI_FLAG_PF0    = ADI_FLAG_CREATE_FLAG_ID(0,    0,  0,  0,  0), /* PF0  */
    ADI_FLAG_PF1    = ADI_FLAG_CREATE_FLAG_ID(1,    0,  0,  0,  0), /* PF1  */
    ADI_FLAG_PF2    = ADI_FLAG_CREATE_FLAG_ID(2,    0,  0,  0,  0), /* PF2  */
    ADI_FLAG_PF3    = ADI_FLAG_CREATE_FLAG_ID(3,    0,  0,  0,  0), /* PF3  */
    ADI_FLAG_PF4    = ADI_FLAG_CREATE_FLAG_ID(4,    0,  0,  0,  0), /* PF4  */
    ADI_FLAG_PF5    = ADI_FLAG_CREATE_FLAG_ID(5,    0,  0,  0,  0), /* PF5  */
    ADI_FLAG_PF6    = ADI_FLAG_CREATE_FLAG_ID(6,    0,  0,  0,  0), /* PF6  */
    ADI_FLAG_PF7    = ADI_FLAG_CREATE_FLAG_ID(7,    0,  0,  0,  0), /* PF7  */
    ADI_FLAG_PF8    = ADI_FLAG_CREATE_FLAG_ID(8,    0,  0,  0,  0), /* PF8  */
    ADI_FLAG_PF9    = ADI_FLAG_CREATE_FLAG_ID(9,    0,  0,  0,  0), /* PF9  */
    ADI_FLAG_PF10   = ADI_FLAG_CREATE_FLAG_ID(10,   0,  0,  0,  0), /* PF10 */
    ADI_FLAG_PF11   = ADI_FLAG_CREATE_FLAG_ID(11,   0,  0,  0,  0), /* PF11 */
    ADI_FLAG_PF12   = ADI_FLAG_CREATE_FLAG_ID(12,   0,  0,  0,  0), /* PF12 */
    ADI_FLAG_PF13   = ADI_FLAG_CREATE_FLAG_ID(13,   0,  0,  0,  0), /* PF13 */
    ADI_FLAG_PF14   = ADI_FLAG_CREATE_FLAG_ID(14,   0,  0,  0,  0), /* PF14 */
    ADI_FLAG_PF15   = ADI_FLAG_CREATE_FLAG_ID(15,   0,  0,  0,  0), /* PF15 */

    /* Port G flags can only generate interrupts ADI_INT_PORTG_INTA and ADI_INT_PORTG_INTB */
    ADI_FLAG_PG0    = ADI_FLAG_CREATE_FLAG_ID(0,    1,  0,  0,  0), /* PG0  */
    ADI_FLAG_PG1    = ADI_FLAG_CREATE_FLAG_ID(1,    1,  0,  0,  0), /* PG1  */
    ADI_FLAG_PG2    = ADI_FLAG_CREATE_FLAG_ID(2,    1,  0,  0,  0), /* PG2  */
    ADI_FLAG_PG3    = ADI_FLAG_CREATE_FLAG_ID(3,    1,  0,  0,  0), /* PG3  */
    ADI_FLAG_PG4    = ADI_FLAG_CREATE_FLAG_ID(4,    1,  0,  0,  0), /* PG4  */
    ADI_FLAG_PG5    = ADI_FLAG_CREATE_FLAG_ID(5,    1,  0,  0,  0), /* PG5  */
    ADI_FLAG_PG6    = ADI_FLAG_CREATE_FLAG_ID(6,    1,  0,  0,  0), /* PG6  */
    ADI_FLAG_PG7    = ADI_FLAG_CREATE_FLAG_ID(7,    1,  0,  0,  0), /* PG7  */
    ADI_FLAG_PG8    = ADI_FLAG_CREATE_FLAG_ID(8,    1,  0,  0,  0), /* PG8  */
    ADI_FLAG_PG9    = ADI_FLAG_CREATE_FLAG_ID(9,    1,  0,  0,  0), /* PG9  */
    ADI_FLAG_PG10   = ADI_FLAG_CREATE_FLAG_ID(10,   1,  0,  0,  0), /* PG10 */
    ADI_FLAG_PG11   = ADI_FLAG_CREATE_FLAG_ID(11,   1,  0,  0,  0), /* PG11 */
    ADI_FLAG_PG12   = ADI_FLAG_CREATE_FLAG_ID(12,   1,  0,  0,  0), /* PG12 */
    ADI_FLAG_PG13   = ADI_FLAG_CREATE_FLAG_ID(13,   1,  0,  0,  0), /* PG13 */
    ADI_FLAG_PG14   = ADI_FLAG_CREATE_FLAG_ID(14,   1,  0,  0,  0), /* PG14 */
    ADI_FLAG_PG15   = ADI_FLAG_CREATE_FLAG_ID(15,   1,  0,  0,  0), /* PG15 */

    ADI_FLAG_UNDEFINED  = -1                                        /* invalid flagID */

} ADI_FLAG_ID;

#endif


/* ****************************************************************************
 * RESULT CODES
 * ****************************************************************************
 */
typedef enum {
    ADI_FLAG_RESULT_SUCCESS=0,                      // Generic success
    ADI_FLAG_RESULT_FAILED=1,                       // Generic failure

    ADI_FLAG_RESULT_START=ADI_FLAG_ENUMERATION_START,

    ADI_FLAG_RESULT_INVALID_FLAG_ID,                // (0x80001) Invalid flag ID
    ADI_FLAG_RESULT_INTERRUPT_MANAGER_ERROR,        // (0x80002) Error returned from interrupt manager
    ADI_FLAG_RESULT_ERROR_REMOVING_CALLBACK,        // (0x80003) Can't find callback for given FlagID
    ADI_FLAG_RESULT_ALL_IN_USE,                     // (0x80004) All flag slots are in use
    ADI_FLAG_RESULT_PORT_CONTROL_ERROR,             // (0x80005) Error within port control
    ADI_FLAG_RESULT_NOT_CAPABLE,                    // (0x80006) Given flag not capable of function requested
    ADI_FLAG_RESULT_TRIGGER_TYPE_NOT_SUPPORTED,     // (0x80007) the trigger type is not supported
    ADI_FLAG_RESULT_CANT_MAP_FLAG_TO_INTERRUPT,     // (0x80008) can't map the flag to the given interrupt peripheral ID
    ADI_FLAG_RESULT_NOT_MAPPED_TO_INTERRUPT,        // (0x80009) the flag is not mapped to an interrupt
    ADI_FLAG_RESULT_CALLBACK_NOT_INSTALLED,         // (0x8000a) no callback is installed for the given flag
    ADI_FLAG_RESULT_BAD_CALLBACK_MEMORY_SIZE        // (0x8000b) the ADI_FLAG_CALLBACK_MEMORY macro is invalid (internal error)
} ADI_FLAG_RESULT;



/* ****************************************************************************
 * Enum for callback triggers
 * value encodes FIO_POLAR (b2), FIO_EDGE (b1), FIO_BOTH (b0)
 * ****************************************************************************
 */
typedef enum {
    ADI_FLAG_TRIGGER_LEVEL_HIGH=0,              // flag reads one when level high on pin
    ADI_FLAG_TRIGGER_LEVEL_LOW=4,               // flag reads one when level low on pin
    ADI_FLAG_TRIGGER_RISING_EDGE=2,             // flag reads one on rising edge (sticky)
    ADI_FLAG_TRIGGER_FALLING_EDGE=6,            // flag reads one on falling edge (sticky)
    ADI_FLAG_TRIGGER_BOTH_EDGES=3               // flag reads one on both rising and falling edges (sticky)
} ADI_FLAG_TRIGGER;

/* ****************************************************************************
 * Enum for flag direction
 * ****************************************************************************
 */
typedef enum {
    ADI_FLAG_DIRECTION_INPUT    = 0,    // flag is an input
    ADI_FLAG_DIRECTION_OUTPUT   = 1     // flag is an output
} ADI_FLAG_DIRECTION;




/* ****************************************************************************
 * Enum for flag events
 * ****************************************************************************
 */
enum {
    ADI_FLAG_EVENT_START=ADI_FLAG_ENUMERATION_START,    // starting point

    ADI_FLAG_EVENT_CALLBACK                             // (0x80001) flag interrupt occurred
};


/////////////////
// API functions
/////////////////

#ifdef __cplusplus
extern "C" {
#endif

ADI_FLAG_RESULT adi_flag_Init(              // initializes the flag manager
    void            *pMemory,                   // pointer to memory
    const size_t    MemorySize,                 // size of memory (in bytes)
    u32             *pMaxEntries,               // number of callback entries supported
    void            *pEnterCriticalArg          // parameter for critical region function
);

ADI_FLAG_RESULT adi_flag_Terminate(         // terminates the flag manager
    void
);

ADI_FLAG_RESULT adi_flag_Open(              // opens a flag for use
    ADI_FLAG_ID         FlagID                  // flag ID
);

ADI_FLAG_RESULT adi_flag_Close(             // closes a flag from further use
    ADI_FLAG_ID         FlagID                  // flag ID
);

ADI_FLAG_RESULT adi_flag_SetDirection(      // sets the direction of a flag
    ADI_FLAG_ID         FlagID,                 // flag ID
    ADI_FLAG_DIRECTION  Direction               // direction
);

ADI_FLAG_RESULT adi_flag_Set(               // sets the flag value to 1
    ADI_FLAG_ID         FlagID                  // flag ID
);

ADI_FLAG_RESULT adi_flag_Clear(             // sets the flag value to 0
    ADI_FLAG_ID         FlagID                  // flag ID
);

ADI_FLAG_RESULT adi_flag_Toggle(            // toggles the flag value
    ADI_FLAG_ID         FlagID                  // flag ID
);

ADI_FLAG_RESULT adi_flag_Sense(             // senses the flag value
    ADI_FLAG_ID         FlagID,                 // flag ID
    u32                 *pValue                 // location to store value
);

ADI_FLAG_RESULT adi_flag_InstallCallback(   // installs a callback for a flag
    ADI_FLAG_ID             FlagID,             // flag ID
    ADI_INT_PERIPHERAL_ID   PeripheralID,       // peripheral ID
    ADI_FLAG_TRIGGER        Trigger,            // trigger
    u32                     WakeupFlag,         // wakeup flag (TRUE/FALSE)
    void                    *ClientHandle,      // client handle argument passed in callbacks
    ADI_DCB_HANDLE          DCBHandle,          // deferred callback service handle
    ADI_DCB_CALLBACK_FN     ClientCallback      // client callback function
);

ADI_FLAG_RESULT adi_flag_RemoveCallback(    // removes a callback for a flag
    ADI_FLAG_ID         FlagID                  // flag ID
);

ADI_FLAG_RESULT adi_flag_SuspendCallbacks(  // suspends callbacks without removing the callback function
    ADI_FLAG_ID             FlagID,             // flag ID
    ADI_INT_PERIPHERAL_ID   PeripheralID        // peripheral ID
);

ADI_FLAG_RESULT adi_flag_ResumeCallbacks(   // resumes callbacks
    ADI_FLAG_ID             FlagID,             // flag ID
    ADI_INT_PERIPHERAL_ID   PeripheralID        // peripheral ID
);

ADI_FLAG_RESULT adi_flag_SetTrigger(        // changes the type of trigger that generates a flag callback
    ADI_FLAG_ID         FlagID,                 // flag ID
    ADI_FLAG_TRIGGER    NewTrigger              // new trigger type
);


#ifdef __cplusplus
}
#endif

#endif // Not ASM

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_FLAG_H__ */
