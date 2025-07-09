/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_int.h,v $
$Revision: 3578 $
$Date: 2010-10-19 09:36:04 -0400 (Tue, 19 Oct 2010) $

Description:
            This is the include file for the interrupt manager.

*********************************************************************************/



#ifndef __ADI_INT_H__
#define __ADI_INT_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

/*********************************************************************

Typedef for IMASK value

*********************************************************************/


typedef u32 ADI_INT_IMASK;      /* typedef for IMASK value */


/*********************************************************************

IVG levels

*********************************************************************/

enum {
    ADI_INT_IVG_EMU,            /* emulation */
    ADI_INT_IVG_RESET,          /* reset */
    ADI_INT_IVG_NMI,            /* nmi */
    ADI_INT_IVG_EXCEPTION,      /* exceptions */
    ADI_INT_IVG_RESERVED,       /* reserved */
    ADI_INT_IVG_HARDWARE_ERROR, /* hardware error */
    ADI_INT_IVG_CORE_TIMER,     /* core timer */
    ADI_INT_IVG_7,              /* general purpose */
    ADI_INT_IVG_8,              /* general purpose */
    ADI_INT_IVG_9,              /* general purpose */
    ADI_INT_IVG_10,             /* general purpose */
    ADI_INT_IVG_11,             /* general purpose */
    ADI_INT_IVG_12,             /* general purpose */
    ADI_INT_IVG_13,             /* general purpose */
    ADI_INT_IVG_14,             /* general purpose */
    ADI_INT_IVG_15              /* general purpose */

};




/*********************************************************************

Default critical region data

This is the data structure used by the default routines for critical region
protection (adi_int_EnterCriticalRegion and adi_int_ExitCriticalRegion).

*********************************************************************/


typedef struct {                /* Critical region data structure */

    u8      Placeholder;            /* not used in current versions of */
} ADI_INT_CRITICAL_REGION_DATA;     /* adi_int_Enter/ExitCriticalRegion */



/*********************************************************************

Return codes

*********************************************************************/

typedef enum {                          /* API function return codes */
    ADI_INT_RESULT_SUCCESS=0,                       /* generic success */
    ADI_INT_RESULT_FAILED=1,                        /* generic failure */

    ADI_INT_RESULT_START=ADI_INT_ENUMERATION_START, /* 0x50000 - starting point */

    ADI_INT_RESULT_INVALID_IVG,                     /* 0x50001 - invalid interrupt vector group */
    ADI_INT_RESULT_INVALID_PERIPHERAL_ID,           /* 0x50002 - invalid peripheral */
    ADI_INT_RESULT_NOT_INITIALIZED,                 /* 0x50003 - interrupt manager has not been initialized */
    ADI_INT_RESULT_NO_MEMORY,                       /* 0x50004 - insufficient memory to complete the operation */
    ADI_INT_RESULT_ASSERTED,                        /* 0x50005 - interrupt is asserted */
    ADI_INT_RESULT_NOT_ASSERTED,                    /* 0x50006 - interrupt is not asserted */
    ADI_INT_RESULT_HANDLER_NOT_FOUND,               /* 0x50007 - the given handler was not found in the chain */
    ADI_INT_RESULT_BAD_SECONDARY_MEMORY_SIZE,       /* 0x50008 - the ADI_INT_SECONDARY_MEMORY macro is invalid (internal error) */
    ADI_INT_RESULT_DISALLOWED_BY_RTOS               /* 0x50009 - the RTOS being targeted disallowed the request */
} ADI_INT_RESULT;

typedef enum {                      /* interrupt handler return codes */
    ADI_INT_RESULT_PROCESSED,           /* interrupt was processed */
    ADI_INT_RESULT_NOT_PROCESSED        /* interrupt was not processed */
} ADI_INT_HANDLER_RESULT;


/*********************************************************************

Macros for a client's interrupt handler

*********************************************************************/

/* this macro should be used for handler function definitions
   the function is a simple 'C' function taking a single argument */
#define ADI_INT_HANDLER(NAME) ADI_INT_HANDLER_RESULT NAME (void *ClientArg)

/* this macro is used in argument lists */
typedef ADI_INT_HANDLER_RESULT (*ADI_INT_HANDLER_FN) (void *ClientArg);


/*********************************************************************

Macros for the memory usage of the Interrupt Manager

*********************************************************************/

#define ADI_INT_SECONDARY_MEMORY    (16)    /* additional memory needed for each secondary handler (bytes) */





/*********************************************************************

Macros for Peripheral IDs

*********************************************************************/

/*
Peripheral ID enumerations are concatenations of several pieces of information
for the peripheral. A peripheral ID enumerator consists of:

    o bit 0-4:   (5 bits, range 0-31)  bit within the IMASK/ISR/IWR register
    o bit 5-9:   (5 bits, range 0-31)  SIC_ISRx address offset from SIC_ISR0
    o bit 10-14: (5 bits, range 0-31)  SIC_IMASKx address offset from SIC_IMASK0
    o bit 15-19: (5 bits, range 0-31)  SIC_IWRx address offset from SIC_IWR0
    o bit 20-24: (5 bits, range 0-31)  SIC_IARx address offset from SIC_IAR0
    o bit 25-27: (3 bits, range 0-7)   nibble within SIC_IARx register for IVG assignment
    o bit 28-31: (4 bits, range 0-15)  Not used presently

Note that these registers contain 32 bit data so an address offset of 1 translates
to a byte address difference of 4.  For example, given a base address of 0xffc00110,
an offset of 1 is used to access 0xffc00114.

Macros are provided to create the actual peripheral ID enumerator and to
extract each of the fields within the value.
*/

/* macro to create the peripheral ID */
#define ADI_INT_PERIPHERAL_ID_VALUE(BIT,ISR_OFFSET,IMASK_OFFSET,IWR_OFFSET,IAR_OFFSET,NIBBLE) \
    ( ((BIT          & 0x0000001f) << 0)  | \
      ((ISR_OFFSET   & 0x0000001f) << 5)  | \
      ((IMASK_OFFSET & 0x0000001f) << 10) | \
      ((IWR_OFFSET   & 0x0000001f) << 15) | \
      ((IAR_OFFSET   & 0x0000001f) << 20) | \
      ((NIBBLE       & 0x00000007) << 25)   \
    )

/* macros to get the individual field values */
#define ADI_INT_GET_SIC_IMASK_ISR_IWR_BIT(PERIPHERAL_ID)    (((PERIPHERAL_ID)     )  & 0x0000001f)
#define ADI_INT_GET_SIC_ISR_OFFSET(PERIPHERAL_ID)           (((PERIPHERAL_ID) >> 5)  & 0x0000001f)
#define ADI_INT_GET_SIC_IMASK_OFFSET(PERIPHERAL_ID)         (((PERIPHERAL_ID) >> 10) & 0x0000001f)
#define ADI_INT_GET_SIC_IWR_OFFSET(PERIPHERAL_ID)           (((PERIPHERAL_ID) >> 15) & 0x0000001f)
#define ADI_INT_GET_SIC_IAR_OFFSET(PERIPHERAL_ID)           (((PERIPHERAL_ID) >> 20) & 0x0000001f)
#define ADI_INT_GET_SIC_IAR_NIBBLE(PERIPHERAL_ID)           (((PERIPHERAL_ID) >> 25) & 0x00000007)
#define ADI_INT_GET_UNUSED_BITS(PERIPHERAL_ID)              (((PERIPHERAL_ID) >> 28) & 0x0000000f)

/* macro to create a mask that can be used to check against the SIC's IMASK, ISR and IWR registers */
#define ADI_INT_GET_SIC_IMASK_ISR_IWR_MASK(PERIPHERAL_ID)   (1 << ADI_INT_GET_SIC_IMASK_ISR_IWR_BIT(PERIPHERAL_ID))


/*********************************************************************

Enumerations for Peripheral IDs

*********************************************************************/

/********************
    Edinburgh
********************/

#if defined(__ADSP_EDINBURGH__)         /* peripheral IDs for BF531, BF532, BF533 */
typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP      = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA_ERROR       = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_PPI_ERROR       = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_SPORT0_ERROR    = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_SPI_ERROR       = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_SPORT1_ERROR    = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_UART_ERROR      = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_RTC             = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_DMA0_PPI        = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_DMA1_SPORT0_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_DMA2_SPORT0_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  10, 0,  0,  0,  1,  2   ),
    ADI_INT_DMA3_SPORT1_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  11, 0,  0,  0,  1,  3   ),
    ADI_INT_DMA4_SPORT1_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  12, 0,  0,  0,  1,  4   ),
    ADI_INT_DMA5_SPI        = ADI_INT_PERIPHERAL_ID_VALUE(  13, 0,  0,  0,  1,  5   ),
    ADI_INT_DMA6_UART_RX    = ADI_INT_PERIPHERAL_ID_VALUE(  14, 0,  0,  0,  1,  6   ),
    ADI_INT_DMA7_UART_TX    = ADI_INT_PERIPHERAL_ID_VALUE(  15, 0,  0,  0,  1,  7   ),
    ADI_INT_TIMER0          = ADI_INT_PERIPHERAL_ID_VALUE(  16, 0,  0,  0,  2,  0   ),
    ADI_INT_TIMER1          = ADI_INT_PERIPHERAL_ID_VALUE(  17, 0,  0,  0,  2,  1   ),
    ADI_INT_TIMER2          = ADI_INT_PERIPHERAL_ID_VALUE(  18, 0,  0,  0,  2,  2   ),
    ADI_INT_PFA             = ADI_INT_PERIPHERAL_ID_VALUE(  19, 0,  0,  0,  2,  3   ),
    ADI_INT_PFB             = ADI_INT_PERIPHERAL_ID_VALUE(  20, 0,  0,  0,  2,  4   ),
    ADI_INT_MDMAS0          = ADI_INT_PERIPHERAL_ID_VALUE(  21, 0,  0,  0,  2,  5   ),
    ADI_INT_MDMAS1          = ADI_INT_PERIPHERAL_ID_VALUE(  22, 0,  0,  0,  2,  6   ),
    ADI_INT_WATCHDOG        = ADI_INT_PERIPHERAL_ID_VALUE(  23, 0,  0,  0,  2,  7   )
} ADI_INT_PERIPHERAL_ID;

#endif  /* Edinburgh Peripheral IDs */



/********************
    Braemar
********************/

#if defined(__ADSP_BRAEMAR__)       /* peripheral IDs for BF534, BF536, BF537 */

typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP                  = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA_ERROR                   = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_PERIPHERAL_ERROR            = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_RTC                         = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_DMA0_PPI                    = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_DMA3_SPORT0_RX              = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_DMA4_SPORT0_TX              = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_DMA5_SPORT1_RX              = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_DMA6_SPORT1_TX              = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_TWI                         = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_DMA7_SPI                    = ADI_INT_PERIPHERAL_ID_VALUE(  10, 0,  0,  0,  1,  2   ),
    ADI_INT_DMA8_UART0_RX               = ADI_INT_PERIPHERAL_ID_VALUE(  11, 0,  0,  0,  1,  3   ),
    ADI_INT_DMA9_UART0_TX               = ADI_INT_PERIPHERAL_ID_VALUE(  12, 0,  0,  0,  1,  4   ),
    ADI_INT_DMA10_UART1_RX              = ADI_INT_PERIPHERAL_ID_VALUE(  13, 0,  0,  0,  1,  5   ),
    ADI_INT_DMA11_UART1_TX              = ADI_INT_PERIPHERAL_ID_VALUE(  14, 0,  0,  0,  1,  6   ),
    ADI_INT_CAN_RX                      = ADI_INT_PERIPHERAL_ID_VALUE(  15, 0,  0,  0,  1,  7   ),
    ADI_INT_CAN_TX                      = ADI_INT_PERIPHERAL_ID_VALUE(  16, 0,  0,  0,  2,  0   ),
    ADI_INT_DMA1_ETHERNET_RX_PORTH_A    = ADI_INT_PERIPHERAL_ID_VALUE(  17, 0,  0,  0,  2,  1   ),
    ADI_INT_DMA2_ETHERNET_TX_PORTH_B    = ADI_INT_PERIPHERAL_ID_VALUE(  18, 0,  0,  0,  2,  2   ),
    ADI_INT_TIMER0                      = ADI_INT_PERIPHERAL_ID_VALUE(  19, 0,  0,  0,  2,  3   ),
    ADI_INT_TIMER1                      = ADI_INT_PERIPHERAL_ID_VALUE(  20, 0,  0,  0,  2,  4   ),
    ADI_INT_TIMER2                      = ADI_INT_PERIPHERAL_ID_VALUE(  21, 0,  0,  0,  2,  5   ),
    ADI_INT_TIMER3                      = ADI_INT_PERIPHERAL_ID_VALUE(  22, 0,  0,  0,  2,  6   ),
    ADI_INT_TIMER4                      = ADI_INT_PERIPHERAL_ID_VALUE(  23, 0,  0,  0,  2,  7   ),
    ADI_INT_TIMER5                      = ADI_INT_PERIPHERAL_ID_VALUE(  24, 0,  0,  0,  3,  0   ),
    ADI_INT_TIMER6                      = ADI_INT_PERIPHERAL_ID_VALUE(  25, 0,  0,  0,  3,  1   ),
    ADI_INT_TIMER7                      = ADI_INT_PERIPHERAL_ID_VALUE(  26, 0,  0,  0,  3,  2   ),
    ADI_INT_PORTFG_A                    = ADI_INT_PERIPHERAL_ID_VALUE(  27, 0,  0,  0,  3,  3   ),
    ADI_INT_PORTG_B                     = ADI_INT_PERIPHERAL_ID_VALUE(  28, 0,  0,  0,  3,  4   ),
    ADI_INT_MDMAS0                      = ADI_INT_PERIPHERAL_ID_VALUE(  29, 0,  0,  0,  3,  5   ),
    ADI_INT_MDMAS1                      = ADI_INT_PERIPHERAL_ID_VALUE(  30, 0,  0,  0,  3,  6   ),
    ADI_INT_WATCHDOG_PORTF_B            = ADI_INT_PERIPHERAL_ID_VALUE(  31, 0,  0,  0,  3,  7   ),
    ADI_INT_WATCHDOG                    = ADI_INT_PERIPHERAL_ID_VALUE(  31, 0,  0,  0,  3,  7   )
} ADI_INT_PERIPHERAL_ID;

#endif  /* Braemar Peripheral IDs */


/********************
    Teton-Lite
********************/

#if defined(__ADSP_TETON__)                 /* Peripheral IDs for BF561  */

typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP          = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA1_ERROR          = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_DMA2_ERROR          = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_IMDMA_ERROR         = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_PPI0_ERROR          = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_PPI1_ERROR          = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_SPORT0_ERROR        = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_SPORT1_ERROR        = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_SPI_ERROR           = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_UART_ERROR          = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_RESERVED1           = ADI_INT_PERIPHERAL_ID_VALUE(  10, 0,  0,  0,  1,  2   ),
    ADI_INT_DMA1_0_PPI0         = ADI_INT_PERIPHERAL_ID_VALUE(  11, 0,  0,  0,  1,  3   ),
    ADI_INT_DMA1_1_PPI1         = ADI_INT_PERIPHERAL_ID_VALUE(  12, 0,  0,  0,  1,  4   ),
    ADI_INT_DMA1_2              = ADI_INT_PERIPHERAL_ID_VALUE(  13, 0,  0,  0,  1,  5   ),
    ADI_INT_DMA1_3              = ADI_INT_PERIPHERAL_ID_VALUE(  14, 0,  0,  0,  1,  6   ),
    ADI_INT_DMA1_4              = ADI_INT_PERIPHERAL_ID_VALUE(  15, 0,  0,  0,  1,  7   ),
    ADI_INT_DMA1_5              = ADI_INT_PERIPHERAL_ID_VALUE(  16, 0,  0,  0,  2,  0   ),
    ADI_INT_DMA1_6              = ADI_INT_PERIPHERAL_ID_VALUE(  17, 0,  0,  0,  2,  1   ),
    ADI_INT_DMA1_7              = ADI_INT_PERIPHERAL_ID_VALUE(  18, 0,  0,  0,  2,  2   ),
    ADI_INT_DMA1_8              = ADI_INT_PERIPHERAL_ID_VALUE(  19, 0,  0,  0,  2,  3   ),
    ADI_INT_DMA1_9              = ADI_INT_PERIPHERAL_ID_VALUE(  20, 0,  0,  0,  2,  4   ),
    ADI_INT_DMA1_10             = ADI_INT_PERIPHERAL_ID_VALUE(  21, 0,  0,  0,  2,  5   ),
    ADI_INT_DMA1_11             = ADI_INT_PERIPHERAL_ID_VALUE(  22, 0,  0,  0,  2,  6   ),
    ADI_INT_DMA2_0_SPORT0_RX    = ADI_INT_PERIPHERAL_ID_VALUE(  23, 0,  0,  0,  2,  7   ),
    ADI_INT_DMA2_1_SPORT0_TX    = ADI_INT_PERIPHERAL_ID_VALUE(  24, 0,  0,  0,  3,  0   ),
    ADI_INT_DMA2_2_SPORT1_RX    = ADI_INT_PERIPHERAL_ID_VALUE(  25, 0,  0,  0,  3,  1   ),
    ADI_INT_DMA2_3_SPORT1_TX    = ADI_INT_PERIPHERAL_ID_VALUE(  26, 0,  0,  0,  3,  2   ),
    ADI_INT_DMA2_4_SPI          = ADI_INT_PERIPHERAL_ID_VALUE(  27, 0,  0,  0,  3,  3   ),
    ADI_INT_DMA2_5_UART_RX      = ADI_INT_PERIPHERAL_ID_VALUE(  28, 0,  0,  0,  3,  4   ),
    ADI_INT_DMA2_6_UART_TX      = ADI_INT_PERIPHERAL_ID_VALUE(  29, 0,  0,  0,  3,  5   ),
    ADI_INT_DMA2_7              = ADI_INT_PERIPHERAL_ID_VALUE(  30, 0,  0,  0,  3,  6   ),
    ADI_INT_DMA2_8              = ADI_INT_PERIPHERAL_ID_VALUE(  31, 0,  0,  0,  3,  7   ),
    ADI_INT_DMA2_9              = ADI_INT_PERIPHERAL_ID_VALUE(  0,  1,  1,  1,  4,  0   ),
    ADI_INT_DMA2_10             = ADI_INT_PERIPHERAL_ID_VALUE(  1,  1,  1,  1,  4,  1   ),
    ADI_INT_DMA2_11             = ADI_INT_PERIPHERAL_ID_VALUE(  2,  1,  1,  1,  4,  2   ),
    ADI_INT_TIMER0              = ADI_INT_PERIPHERAL_ID_VALUE(  3,  1,  1,  1,  4,  3   ),
    ADI_INT_TIMER1              = ADI_INT_PERIPHERAL_ID_VALUE(  4,  1,  1,  1,  4,  4   ),
    ADI_INT_TIMER2              = ADI_INT_PERIPHERAL_ID_VALUE(  5,  1,  1,  1,  4,  5   ),
    ADI_INT_TIMER3              = ADI_INT_PERIPHERAL_ID_VALUE(  6,  1,  1,  1,  4,  6   ),
    ADI_INT_TIMER4              = ADI_INT_PERIPHERAL_ID_VALUE(  7,  1,  1,  1,  4,  7   ),
    ADI_INT_TIMER5              = ADI_INT_PERIPHERAL_ID_VALUE(  8,  1,  1,  1,  5,  0   ),
    ADI_INT_TIMER6              = ADI_INT_PERIPHERAL_ID_VALUE(  9,  1,  1,  1,  5,  1   ),
    ADI_INT_TIMER7              = ADI_INT_PERIPHERAL_ID_VALUE(  10, 1,  1,  1,  5,  2   ),
    ADI_INT_TIMER8              = ADI_INT_PERIPHERAL_ID_VALUE(  11, 1,  1,  1,  5,  3   ),
    ADI_INT_TIMER9              = ADI_INT_PERIPHERAL_ID_VALUE(  12, 1,  1,  1,  5,  4   ),
    ADI_INT_TIMER10             = ADI_INT_PERIPHERAL_ID_VALUE(  13, 1,  1,  1,  5,  5   ),
    ADI_INT_TIMER11             = ADI_INT_PERIPHERAL_ID_VALUE(  14, 1,  1,  1,  5,  6   ),
    ADI_INT_PF0_15_A            = ADI_INT_PERIPHERAL_ID_VALUE(  15, 1,  1,  1,  5,  7   ),
    ADI_INT_PF0_15_B            = ADI_INT_PERIPHERAL_ID_VALUE(  16, 1,  1,  1,  6,  0   ),
    ADI_INT_PF16_31_A           = ADI_INT_PERIPHERAL_ID_VALUE(  17, 1,  1,  1,  6,  1   ),
    ADI_INT_PF16_31_B           = ADI_INT_PERIPHERAL_ID_VALUE(  18, 1,  1,  1,  6,  2   ),
    ADI_INT_PF32_47_A           = ADI_INT_PERIPHERAL_ID_VALUE(  19, 1,  1,  1,  6,  3   ),
    ADI_INT_PF32_47_B           = ADI_INT_PERIPHERAL_ID_VALUE(  20, 1,  1,  1,  6,  4   ),
    ADI_INT_MDMA1_S0            = ADI_INT_PERIPHERAL_ID_VALUE(  21, 1,  1,  1,  6,  5   ),
    ADI_INT_MDMA1_S1            = ADI_INT_PERIPHERAL_ID_VALUE(  22, 1,  1,  1,  6,  6   ),
    ADI_INT_MDMA2_S0            = ADI_INT_PERIPHERAL_ID_VALUE(  23, 1,  1,  1,  6,  7   ),
    ADI_INT_MDMA2_S1            = ADI_INT_PERIPHERAL_ID_VALUE(  24, 1,  1,  1,  7,  0   ),
    ADI_INT_IMDMA_S0            = ADI_INT_PERIPHERAL_ID_VALUE(  25, 1,  1,  1,  7,  1   ),
    ADI_INT_IMDMA_S1            = ADI_INT_PERIPHERAL_ID_VALUE(  26, 1,  1,  1,  7,  2   ),
    ADI_INT_WATCHDOG            = ADI_INT_PERIPHERAL_ID_VALUE(  27, 1,  1,  1,  7,  3   ),
    ADI_INT_RESERVED2           = ADI_INT_PERIPHERAL_ID_VALUE(  28, 1,  1,  1,  7,  4   ),
    ADI_INT_RESERVED3           = ADI_INT_PERIPHERAL_ID_VALUE(  29, 1,  1,  1,  7,  5   ),
    ADI_INT_SI0                 = ADI_INT_PERIPHERAL_ID_VALUE(  30, 1,  1,  1,  7,  6   ),
    ADI_INT_SI1                 = ADI_INT_PERIPHERAL_ID_VALUE(  31, 1,  1,  1,  7,  7   )
} ADI_INT_PERIPHERAL_ID;

#endif  /* BF561 Peripheral IDs  */


/********************
    Stirling
********************/

#if defined(__ADSP_STIRLING__)      /* peripheral IDs for BF538, BF539 */
typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP      = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA0_ERROR      = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_PPI_ERROR       = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_SPORT0_ERROR    = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_SPORT1_ERROR    = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_SPI0_ERROR      = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_UART0_ERROR     = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_RTC             = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_DMA0_PPI        = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_DMA1_SPORT0_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_DMA2_SPORT0_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  10, 0,  0,  0,  1,  2   ),
    ADI_INT_DMA3_SPORT1_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  11, 0,  0,  0,  1,  3   ),
    ADI_INT_DMA4_SPORT1_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  12, 0,  0,  0,  1,  4   ),
    ADI_INT_DMA5_SPI0       = ADI_INT_PERIPHERAL_ID_VALUE(  13, 0,  0,  0,  1,  5   ),
    ADI_INT_DMA6_UART0_RX   = ADI_INT_PERIPHERAL_ID_VALUE(  14, 0,  0,  0,  1,  6   ),
    ADI_INT_DMA7_UART0_TX   = ADI_INT_PERIPHERAL_ID_VALUE(  15, 0,  0,  0,  1,  7   ),
    ADI_INT_TIMER0          = ADI_INT_PERIPHERAL_ID_VALUE(  16, 0,  0,  0,  2,  0   ),
    ADI_INT_TIMER1          = ADI_INT_PERIPHERAL_ID_VALUE(  17, 0,  0,  0,  2,  1   ),
    ADI_INT_TIMER2          = ADI_INT_PERIPHERAL_ID_VALUE(  18, 0,  0,  0,  2,  2   ),
    ADI_INT_PFA             = ADI_INT_PERIPHERAL_ID_VALUE(  19, 0,  0,  0,  2,  3   ),
    ADI_INT_PFB             = ADI_INT_PERIPHERAL_ID_VALUE(  20, 0,  0,  0,  2,  4   ),
    ADI_INT_MDMA0_S0        = ADI_INT_PERIPHERAL_ID_VALUE(  21, 0,  0,  0,  2,  5   ),
    ADI_INT_MDMA0_S1        = ADI_INT_PERIPHERAL_ID_VALUE(  22, 0,  0,  0,  2,  6   ),
    ADI_INT_WATCHDOG        = ADI_INT_PERIPHERAL_ID_VALUE(  23, 0,  0,  0,  2,  7   ),
    ADI_INT_DMA1_ERROR      = ADI_INT_PERIPHERAL_ID_VALUE(  24, 0,  0,  0,  3,  0   ),
    ADI_INT_SPORT2_ERROR    = ADI_INT_PERIPHERAL_ID_VALUE(  25, 0,  0,  0,  3,  1   ),
    ADI_INT_SPORT3_ERROR    = ADI_INT_PERIPHERAL_ID_VALUE(  26, 0,  0,  0,  3,  2   ),
    ADI_INT_MXVR_SYNC       = ADI_INT_PERIPHERAL_ID_VALUE(  27, 0,  0,  0,  3,  3   ),
    ADI_INT_SPI1_ERROR      = ADI_INT_PERIPHERAL_ID_VALUE(  28, 0,  0,  0,  3,  4   ),
    ADI_INT_SPI2_ERROR      = ADI_INT_PERIPHERAL_ID_VALUE(  29, 0,  0,  0,  3,  5   ),
    ADI_INT_UART1_ERROR     = ADI_INT_PERIPHERAL_ID_VALUE(  30, 0,  0,  0,  3,  6   ),
    ADI_INT_UART2_ERROR     = ADI_INT_PERIPHERAL_ID_VALUE(  31, 0,  0,  0,  3,  7   ),
    ADI_INT_CAN_ERROR       = ADI_INT_PERIPHERAL_ID_VALUE(  0,  3,  7,  3,  9,  0   ),
    ADI_INT_DMA8_SPORT2_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  1,  3,  7,  3,  9,  1   ),
    ADI_INT_DMA9_SPORT2_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  2,  3,  7,  3,  9,  2   ),
    ADI_INT_DMA10_SPORT3_RX = ADI_INT_PERIPHERAL_ID_VALUE(  3,  3,  7,  3,  9,  3   ),
    ADI_INT_DMA11_SPORT3_TX = ADI_INT_PERIPHERAL_ID_VALUE(  4,  3,  7,  3,  9,  4   ),
    ADI_INT_DMA12           = ADI_INT_PERIPHERAL_ID_VALUE(  5,  3,  7,  3,  9,  5   ),
    ADI_INT_DMA13           = ADI_INT_PERIPHERAL_ID_VALUE(  6,  3,  7,  3,  9,  6   ),
    ADI_INT_DMA14_SPI1      = ADI_INT_PERIPHERAL_ID_VALUE(  7,  3,  7,  3,  9,  7   ),
    ADI_INT_DMA15_SPI2      = ADI_INT_PERIPHERAL_ID_VALUE(  8,  3,  7,  3,  10, 0   ),
    ADI_INT_DMA16_UART1_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  9,  3,  7,  3,  10, 1   ),
    ADI_INT_DMA17_UART1_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  10, 3,  7,  3,  10, 2   ),
    ADI_INT_DMA18_UART2_RX  = ADI_INT_PERIPHERAL_ID_VALUE(  11, 3,  7,  3,  10, 3   ),
    ADI_INT_DMA19_UART2_TX  = ADI_INT_PERIPHERAL_ID_VALUE(  12, 3,  7,  3,  10, 4   ),
    ADI_INT_TWI0            = ADI_INT_PERIPHERAL_ID_VALUE(  13, 3,  7,  3,  10, 5   ),
    ADI_INT_TWI1            = ADI_INT_PERIPHERAL_ID_VALUE(  14, 3,  7,  3,  10, 6   ),
    ADI_INT_CAN_RX          = ADI_INT_PERIPHERAL_ID_VALUE(  15, 3,  7,  3,  10, 7   ),
    ADI_INT_CAN_TX          = ADI_INT_PERIPHERAL_ID_VALUE(  16, 3,  7,  3,  11, 0   ),
    ADI_INT_MDMA1_S0        = ADI_INT_PERIPHERAL_ID_VALUE(  17, 3,  7,  3,  11, 1   ),
    ADI_INT_MDMA1_S1        = ADI_INT_PERIPHERAL_ID_VALUE(  18, 3,  7,  3,  11, 2   ),
    ADI_INT_MXVR_STATUS     = ADI_INT_PERIPHERAL_ID_VALUE(  19, 3,  7,  3,  11, 3   ),
    ADI_INT_MXVR_CONTROL    = ADI_INT_PERIPHERAL_ID_VALUE(  20, 3,  7,  3,  11, 4   ),
    ADI_INT_MXVR_ASYNC      = ADI_INT_PERIPHERAL_ID_VALUE(  21, 3,  7,  3,  11, 5   )
} ADI_INT_PERIPHERAL_ID;

#endif  /* Stirling Peripheral IDs */



/********************
    Moab
********************/

#if defined(__ADSP_MOAB__)      /* peripheral IDs for BF54x */
typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP              = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMAC0_ERROR             = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_EPPI0_ERROR             = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_SPORT0_ERROR            = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_SPORT1_ERROR            = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_SPI0_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_UART0_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_RTC                     = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_DMA12_EPPI0             = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_DMA0_SPORT0_RX          = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_DMA1_SPORT0_TX          = ADI_INT_PERIPHERAL_ID_VALUE(  10, 0,  0,  0,  1,  2   ),
    ADI_INT_DMA2_SPORT1_RX          = ADI_INT_PERIPHERAL_ID_VALUE(  11, 0,  0,  0,  1,  3   ),
    ADI_INT_DMA3_SPORT1_TX          = ADI_INT_PERIPHERAL_ID_VALUE(  12, 0,  0,  0,  1,  4   ),
    ADI_INT_DMA4_SPI0               = ADI_INT_PERIPHERAL_ID_VALUE(  13, 0,  0,  0,  1,  5   ),
    ADI_INT_DMA6_UART0_RX           = ADI_INT_PERIPHERAL_ID_VALUE(  14, 0,  0,  0,  1,  6   ),
    ADI_INT_DMA7_UART0_TX           = ADI_INT_PERIPHERAL_ID_VALUE(  15, 0,  0,  0,  1,  7   ),
    ADI_INT_TIMER8                  = ADI_INT_PERIPHERAL_ID_VALUE(  16, 0,  0,  0,  2,  0   ),
    ADI_INT_TIMER9                  = ADI_INT_PERIPHERAL_ID_VALUE(  17, 0,  0,  0,  2,  1   ),
    ADI_INT_TIMER10                 = ADI_INT_PERIPHERAL_ID_VALUE(  18, 0,  0,  0,  2,  2   ),
    ADI_INT_PINT0                   = ADI_INT_PERIPHERAL_ID_VALUE(  19, 0,  0,  0,  2,  3   ),
    ADI_INT_PINT1                   = ADI_INT_PERIPHERAL_ID_VALUE(  20, 0,  0,  0,  2,  4   ),
    ADI_INT_MDMA_S0                 = ADI_INT_PERIPHERAL_ID_VALUE(  21, 0,  0,  0,  2,  5   ),
    ADI_INT_MDMA_S1                 = ADI_INT_PERIPHERAL_ID_VALUE(  22, 0,  0,  0,  2,  6   ),
    ADI_INT_WATCHDOG                = ADI_INT_PERIPHERAL_ID_VALUE(  23, 0,  0,  0,  2,  7   ),
    ADI_INT_DMAC1_ERROR             = ADI_INT_PERIPHERAL_ID_VALUE(  24, 0,  0,  0,  3,  0   ),
    ADI_INT_SPORT2_ERROR            = ADI_INT_PERIPHERAL_ID_VALUE(  25, 0,  0,  0,  3,  1   ),
    ADI_INT_SPORT3_ERROR            = ADI_INT_PERIPHERAL_ID_VALUE(  26, 0,  0,  0,  3,  2   ),
    ADI_INT_MXVR_SYNC               = ADI_INT_PERIPHERAL_ID_VALUE(  27, 0,  0,  0,  3,  3   ),
    ADI_INT_SPI1_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  28, 0,  0,  0,  3,  4   ),
    ADI_INT_SPI2_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  29, 0,  0,  0,  3,  5   ),
    ADI_INT_UART1_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  30, 0,  0,  0,  3,  6   ),
    ADI_INT_UART2_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  31, 0,  0,  0,  3,  7   ),
    ADI_INT_CAN0_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  0,  1,  1,  1,  4,  0   ),
    ADI_INT_DMA18_SPORT2_RX         = ADI_INT_PERIPHERAL_ID_VALUE(  1,  1,  1,  1,  4,  1   ),
    ADI_INT_DMA19_SPORT2_TX         = ADI_INT_PERIPHERAL_ID_VALUE(  2,  1,  1,  1,  4,  2   ),
    ADI_INT_DMA20_SPORT3_RX         = ADI_INT_PERIPHERAL_ID_VALUE(  3,  1,  1,  1,  4,  3   ),
    ADI_INT_DMA21_SPORT3_TX         = ADI_INT_PERIPHERAL_ID_VALUE(  4,  1,  1,  1,  4,  4   ),
    ADI_INT_DMA13_EPPI1             = ADI_INT_PERIPHERAL_ID_VALUE(  5,  1,  1,  1,  4,  5   ),
    ADI_INT_DMA14_EPPI2_HOST        = ADI_INT_PERIPHERAL_ID_VALUE(  6,  1,  1,  1,  4,  6   ),
    ADI_INT_DMA5_SPI1               = ADI_INT_PERIPHERAL_ID_VALUE(  7,  1,  1,  1,  4,  7   ),
    ADI_INT_DMA23_SPI2              = ADI_INT_PERIPHERAL_ID_VALUE(  8,  1,  1,  1,  5,  0   ),
    ADI_INT_DMA8_UART1_RX           = ADI_INT_PERIPHERAL_ID_VALUE(  9,  1,  1,  1,  5,  1   ),
    ADI_INT_DMA9_UART1_TX           = ADI_INT_PERIPHERAL_ID_VALUE(  10, 1,  1,  1,  5,  2   ),
    ADI_INT_DMA10_ATAPI_RX          = ADI_INT_PERIPHERAL_ID_VALUE(  11, 1,  1,  1,  5,  3   ),
    ADI_INT_DMA11_ATAPI_TX          = ADI_INT_PERIPHERAL_ID_VALUE(  12, 1,  1,  1,  5,  4   ),
    ADI_INT_TWI0                    = ADI_INT_PERIPHERAL_ID_VALUE(  13, 1,  1,  1,  5,  5   ),
    ADI_INT_TWI1                    = ADI_INT_PERIPHERAL_ID_VALUE(  14, 1,  1,  1,  5,  6   ),
    ADI_INT_CAN0_RX                 = ADI_INT_PERIPHERAL_ID_VALUE(  15, 1,  1,  1,  5,  7   ),
    ADI_INT_CAN0_TX                 = ADI_INT_PERIPHERAL_ID_VALUE(  16, 1,  1,  1,  6,  0   ),
    ADI_INT_MDMA_S2                 = ADI_INT_PERIPHERAL_ID_VALUE(  17, 1,  1,  1,  6,  1   ),
    ADI_INT_MDMA_S3                 = ADI_INT_PERIPHERAL_ID_VALUE(  18, 1,  1,  1,  6,  2   ),
    ADI_INT_MXVR_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  19, 1,  1,  1,  6,  3   ),
    ADI_INT_MXVR_CONTROL            = ADI_INT_PERIPHERAL_ID_VALUE(  20, 1,  1,  1,  6,  4   ),
    ADI_INT_MXVR_ASYNC              = ADI_INT_PERIPHERAL_ID_VALUE(  21, 1,  1,  1,  6,  5   ),
    ADI_INT_EPPI1_ERROR             = ADI_INT_PERIPHERAL_ID_VALUE(  22, 1,  1,  1,  6,  6   ),
    ADI_INT_EPPI2_ERROR             = ADI_INT_PERIPHERAL_ID_VALUE(  23, 1,  1,  1,  6,  7   ),
    ADI_INT_UART3_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  24, 1,  1,  1,  7,  0   ),
    ADI_INT_HOST_ERROR              = ADI_INT_PERIPHERAL_ID_VALUE(  25, 1,  1,  1,  7,  1   ),
    ADI_INT_RESERVED0               = ADI_INT_PERIPHERAL_ID_VALUE(  26, 1,  1,  1,  7,  2   ),
    ADI_INT_PIXC_ERROR              = ADI_INT_PERIPHERAL_ID_VALUE(  27, 1,  1,  1,  7,  3   ),
    ADI_INT_NFC_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  28, 1,  1,  1,  7,  4   ),
    ADI_INT_ATAPI_ERROR             = ADI_INT_PERIPHERAL_ID_VALUE(  29, 1,  1,  1,  7,  5   ),
    ADI_INT_CAN1_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  30, 1,  1,  1,  7,  6   ),
    ADI_INT_DMAR_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  31, 1,  1,  1,  7,  7   ),
    ADI_INT_DMA15_PIXC_IMAGE        = ADI_INT_PERIPHERAL_ID_VALUE(   0, 2,  2,  2,  8,  0   ),
    ADI_INT_DMA16_PIXC_OVERLAY      = ADI_INT_PERIPHERAL_ID_VALUE(   1, 2,  2,  2,  8,  1   ),
    ADI_INT_DMA17_PIXC_OUTPUT       = ADI_INT_PERIPHERAL_ID_VALUE(   2, 2,  2,  2,  8,  2   ),
    ADI_INT_DMA22_SDH_NFC           = ADI_INT_PERIPHERAL_ID_VALUE(   3, 2,  2,  2,  8,  3   ),
    ADI_INT_COUNTER                 = ADI_INT_PERIPHERAL_ID_VALUE(   4, 2,  2,  2,  8,  4   ),
    ADI_INT_KEYPAD                  = ADI_INT_PERIPHERAL_ID_VALUE(   5, 2,  2,  2,  8,  5   ),
    ADI_INT_CAN1_RX                 = ADI_INT_PERIPHERAL_ID_VALUE(   6, 2,  2,  2,  8,  6   ),
    ADI_INT_CAN1_TX                 = ADI_INT_PERIPHERAL_ID_VALUE(   7, 2,  2,  2,  8,  7   ),
    ADI_INT_SDH_INT0                = ADI_INT_PERIPHERAL_ID_VALUE(   8, 2,  2,  2,  9,  0   ),
    ADI_INT_SDH_INT1                = ADI_INT_PERIPHERAL_ID_VALUE(   9, 2,  2,  2,  9,  1   ),
    ADI_INT_RESERVED1               = ADI_INT_PERIPHERAL_ID_VALUE(  10, 2,  2,  2,  9,  2   ),
    ADI_INT_USB_INT0                = ADI_INT_PERIPHERAL_ID_VALUE(  11, 2,  2,  2,  9,  3   ),
    ADI_INT_USB_INT1                = ADI_INT_PERIPHERAL_ID_VALUE(  12, 2,  2,  2,  9,  4   ),
    ADI_INT_USB_INT2                = ADI_INT_PERIPHERAL_ID_VALUE(  13, 2,  2,  2,  9,  5   ),
    ADI_INT_USB_DMAINT              = ADI_INT_PERIPHERAL_ID_VALUE(  14, 2,  2,  2,  9,  6   ),
    ADI_INT_OTP                     = ADI_INT_PERIPHERAL_ID_VALUE(  15, 2,  2,  2,  9,  7   ),
    ADI_INT_RESERVED2               = ADI_INT_PERIPHERAL_ID_VALUE(  16, 2,  2,  2,  10, 0   ),
    ADI_INT_RESERVED3               = ADI_INT_PERIPHERAL_ID_VALUE(  17, 2,  2,  2,  10, 1   ),
    ADI_INT_RESERVED4               = ADI_INT_PERIPHERAL_ID_VALUE(  18, 2,  2,  2,  10, 2   ),
    ADI_INT_RESERVED5               = ADI_INT_PERIPHERAL_ID_VALUE(  19, 2,  2,  2,  10, 3   ),
    ADI_INT_RESERVED6               = ADI_INT_PERIPHERAL_ID_VALUE(  20, 2,  2,  2,  10, 4   ),
    ADI_INT_RESERVED7               = ADI_INT_PERIPHERAL_ID_VALUE(  21, 2,  2,  2,  10, 5   ),
    ADI_INT_TIMER0                  = ADI_INT_PERIPHERAL_ID_VALUE(  22, 2,  2,  2,  10, 6   ),
    ADI_INT_TIMER1                  = ADI_INT_PERIPHERAL_ID_VALUE(  23, 2,  2,  2,  10, 7   ),
    ADI_INT_TIMER2                  = ADI_INT_PERIPHERAL_ID_VALUE(  24, 2,  2,  2,  11, 0   ),
    ADI_INT_TIMER3                  = ADI_INT_PERIPHERAL_ID_VALUE(  25, 2,  2,  2,  11, 1   ),
    ADI_INT_TIMER4                  = ADI_INT_PERIPHERAL_ID_VALUE(  26, 2,  2,  2,  11, 2   ),
    ADI_INT_TIMER5                  = ADI_INT_PERIPHERAL_ID_VALUE(  27, 2,  2,  2,  11, 3   ),
    ADI_INT_TIMER6                  = ADI_INT_PERIPHERAL_ID_VALUE(  28, 2,  2,  2,  11, 4   ),
    ADI_INT_TIMER7                  = ADI_INT_PERIPHERAL_ID_VALUE(  29, 2,  2,  2,  11, 5   ),
    ADI_INT_PINT2                   = ADI_INT_PERIPHERAL_ID_VALUE(  30, 2,  2,  2,  11, 6   ),
    ADI_INT_PINT3                   = ADI_INT_PERIPHERAL_ID_VALUE(  31, 2,  2,  2,  11, 7   ),

    /* obsoleted */
    ADI_INT_OTPSEC                  = ADI_INT_OTP

} ADI_INT_PERIPHERAL_ID;

#endif  /* Moab Peripheral IDs */

/********************
    Kookaburra/Mockingbird
********************/

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)      /* peripheral IDs for BF52x */

typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP              = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_DMAR0_BLOCK             = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_DMAR1_BLOCK             = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_DMAR0_OVERFLOW          = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_DMAR1_OVERFLOW          = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_PPI_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_MAC_STATUS              = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_SPORT0_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_SPORT1_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_RESERVED0               = ADI_INT_PERIPHERAL_ID_VALUE( 10,  0,  0,  0,  1,  2   ),
    ADI_INT_RESERVED1               = ADI_INT_PERIPHERAL_ID_VALUE( 11,  0,  0,  0,  1,  3   ),
    ADI_INT_UART0_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE( 12,  0,  0,  0,  1,  4   ),
    ADI_INT_UART1_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE( 13,  0,  0,  0,  1,  5   ),
    ADI_INT_RTC                     = ADI_INT_PERIPHERAL_ID_VALUE( 14,  0,  0,  0,  1,  6   ),
    ADI_INT_DMA0_PPI                = ADI_INT_PERIPHERAL_ID_VALUE( 15,  0,  0,  0,  1,  7   ),
    ADI_INT_DMA3_SPORT0_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 16,  0,  0,  0,  2,  0   ),
    ADI_INT_DMA4_SPORT0_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 17,  0,  0,  0,  2,  1   ),
    ADI_INT_DMA5_SPORT1_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 18,  0,  0,  0,  2,  2   ),
    ADI_INT_DMA6_SPORT1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 19,  0,  0,  0,  2,  3   ),
    ADI_INT_TWI                     = ADI_INT_PERIPHERAL_ID_VALUE( 20,  0,  0,  0,  2,  4   ),
    ADI_INT_DMA7_SPI                = ADI_INT_PERIPHERAL_ID_VALUE( 21,  0,  0,  0,  2,  5   ),
    ADI_INT_DMA8_UART0_RX           = ADI_INT_PERIPHERAL_ID_VALUE( 22,  0,  0,  0,  2,  6   ),
    ADI_INT_DMA9_UART0_TX           = ADI_INT_PERIPHERAL_ID_VALUE( 23,  0,  0,  0,  2,  7   ),
    ADI_INT_DMA10_UART1_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 24,  0,  0,  0,  3,  0   ),
    ADI_INT_DMA11_UART1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 25,  0,  0,  0,  3,  1   ),
    ADI_INT_OTP                     = ADI_INT_PERIPHERAL_ID_VALUE( 26,  0,  0,  0,  3,  2   ),

    /* resolve naming confision between Moab, Kookaburra, Mockingburd and Brodie; support both */
    ADI_INT_COUNTER                 = ADI_INT_PERIPHERAL_ID_VALUE( 27,  0,  0,  0,  3,  3   ),  /* different name, same as ADI_INT_GP_COUNTER */
    ADI_INT_GP_COUNTER              = ADI_INT_PERIPHERAL_ID_VALUE( 27,  0,  0,  0,  3,  3   ),  /* different name, same as ADI_INT_COUNTER */

    ADI_INT_DMA1_MAC_RX             = ADI_INT_PERIPHERAL_ID_VALUE( 28,  0,  0,  0,  3,  4   ),
    ADI_INT_PORTH_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 29,  0,  0,  0,  3,  5   ),
    ADI_INT_DMA2_MAC_TX             = ADI_INT_PERIPHERAL_ID_VALUE( 30,  0,  0,  0,  3,  6   ),
    ADI_INT_PORTH_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 31,  0,  0,  0,  3,  7   ),
      /***************************************************************************************\
      |  Kookaburra/Mockingbird contains gaps in the register space that are discontiguous:   |
      |   a 64-byte gap (16 longs) between SIC_ISR0 and SIC_ISR1     (add 16 to offset)       |
      |   a 64-byte gap (16 longs) between SIC_IMASK0 and SIC_IMASK1 (add 16 to offset)       |
      |   a 64-byte gap (16 longs) between SIC_IWR0 and SIC_IWR1     (add 16 to offset)       |
      |   a 52-byte gap (13 longs) between SIC_IAR3 and SIC_IAR4     (add 13 to offset)       |
      \***************************************************************************************/
    ADI_INT_TIMER0                  = ADI_INT_PERIPHERAL_ID_VALUE(  0, 16, 16, 16, 16,  0   ),
    ADI_INT_TIMER1                  = ADI_INT_PERIPHERAL_ID_VALUE(  1, 16, 16, 16, 16,  1   ),
    ADI_INT_TIMER2                  = ADI_INT_PERIPHERAL_ID_VALUE(  2, 16, 16, 16, 16,  2   ),
    ADI_INT_TIMER3                  = ADI_INT_PERIPHERAL_ID_VALUE(  3, 16, 16, 16, 16,  3   ),
    ADI_INT_TIMER4                  = ADI_INT_PERIPHERAL_ID_VALUE(  4, 16, 16, 16, 16,  4   ),
    ADI_INT_TIMER5                  = ADI_INT_PERIPHERAL_ID_VALUE(  5, 16, 16, 16, 16,  5   ),
    ADI_INT_TIMER6                  = ADI_INT_PERIPHERAL_ID_VALUE(  6, 16, 16, 16, 16,  6   ),
    ADI_INT_TIMER7                  = ADI_INT_PERIPHERAL_ID_VALUE(  7, 16, 16, 16, 16,  7   ),
    ADI_INT_PORTG_INTA              = ADI_INT_PERIPHERAL_ID_VALUE(  8, 16, 16, 16, 17,  0   ),
    ADI_INT_PORTG_INTB              = ADI_INT_PERIPHERAL_ID_VALUE(  9, 16, 16, 16, 17,  1   ),
    ADI_INT_MDMA0                   = ADI_INT_PERIPHERAL_ID_VALUE( 10, 16, 16, 16, 17,  2   ),
    ADI_INT_MDMA1                   = ADI_INT_PERIPHERAL_ID_VALUE( 11, 16, 16, 16, 17,  3   ),
    ADI_INT_WATCHDOG                = ADI_INT_PERIPHERAL_ID_VALUE( 12, 16, 16, 16, 17,  4   ),
    ADI_INT_PORTF_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 13, 16, 16, 16, 17,  5   ),
    ADI_INT_PORTF_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 14, 16, 16, 16, 17,  6   ),
    ADI_INT_SPI_STATUS              = ADI_INT_PERIPHERAL_ID_VALUE( 15, 16, 16, 16, 17,  7   ),
    ADI_INT_NAND_ERROR              = ADI_INT_PERIPHERAL_ID_VALUE( 16, 16, 16, 16, 18,  0   ),
    ADI_INT_HDMA_ERROR              = ADI_INT_PERIPHERAL_ID_VALUE( 17, 16, 16, 16, 18,  1   ),
    ADI_INT_HDMA_TFI                = ADI_INT_PERIPHERAL_ID_VALUE( 18, 16, 16, 16, 18,  2   ),
    ADI_INT_USB_EINT                = ADI_INT_PERIPHERAL_ID_VALUE( 19, 16, 16, 16, 18,  3   ),
    ADI_INT_USB_INT0                = ADI_INT_PERIPHERAL_ID_VALUE( 20, 16, 16, 16, 18,  4   ),
    ADI_INT_USB_INT1                = ADI_INT_PERIPHERAL_ID_VALUE( 21, 16, 16, 16, 18,  5   ),
    ADI_INT_USB_INT2                = ADI_INT_PERIPHERAL_ID_VALUE( 22, 16, 16, 16, 18,  6   ),
    ADI_INT_USB_DMAINT              = ADI_INT_PERIPHERAL_ID_VALUE( 23, 16, 16, 16, 18,  7   ),
    ADI_INT_RESERVED2               = ADI_INT_PERIPHERAL_ID_VALUE( 24, 16, 16, 16, 19,  0   ),
    ADI_INT_RESERVED3               = ADI_INT_PERIPHERAL_ID_VALUE( 25, 16, 16, 16, 19,  1   ),
    ADI_INT_RESERVED4               = ADI_INT_PERIPHERAL_ID_VALUE( 26, 16, 16, 16, 19,  2   ),
    ADI_INT_RESERVED5               = ADI_INT_PERIPHERAL_ID_VALUE( 27, 16, 16, 16, 19,  3   ),
    ADI_INT_RESERVED6               = ADI_INT_PERIPHERAL_ID_VALUE( 28, 16, 16, 16, 19,  4   ),
    ADI_INT_RESERVED7               = ADI_INT_PERIPHERAL_ID_VALUE( 29, 16, 16, 16, 19,  5   ),
    ADI_INT_RESERVED8               = ADI_INT_PERIPHERAL_ID_VALUE( 30, 16, 16, 16, 19,  6   ),
    ADI_INT_RESERVED9               = ADI_INT_PERIPHERAL_ID_VALUE( 31, 16, 16, 16, 19,  7   ),

    /* Obsoleted */
    ADI_INT_OTPSEC                  = ADI_INT_OTP

} ADI_INT_PERIPHERAL_ID;

#endif  /* Kookaburra/Mockingbird Peripheral IDs */



/********************
    Brodie
********************/

#if defined(__ADSP_BRODIE__)     /* peripheral IDs for BF51x */

typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP              = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_DMAR0_BLOCK             = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_DMAR1_BLOCK             = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_DMAR0_OVERFLOW          = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_DMAR1_OVERFLOW          = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_PPI_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_MAC_STATUS              = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_SPORT0_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_SPORT1_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_PTP_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE( 10,  0,  0,  0,  1,  2   ),
    ADI_INT_RESERVED0               = ADI_INT_PERIPHERAL_ID_VALUE( 11,  0,  0,  0,  1,  3   ),
    ADI_INT_UART0_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE( 12,  0,  0,  0,  1,  4   ),
    ADI_INT_UART1_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE( 13,  0,  0,  0,  1,  5   ),
    ADI_INT_RTC                     = ADI_INT_PERIPHERAL_ID_VALUE( 14,  0,  0,  0,  1,  6   ),
    ADI_INT_DMA0_PPI                = ADI_INT_PERIPHERAL_ID_VALUE( 15,  0,  0,  0,  1,  7   ),
    ADI_INT_DMA3_SPORT0_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 16,  0,  0,  0,  2,  0   ),
    ADI_INT_DMA4_SPORT0_TX_AND_RSI  = ADI_INT_PERIPHERAL_ID_VALUE( 17,  0,  0,  0,  2,  1   ),
    ADI_INT_DMA5_SPORT1_RX_AND_SPI1 = ADI_INT_PERIPHERAL_ID_VALUE( 18,  0,  0,  0,  2,  2   ),
    ADI_INT_DMA6_SPORT1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 19,  0,  0,  0,  2,  3   ),
    ADI_INT_TWI                     = ADI_INT_PERIPHERAL_ID_VALUE( 20,  0,  0,  0,  2,  4   ),
    ADI_INT_DMA7_SPI0               = ADI_INT_PERIPHERAL_ID_VALUE( 21,  0,  0,  0,  2,  5   ),
    ADI_INT_DMA8_UART0_RX           = ADI_INT_PERIPHERAL_ID_VALUE( 22,  0,  0,  0,  2,  6   ),
    ADI_INT_DMA9_UART0_TX           = ADI_INT_PERIPHERAL_ID_VALUE( 23,  0,  0,  0,  2,  7   ),
    ADI_INT_DMA10_UART1_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 24,  0,  0,  0,  3,  0   ),
    ADI_INT_DMA11_UART1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 25,  0,  0,  0,  3,  1   ),
    ADI_INT_OTPSEC                  = ADI_INT_PERIPHERAL_ID_VALUE( 26,  0,  0,  0,  3,  2   ),
    ADI_INT_COUNTER                 = ADI_INT_PERIPHERAL_ID_VALUE( 27,  0,  0,  0,  3,  3   ),
    ADI_INT_DMA1_MAC_RX             = ADI_INT_PERIPHERAL_ID_VALUE( 28,  0,  0,  0,  3,  4   ),
    ADI_INT_PORTH_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 29,  0,  0,  0,  3,  5   ),
    ADI_INT_DMA2_MAC_TX             = ADI_INT_PERIPHERAL_ID_VALUE( 30,  0,  0,  0,  3,  6   ),
    ADI_INT_PORTH_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 31,  0,  0,  0,  3,  7   ),
      /***************************************************************************************\
      |  Brodie contains gaps in the ISR/IMASK/IWR/IAR address space, introducing a gap       |
      |  between registers.  The  normal 32-bit pointer math moves 4-bytes at a time through  |
      |  the MMR address space, but we need an additional 12 bytes to span the gap from the   |
      |  next expected register to the next actual register.  The gap amounts to a 12 32-bit  |
      |  slots, resulting 16 32-bit addresses from IAR0 to IAR4 (for example), while the IAR3 |
      |  offset was only 3                                                                    |
      \***************************************************************************************/
    ADI_INT_TIMER0                  = ADI_INT_PERIPHERAL_ID_VALUE(  0, 16, 16, 16, 16,  0   ),
    ADI_INT_TIMER1                  = ADI_INT_PERIPHERAL_ID_VALUE(  1, 16, 16, 16, 16,  1   ),
    ADI_INT_TIMER2                  = ADI_INT_PERIPHERAL_ID_VALUE(  2, 16, 16, 16, 16,  2   ),
    ADI_INT_TIMER3                  = ADI_INT_PERIPHERAL_ID_VALUE(  3, 16, 16, 16, 16,  3   ),
    ADI_INT_TIMER4                  = ADI_INT_PERIPHERAL_ID_VALUE(  4, 16, 16, 16, 16,  4   ),
    ADI_INT_TIMER5                  = ADI_INT_PERIPHERAL_ID_VALUE(  5, 16, 16, 16, 16,  5   ),
    ADI_INT_TIMER6                  = ADI_INT_PERIPHERAL_ID_VALUE(  6, 16, 16, 16, 16,  6   ),
    ADI_INT_TIMER7                  = ADI_INT_PERIPHERAL_ID_VALUE(  7, 16, 16, 16, 16,  7   ),
    ADI_INT_PORTG_INTA              = ADI_INT_PERIPHERAL_ID_VALUE(  8, 16, 16, 16, 17,  0   ),
    ADI_INT_PORTG_INTB              = ADI_INT_PERIPHERAL_ID_VALUE(  9, 16, 16, 16, 17,  1   ),
    ADI_INT_MDMA0                   = ADI_INT_PERIPHERAL_ID_VALUE( 10, 16, 16, 16, 17,  2   ),
    ADI_INT_MDMA1                   = ADI_INT_PERIPHERAL_ID_VALUE( 11, 16, 16, 16, 17,  3   ),
    ADI_INT_WATCHDOG                = ADI_INT_PERIPHERAL_ID_VALUE( 12, 16, 16, 16, 17,  4   ),
    ADI_INT_PORTF_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 13, 16, 16, 16, 17,  5   ),
    ADI_INT_PORTF_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 14, 16, 16, 16, 17,  6   ),
    ADI_INT_SPI0_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE( 15, 16, 16, 16, 17,  7   ),
    ADI_INT_SPI1_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE( 16, 16, 16, 16, 18,  0   ),
    ADI_INT_RESERVED1               = ADI_INT_PERIPHERAL_ID_VALUE( 17, 16, 16, 16, 18,  1   ),
    ADI_INT_RESERVED2               = ADI_INT_PERIPHERAL_ID_VALUE( 18, 16, 16, 16, 18,  2   ),
    ADI_INT_RSI0                    = ADI_INT_PERIPHERAL_ID_VALUE( 19, 16, 16, 16, 18,  3   ),
    ADI_INT_RSI1                    = ADI_INT_PERIPHERAL_ID_VALUE( 20, 16, 16, 16, 18,  4   ),
    ADI_INT_PWM_TRIP                = ADI_INT_PERIPHERAL_ID_VALUE( 21, 16, 16, 16, 18,  5   ),
    ADI_INT_PWM_SYNC                = ADI_INT_PERIPHERAL_ID_VALUE( 22, 16, 16, 16, 18,  6   ),
    ADI_INT_PTP_STATUS              = ADI_INT_PERIPHERAL_ID_VALUE( 23, 16, 16, 16, 18,  7   ),
    ADI_INT_RESERVED3               = ADI_INT_PERIPHERAL_ID_VALUE( 24, 16, 16, 16, 19,  0   ),
    ADI_INT_RESERVED4               = ADI_INT_PERIPHERAL_ID_VALUE( 25, 16, 16, 16, 19,  1   ),
    ADI_INT_RESERVED5               = ADI_INT_PERIPHERAL_ID_VALUE( 26, 16, 16, 16, 19,  2   ),
    ADI_INT_RESERVED6               = ADI_INT_PERIPHERAL_ID_VALUE( 27, 16, 16, 16, 19,  3   ),
    ADI_INT_RESERVED7               = ADI_INT_PERIPHERAL_ID_VALUE( 28, 16, 16, 16, 19,  4   ),
    ADI_INT_RESERVED8               = ADI_INT_PERIPHERAL_ID_VALUE( 29, 16, 16, 16, 19,  5   ),
    ADI_INT_RESERVED9               = ADI_INT_PERIPHERAL_ID_VALUE( 30, 16, 16, 16, 19,  6   ),
    ADI_INT_RESERVED10              = ADI_INT_PERIPHERAL_ID_VALUE( 31, 16, 16, 16, 19,  7   )

} ADI_INT_PERIPHERAL_ID;

#endif  /* Brodie Peripheral IDs */


/********************
    Moy
********************/

#if defined(__ADSP_MOY__)     /* peripheral IDs for BF50x */

typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP              = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_PPI_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_SPORT0_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_SPORT1_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_UART0_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_UART1_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_SPI0_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_SPI1_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_CAN_STATUS              = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_RSI0                    = ADI_INT_PERIPHERAL_ID_VALUE( 10,  0,  0,  0,  1,  2   ),
    ADI_INT_RESERVED0               = ADI_INT_PERIPHERAL_ID_VALUE( 11,  0,  0,  0,  1,  3   ),
    ADI_INT_COUNTER0                = ADI_INT_PERIPHERAL_ID_VALUE( 12,  0,  0,  0,  1,  4   ),
    ADI_INT_COUNTER1                = ADI_INT_PERIPHERAL_ID_VALUE( 13,  0,  0,  0,  1,  5   ),
    ADI_INT_DMA0_PPI                = ADI_INT_PERIPHERAL_ID_VALUE( 14,  0,  0,  0,  1,  6   ),
    ADI_INT_DMA1_RSI                = ADI_INT_PERIPHERAL_ID_VALUE( 15,  0,  0,  0,  1,  7   ),
    ADI_INT_DMA2_SPORT0_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 16,  0,  0,  0,  2,  0   ),
    ADI_INT_DMA3_SPORT0_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 17,  0,  0,  0,  2,  1   ),
    ADI_INT_DMA4_SPORT1_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 18,  0,  0,  0,  2,  2   ),
    ADI_INT_DMA5_SPORT1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 19,  0,  0,  0,  2,  3   ),
    ADI_INT_DMA6_SPI0               = ADI_INT_PERIPHERAL_ID_VALUE( 20,  0,  0,  0,  2,  4   ),
    ADI_INT_DMA7_SPI1               = ADI_INT_PERIPHERAL_ID_VALUE( 21,  0,  0,  0,  2,  5   ),
    ADI_INT_DMA8_UART0_RX           = ADI_INT_PERIPHERAL_ID_VALUE( 22,  0,  0,  0,  2,  6   ),
    ADI_INT_DMA9_UART0_TX           = ADI_INT_PERIPHERAL_ID_VALUE( 23,  0,  0,  0,  2,  7   ),
    ADI_INT_DMA10_UART1_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 24,  0,  0,  0,  3,  0   ),
    ADI_INT_DMA11_UART1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 25,  0,  0,  0,  3,  1   ),
    ADI_INT_CAN_RX                  = ADI_INT_PERIPHERAL_ID_VALUE( 26,  0,  0,  0,  3,  2   ),
    ADI_INT_CAN_TX                  = ADI_INT_PERIPHERAL_ID_VALUE( 27,  0,  0,  0,  3,  3   ),
    ADI_INT_TWI                     = ADI_INT_PERIPHERAL_ID_VALUE( 28,  0,  0,  0,  3,  4   ),
    ADI_INT_PORTF_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 29,  0,  0,  0,  3,  5   ),
    ADI_INT_PORTF_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 30,  0,  0,  0,  3,  6   ),
    ADI_INT_RESERVED1               = ADI_INT_PERIPHERAL_ID_VALUE( 31,  0,  0,  0,  3,  7   ),
    /***************************************************************************************\
    |  Moy contains gaps in the register space that are discontiguous:                      |
    |   a 64-byte gap (16 longs) between SIC_ISR0 and SIC_ISR1     (add 16 to offset)       |
    |   a 64-byte gap (16 longs) between SIC_IMASK0 and SIC_IMASK1 (add 16 to offset)       |
    |   a 64-byte gap (16 longs) between SIC_IWR0 and SIC_IWR1     (add 16 to offset)       |
    |   a 52-byte gap (13 longs) between SIC_IAR3 and SIC_IAR4     (add 13 to offset)       |
    \***************************************************************************************/
    ADI_INT_TIMER0                  = ADI_INT_PERIPHERAL_ID_VALUE(  0, 16, 16, 16, 16,  0   ),
    ADI_INT_TIMER1                  = ADI_INT_PERIPHERAL_ID_VALUE(  1, 16, 16, 16, 16,  1   ),
    ADI_INT_TIMER2                  = ADI_INT_PERIPHERAL_ID_VALUE(  2, 16, 16, 16, 16,  2   ),
    ADI_INT_TIMER3                  = ADI_INT_PERIPHERAL_ID_VALUE(  3, 16, 16, 16, 16,  3   ),
    ADI_INT_TIMER4                  = ADI_INT_PERIPHERAL_ID_VALUE(  4, 16, 16, 16, 16,  4   ),
    ADI_INT_TIMER5                  = ADI_INT_PERIPHERAL_ID_VALUE(  5, 16, 16, 16, 16,  5   ),
    ADI_INT_TIMER6                  = ADI_INT_PERIPHERAL_ID_VALUE(  6, 16, 16, 16, 16,  6   ),
    ADI_INT_TIMER7                  = ADI_INT_PERIPHERAL_ID_VALUE(  7, 16, 16, 16, 16,  7   ),
    ADI_INT_PORTG_INTA              = ADI_INT_PERIPHERAL_ID_VALUE(  8, 16, 16, 16, 17,  0   ),
    ADI_INT_PORTG_INTB              = ADI_INT_PERIPHERAL_ID_VALUE(  9, 16, 16, 16, 17,  1   ),
    ADI_INT_MDMA0                   = ADI_INT_PERIPHERAL_ID_VALUE( 10, 16, 16, 16, 17,  2   ),
    ADI_INT_MDMA1                   = ADI_INT_PERIPHERAL_ID_VALUE( 11, 16, 16, 16, 17,  3   ),
    ADI_INT_WATCHDOG                = ADI_INT_PERIPHERAL_ID_VALUE( 12, 16, 16, 16, 17,  4   ),
    ADI_INT_PORTH_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 13, 16, 16, 16, 17,  5   ),
    ADI_INT_PORTH_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 14, 16, 16, 16, 17,  6   ),
    ADI_INT_ACM_STATUS              = ADI_INT_PERIPHERAL_ID_VALUE( 15, 16, 16, 16, 17,  7   ),
    ADI_INT_ACM                     = ADI_INT_PERIPHERAL_ID_VALUE( 16, 16, 16, 16, 18,  0   ),
    ADI_INT_RESERVED2               = ADI_INT_PERIPHERAL_ID_VALUE( 17, 16, 16, 16, 18,  1   ),
    ADI_INT_RESERVED3               = ADI_INT_PERIPHERAL_ID_VALUE( 18, 16, 16, 16, 18,  2   ),
    ADI_INT_PWM0_TRIP               = ADI_INT_PERIPHERAL_ID_VALUE( 19, 16, 16, 16, 18,  3   ),
    ADI_INT_PWM0_SYNC               = ADI_INT_PERIPHERAL_ID_VALUE( 20, 16, 16, 16, 18,  4   ),
    ADI_INT_PWM1_TRIP               = ADI_INT_PERIPHERAL_ID_VALUE( 21, 16, 16, 16, 18,  5   ),
    ADI_INT_PWM1_SYNC               = ADI_INT_PERIPHERAL_ID_VALUE( 22, 16, 16, 16, 18,  6   ),
    ADI_INT_RSI1                    = ADI_INT_PERIPHERAL_ID_VALUE( 23, 16, 16, 16, 18,  7   ),
    ADI_INT_RESERVED4               = ADI_INT_PERIPHERAL_ID_VALUE( 24, 16, 16, 16, 19,  0   ),
    ADI_INT_RESERVED5               = ADI_INT_PERIPHERAL_ID_VALUE( 25, 16, 16, 16, 19,  1   ),
    ADI_INT_RESERVED6               = ADI_INT_PERIPHERAL_ID_VALUE( 26, 16, 16, 16, 19,  2   ),
    ADI_INT_RESERVED7               = ADI_INT_PERIPHERAL_ID_VALUE( 27, 16, 16, 16, 19,  3   ),
    ADI_INT_RESERVED8               = ADI_INT_PERIPHERAL_ID_VALUE( 28, 16, 16, 16, 19,  4   ),
    ADI_INT_RESERVED9               = ADI_INT_PERIPHERAL_ID_VALUE( 29, 16, 16, 16, 19,  5   ),
    ADI_INT_RESERVED10              = ADI_INT_PERIPHERAL_ID_VALUE( 30, 16, 16, 16, 19,  6   ),
    ADI_INT_RESERVED11              = ADI_INT_PERIPHERAL_ID_VALUE( 31, 16, 16, 16, 19,  7   )

} ADI_INT_PERIPHERAL_ID;

#endif  /* Moy Peripheral IDs */

/********************
    Delta
********************/

#if defined(__ADSP_DELTA__)     /* peripheral IDs for BF59x */

typedef enum ADI_INT_PERIPHERAL_ID {    /* IMASK/ISR/IWR bit, SIC_ISRx offset, SIC_IMASKx offset, SIC_IWRx offset, SIC_IARx offset, SIC_IAR nibble */
    ADI_INT_PLL_WAKEUP              = ADI_INT_PERIPHERAL_ID_VALUE(  0,  0,  0,  0,  0,  0   ),
    ADI_INT_DMA_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  1,  0,  0,  0,  0,  1   ),
    ADI_INT_PPI_ERROR               = ADI_INT_PERIPHERAL_ID_VALUE(  2,  0,  0,  0,  0,  2   ),
    ADI_INT_SPORT0_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  3,  0,  0,  0,  0,  3   ),
    ADI_INT_SPORT1_STATUS           = ADI_INT_PERIPHERAL_ID_VALUE(  4,  0,  0,  0,  0,  4   ),
    ADI_INT_SPI0_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  5,  0,  0,  0,  0,  5   ),
    ADI_INT_SPI1_STATUS             = ADI_INT_PERIPHERAL_ID_VALUE(  6,  0,  0,  0,  0,  6   ),
    ADI_INT_UART0_STATUS            = ADI_INT_PERIPHERAL_ID_VALUE(  7,  0,  0,  0,  0,  7   ),
    ADI_INT_DMA0_PPI                = ADI_INT_PERIPHERAL_ID_VALUE(  8,  0,  0,  0,  1,  0   ),
    ADI_INT_DMA1_SPORT0_RX          = ADI_INT_PERIPHERAL_ID_VALUE(  9,  0,  0,  0,  1,  1   ),
    ADI_INT_DMA2_SPORT0_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 10,  0,  0,  0,  1,  2   ),
    ADI_INT_DMA3_SPORT1_RX          = ADI_INT_PERIPHERAL_ID_VALUE( 11,  0,  0,  0,  1,  3   ),
    ADI_INT_DMA4_SPORT1_TX          = ADI_INT_PERIPHERAL_ID_VALUE( 12,  0,  0,  0,  1,  4   ),
    ADI_INT_DMA5_SPI0               = ADI_INT_PERIPHERAL_ID_VALUE( 13,  0,  0,  0,  1,  5   ),
    ADI_INT_DMA6_SPI1               = ADI_INT_PERIPHERAL_ID_VALUE( 14,  0,  0,  0,  1,  6   ),
    ADI_INT_DMA7_UART0_RX           = ADI_INT_PERIPHERAL_ID_VALUE( 15,  0,  0,  0,  1,  7   ),
    ADI_INT_DMA8_UART0_TX           = ADI_INT_PERIPHERAL_ID_VALUE( 16,  0,  0,  0,  2,  0   ),
    ADI_INT_PORTF_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 17,  0,  0,  0,  2,  1   ),
    ADI_INT_PORTF_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 18,  0,  0,  0,  2,  2   ),
    ADI_INT_TIMER0                  = ADI_INT_PERIPHERAL_ID_VALUE( 19,  0,  0,  0,  2,  3   ),
    ADI_INT_TIMER1                  = ADI_INT_PERIPHERAL_ID_VALUE( 20,  0,  0,  0,  2,  4   ),
    ADI_INT_TIMER2                  = ADI_INT_PERIPHERAL_ID_VALUE( 21,  0,  0,  0,  2,  5   ),
    ADI_INT_PORTG_INTA              = ADI_INT_PERIPHERAL_ID_VALUE( 22,  0,  0,  0,  2,  6   ),
    ADI_INT_PORTG_INTB              = ADI_INT_PERIPHERAL_ID_VALUE( 23,  0,  0,  0,  2,  7   ),
    ADI_INT_TWI                     = ADI_INT_PERIPHERAL_ID_VALUE( 24,  0,  0,  0,  3,  0   ),
    ADI_INT_RESERVED0               = ADI_INT_PERIPHERAL_ID_VALUE( 25,  0,  0,  0,  3,  1   ),
    ADI_INT_RESERVED1               = ADI_INT_PERIPHERAL_ID_VALUE( 26,  0,  0,  0,  3,  2   ),
    ADI_INT_RESERVED2               = ADI_INT_PERIPHERAL_ID_VALUE( 27,  0,  0,  0,  3,  3   ),
    ADI_INT_RESERVED3               = ADI_INT_PERIPHERAL_ID_VALUE( 28,  0,  0,  0,  3,  4   ),
    ADI_INT_MDMA0                   = ADI_INT_PERIPHERAL_ID_VALUE( 29,  0,  0,  0,  3,  5   ),
    ADI_INT_MDMA1                   = ADI_INT_PERIPHERAL_ID_VALUE( 30,  0,  0,  0,  3,  6   ),
    ADI_INT_WATCHDOG                = ADI_INT_PERIPHERAL_ID_VALUE( 31,  0,  0,  0,  3,  7   )

} ADI_INT_PERIPHERAL_ID;

#endif  /* Delta Peripheral IDs */


/*********************************************************************

Enumerations for defining the details of the library being used.

*********************************************************************/

typedef enum ADI_INT_LIBRARY_PROC {                 /* Processor */
    ADI_INT_LIBRARY_PROC_UNKNOWN=0,
    ADI_INT_LIBRARY_PROC_BF512,
    ADI_INT_LIBRARY_PROC_BF526,
    ADI_INT_LIBRARY_PROC_BF527,
    ADI_INT_LIBRARY_PROC_BF533,
    ADI_INT_LIBRARY_PROC_BF537,
    ADI_INT_LIBRARY_PROC_BF538,
    ADI_INT_LIBRARY_PROC_BF548,
    ADI_INT_LIBRARY_PROC_BF561,
    ADI_INT_LIBRARY_PROC_BF506F,
    ADI_INT_LIBRARY_PROC_BF592
} ADI_INT_LIBRARY_PROC;

typedef enum ADI_INT_LIBRARY_CONFIG {               /* Debug vs Release library */
    ADI_INT_LIBRARY_CONFIG_UNKNOWN=0,
    ADI_INT_LIBRARY_CONFIG_DEBUG,
    ADI_INT_LIBRARY_CONFIG_RELEASE
} ADI_INT_LIBRARY_CONFIG;

typedef enum ADI_INT_LIBRARY_WRKRNDS {              /* Chip workarounds for anomalies ("y" in the library name) */
    ADI_INT_LIBRARY_WRKRNDS_UNKNOWN=0,
    ADI_INT_LIBRARY_WRKRNDS_ENABLED,
    ADI_INT_LIBRARY_WRKRNDS_DISABLED
} ADI_INT_LIBRARY_WRKRNDS;

typedef enum ADI_INT_LIBRARY_OS {                   /* Stand-alone vs VDK (and other options in the future) */
    ADI_INT_LIBRARY_OS_UNKNOWN=0,
    ADI_INT_LIBRARY_OS_STANDALONE,
    ADI_INT_LIBRARY_OS_VDK,
    ADI_INT_LIBRARY_OS_UCOS
} ADI_INT_LIBRARY_OS;

#define ADI_INT_LIBRARY_CHIP_REV_NONE   0x7F        /* This is for unknown chip revisions */
#define ADI_INT_LIBRARY_CHIP_REV_AUTO   0x7E        /* This is for "auto" projects which automatically detect chip rev */

typedef struct ADI_INT_LIBRARY_DETAILS {
    enum ADI_INT_LIBRARY_PROC       Processor;
    enum ADI_INT_LIBRARY_CONFIG     Config;
    enum ADI_INT_LIBRARY_WRKRNDS    Workarounds;
    enum ADI_INT_LIBRARY_OS         Os;
    u8                              ChipRev;        /* This is a number representing the chip version of the processor */
} ADI_INT_LIBRARY_DETAILS;

/* structure to save/restore wakeup registers when globally disabling wakeups */
/* Not all fields are used on all processors. */

typedef struct ADI_INT_WAKEUP_REGISTER
{

    u32 RegIWR0;

/* these two only have one wakeup register */
#if !( defined(__ADSP_EDINBURGH__) || defined(__ADSP_BRAEMAR__) )
    u32 RegIWR1;
#endif

/* Moab has three */
#if defined(__ADSP_MOAB__)
    u32 RegIWR2;
#endif

} ADI_INT_WAKEUP_REGISTER, *pADI_INT_WAKEUP_REGISTER;

/*********************************************************************

API function prototypes

*********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

ADI_INT_RESULT adi_int_Init(        /* Initializes the interrupt manager */
    void            *pMemory,           /* pointer to memory */
    const size_t    MemorySize,         /* size of the memory (in bytes) */
    u32             *pMaxEntries,       /* number of secondary handlers supported */
    void            *pEnterCriticalArg  /* parameter for enter critical region */
);

ADI_INT_RESULT adi_int_Terminate(   /* Terminates the interrupt manager */
    void
);

ADI_INT_RESULT adi_int_CECHook(     /* Hooks the given interrupt handler into the handler chain */
    u32                 IVG,            /* IVG level to hook into */
    ADI_INT_HANDLER_FN  Handler,        /* handler function address */
    void                *ClientArg,     /* client argument supplied to handler */
    u32                 NestingFlag     /* nesting enable flag (TRUE/FALSE) */
);

ADI_INT_RESULT adi_int_CECUnhook(   /* Unhooks the given interrupt handler from the handler chain */
    u32                 IVG,            /* IVG level to unhook from */
    ADI_INT_HANDLER_FN  Handler,        /* handler function address */
    void                *ClientArg      /* client argument supplied to handler */
);



ADI_INT_RESULT adi_int_SICEnable(               /* Enables a SIC interrupt to be passed to the CEC */
    const ADI_INT_PERIPHERAL_ID PeripheralID        /* peripheral ID */
);

ADI_INT_RESULT adi_int_SICDisable(              /* Disables a SIC interrupt from being passed to the CEC */
    const ADI_INT_PERIPHERAL_ID PeripheralID        /* peripheral ID */
);

ADI_INT_RESULT adi_int_SICSetIVG(               /* Sets the IVG number a peripheral is mapped to */
    const ADI_INT_PERIPHERAL_ID PeripheralID,       /* peripheral ID */
    const u32                   IVG                 /* IVG number to which the peripheral will be mapped */
);

ADI_INT_RESULT adi_int_SICGetIVG(               /* Gets the IVG number a peripheral is mapped to */
    const ADI_INT_PERIPHERAL_ID PeripheralID,       /* peripheral ID */
    u32                         *pIVG               /* address to store the IVG number into */
);

ADI_INT_RESULT adi_int_SICWakeup(               /* Enables/disables a SIC interrupt from waking up the core */
    const ADI_INT_PERIPHERAL_ID PeripheralID,       /* peripheral ID */
    u32                         WakeupFlag          /* wakeup enable flag (TRUE/FALSE) */
);

ADI_INT_RESULT adi_int_SICInterruptAsserted(    /* Determines if peripheral is asserting an interrupt */
    const ADI_INT_PERIPHERAL_ID PeripheralID        /* peripheral ID */
);

ADI_INT_RESULT adi_int_GetLibraryDetails(
    ADI_INT_LIBRARY_DETAILS *pLibraryDetails    /* Pointer to structure containing fields for info about this library */
);

ADI_INT_RESULT adi_int_GetCurrentIVGLevel(      /* Senses the current IVG level */
    u32 *pIVG                                 /* location where the current IVG level is stored */
);

ADI_INT_RESULT adi_int_SICGlobalWakeup(             /* Enables/disables all SIC interrupts from waking up the core */
    u32                         WakeupFlag,          /* wakeup enable flag (TRUE/FALSE) */
    pADI_INT_WAKEUP_REGISTER    SaveIWR
);

/*********************************************************************

API functions that are operating environment dependent.  Though the
functionality of these routines is consistent across operating environments,
these functions may have different implementation depending on the
specific operating environment such as standalone, VDK, other RTOS etc.

*********************************************************************/

void *adi_int_EnterCriticalRegion(  /* protects a critical region of code */
    void *pArg                          /* pointer to enter critical data */
);

void adi_int_ExitCriticalRegion(    /* unprotects a critical region of code */
    void *pArg                          /* pointer to exit critical data */
);

void adi_int_SetIMaskBits(          /* sets bits in the IMASK register */
    ADI_INT_IMASK BitsToSet             /* bits to set */
);

void adi_int_ClearIMaskBits(        /* clears bits in the IMASK register */
    ADI_INT_IMASK BitsToClear           /* bits to clear */
);


#ifdef __cplusplus
}
#endif


/********************************************************************************/
#endif /* end of C/C++ section */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_INT_H__ */
