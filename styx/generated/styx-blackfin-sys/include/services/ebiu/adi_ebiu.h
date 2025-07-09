/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ebiu.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            EBIU Management Header File

*********************************************************************************/

#ifndef __ADI_EBIU_H__
#define __ADI_EBIU_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <services/services.h>


/* if the current processor supports DDR memory */
#if defined(__ADSP_MOAB__)
/* then define this directive */
#define __ADI_EBIU_USE_DDR_MEMORY__
#endif


#define ADI_EBIU_SDRAM_MODULE_ID_VALUE(MODULE,ROWS,COLUMN_ADDRESS_WIDTH,SPEED_GRADE) \
    (                                 \
        (SPEED_GRADE) << 0          | \
        (COLUMN_ADDRESS_WIDTH) << 3 | \
        (ROWS) <<5                  | \
        (MODULE) << 16                \
    )

#if !defined(_LANGUAGE_ASM)




/********************************************************************************
* Asynch Hold Time - if specified in cycles
*********************************************************************************/
typedef enum ADI_EBIU_ASYNCH_HOLD_TIME {

    ADI_EBIU_ASYNCH_HT_0_CYCLES,
    ADI_EBIU_ASYNCH_HT_1_CYCLES,
    ADI_EBIU_ASYNCH_HT_2_CYCLES,
    ADI_EBIU_ASYNCH_HT_3_CYCLES
} ADI_EBIU_ASYNCH_HOLD_TIME;


/********************************************************************************
* Asynch Setup Time - if specified in cycles
*********************************************************************************/
typedef enum ADI_EBIU_ASYNCH_SETUP_TIME {

    ADI_EBIU_ASYNCH_ST_4_CYCLES,
    ADI_EBIU_ASYNCH_ST_1_CYCLES,
    ADI_EBIU_ASYNCH_ST_2_CYCLES,
    ADI_EBIU_ASYNCH_ST_3_CYCLES
} ADI_EBIU_ASYNCH_SETUP_TIME;

/********************************************************************************
* Asynch Transition Time - if specified in cycles
*********************************************************************************/
typedef enum ADI_EBIU_ASYNCH_TRANSITION_TIME {

    ADI_EBIU_ASYNCH_TT_4_CYCLES,
    ADI_EBIU_ASYNCH_TT_1_CYCLES,
    ADI_EBIU_ASYNCH_TT_2_CYCLES,
    ADI_EBIU_ASYNCH_TT_3_CYCLES
} ADI_EBIU_ASYNCH_TRANSITION_TIME;



/************  if this is not one of the processors which use DDR memory ********/
#if !defined (__ADI_EBIU_USE_DDR_MEMORY__)


/********************************************************************************
* EBIU Module result codes
*********************************************************************************/
typedef enum ADI_EBIU_RESULT {
    ADI_EBIU_RESULT_SUCCESS = 0,                        // Successfull completion
    ADI_EBIU_RESULT_FAILED = 1,                         // Generic failure

    ADI_EBIU_RESULT_START=ADI_EBIU_ENUMERATION_START,

    ADI_EBIU_RESULT_BAD_COMMAND,                        // Invalid ADI_EBIU_RESULT_COMMAND Command value
    ADI_EBIU_RESULT_NOT_INITIALIZED,                    // EBIU service not initialized
    ADI_EBIU_RESULT_INVALID_SDRAM_EBE,                  // Invalid ADI_EBIU_RESULT_SDRAM_ENABLE value
    ADI_EBIU_RESULT_INVALID_SDRAM_BANK_SIZE,            // Invalid ADI_EBIU_RESULT_SDRAM_BANK_SIZE value
    ADI_EBIU_RESULT_INVALID_SDRAM_COL_WIDTH,            // Invalid ADI_EBIU_RESULT_SDRAM_BANK_COL_WIDTH value
    ADI_EBIU_RESULT_INVALID_SDRAM_CDDBG,                // Invalid ADI_EBIU_RESULT_SDRAM_CDDBG value
    ADI_EBIU_RESULT_INVALID_SDRAM_EBUFE,                // Invalid ADI_EBIU_RESULT_SDRAM_EBUFE value
    ADI_EBIU_RESULT_INVALID_SDRAM_EMREN,                // Invalid ADI_EBIU_RESULT_SDRAM_EMREN value
    ADI_EBIU_RESULT_INVALID_SDRAM_FBBRW,                // Invalid ADI_EBIU_RESULT_SDRAM_FBBRW value
    ADI_EBIU_RESULT_INVALID_SDRAM_PASR,                 // Invalid ADI_EBIU_RESULT_SDRAM_PASR value
    ADI_EBIU_RESULT_INVALID_SDRAM_PSM,                  // Invalid ADI_EBIU_RESULT_SDRAM_PSM value
    ADI_EBIU_RESULT_INVALID_SDRAM_PUPSD,                // Invalid ADI_EBIU_RESULT_SDRAM_PUPSD value
    ADI_EBIU_RESULT_INVALID_SDRAM_SRFS,                 // Invalid ADI_EBIU_RESULT_SDRAM_SRFS value
    ADI_EBIU_RESULT_INVALID_SDRAM_TCSR,                 // Invalid ADI_EBIU_RESULT_SDRAM_TCRS value
    ADI_EBIU_RESULT_INVALID_SDRAM_TWRMIN,                       // Invalid value for TWRMIN - would cause TWR>3
    ADI_EBIU_RESULT_NO_MEMORY,                          // Insufficient memory to load/save configuration
    ADI_EBIU_RESULT_INVALID_EZKIT,                      // Invalid EZKIT revision number
    ADI_EBIU_RESULT_INVALID_SDRAM_SCTLE,                // invalid SCTLE value
    ADI_EBIU_RESULT_INVALID_SDRAM_MODULE,               // invalid SDRAM module type
#if defined(__ADSP_TETON__)
      ADI_EBIU_RESULT_INVALID_IVG,                      // Invalid IVG level for supplemental interrupt
    ADI_EBIU_RESULT_INVALID_SDRAM_BANK,                 // Invalid bank number given
    ADI_EBIU_RESULT_INVALID_SDRAM_SCK1E,                // Invalide SCK1E value
#endif
    ADI_EBIU_RESULT_ALREADY_INITIALIZED,                // EBIU service already initialized


/* Asynch memory controller result codes  */

    ADI_EBIU_RESULT_INVALID_ASYNCH_CLKOUT_ENABLE,            /* invalid clock out enable/disable choice                          */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ENABLE,              /* invalid bank enable/disable choice                               */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_NUMBER,              /* invalid bank number specified in command argument                */


#if defined(__ADSP_TETON__)
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_16_BIT_PACKING_ENABLE, /* invalid data packing selection                                 */
#endif

    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_TRANSITION_TIME,     /* invalid transition time (used to avoid bus contention)           */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_READ_ACCESS_TIME,    /* invalid read access time - R-enable assertion to de-assertion    */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_WRITE_ACCESS_TIME,   /* invalid write access time W-enable assertion to de-assertion     */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_SETUP_TIME,          /* invalid setup time - start of memory cycle to R/W-enable         */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_HOLD_TIME,           /* invalid hold time - R/W-enable de-assertion to end of memory cycle */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ARDY_ENABLE,         /* invalid ARDY enable/disable - used to insert extra wait states   */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ARDY_POLARITY,       /* invalid ARDY sample polarity - low or high                       */

    /***********  obsoleted enumerations ***********/
    ADI_EBIU_RESULT_CALL_IGNORED = ADI_EBIU_RESULT_NOT_INITIALIZED      // obsoleted


} ADI_EBIU_RESULT;



/********************************************************************************
* EBIU Module Command codes
*********************************************************************************/
typedef enum ADI_EBIU_COMMAND {
    ADI_EBIU_CMD_START=ADI_EBIU_ENUMERATION_START,

    ADI_EBIU_CMD_END,                           // end of table
    ADI_EBIU_CMD_PAIR,                          // command pair follows
    ADI_EBIU_CMD_TABLE,                         // command table follows
    ADI_EBIU_CMD_SET_EZKIT,                     // set details as per given EZKIT board
    ADI_EBIU_CMD_SET_SDRAM_ENABLE,              // set EBIU_SDBCTL::EBE field
    ADI_EBIU_CMD_SET_SDRAM_BANK_SIZE,           // set EBIU_SDBCTL::EBSZ field
    ADI_EBIU_CMD_SET_SDRAM_BANK_COL_WIDTH,      // set EBIU_SDBCTL::EBCAW field
    ADI_EBIU_CMD_SET_SDRAM_PASR,                // set EBIU_SDGCTL::PASR field
    ADI_EBIU_CMD_SET_SDRAM_EBUFE,               // set EBIU_SDGCTL::EBUFE field
    ADI_EBIU_CMD_SET_SDRAM_PUPSD,               // set EBIU_SDGCTL::PUPSD field
    ADI_EBIU_CMD_SET_SDRAM_PSM,                 // set EBIU_SDGCTL::PSM field
    ADI_EBIU_CMD_SET_SDRAM_SCTLE,               // sets the SCTLE bit to enable/disable CLKOUT, SRAS, SCAS, SDQM[1:0]
    ADI_EBIU_CMD_SET_SDRAM_FBBRW,               // set EBIU_SDGCTL::FBBRW field
    ADI_EBIU_CMD_SET_SDRAM_CDDBG,               // set EBIU_SDGCTL::CDDBG field
    ADI_EBIU_CMD_SET_SDRAM_SRFS,                // set EBIU_SDGCTL::SRFS field (set SDRAM in self refresh mode)
    ADI_EBIU_CMD_SET_SDRAM_EMREN,               // set EBIU_SDGCTL::EMREN field (using low-power SDRAM)
    ADI_EBIU_CMD_SET_SDRAM_TCSR,                // set EBIU_SDGCTL::TCSR field
    ADI_EBIU_CMD_SET_SDRAM_CL_THRESHOLD,        // set CAS latency threshold as per SDRAM datasheet
    ADI_EBIU_CMD_SET_SDRAM_TRASMIN,             // set min TRAS value as per SDRAM datasheet
    ADI_EBIU_CMD_SET_SDRAM_TRPMIN,              // set min TRP value as per SDRAM datasheet
    ADI_EBIU_CMD_SET_SDRAM_TRCDMIN,             // set min TRCD value as per SDRAM datasheet
    ADI_EBIU_CMD_SET_SDRAM_TWRMIN,              // set min TWR value as per SDRAM datasheet
    ADI_EBIU_CMD_SET_SDRAM_REFRESH,             // set REFRESH period value as per SDRAM datasheet
    ADI_EBIU_CMD_SET_SDGCTL_REG,                // set whole EBIU_SDGCTL word
    ADI_EBIU_CMD_SET_SDBCTL_REG,                // set whole EBIU_SDBCTL word
    ADI_EBIU_CMD_SET_CRITICAL_REGION_DATA,      // sets the data location for critical region data to be stored (eg IMASK)
    ADI_EBIU_CMD_SET_SDRAM_MODULE,              // sets the timings etc for a given (Micron) SDRAM module
    ADI_EBIU_CMD_SET_FREQ_AS_MHZ,               // = 1 if CCLK & SCLK are expressed in MHz throughout, =1000000 if as Hz (default)
#if defined(__ADSP_TETON__) && !defined(ADI_SSL_SINGLE_CORE)
    ADI_EBIU_CMD_SET_COREB_SUPP_INT0_IVG=(ADI_EBIU_ENUMERATION_START+40),    // set bCore B Supplemental interrupt level
    ADI_EBIU_CMD_SET_AUTO_SYNC_ENABLED,         // enable core synchronisation within module.
    ADI_EBIU_CMD_SET_SYNC_LOCK_VARIABLE,        // Sets the lock variable pointer
    ADI_EBIU_CMD_SET_SDRAM_SCK1E,               // Sets the EBIU_SDGCTL::SCK1E field
#endif

    /*  Asynch memory controller commands  */

    ADI_EBIU_CMD_SET_ASYNCH_AMGCTL,                 /* set the global asynch control register            */
    ADI_EBIU_CMD_SET_ASYNCH_AMBCTL0,                /* set the asynch bank control register 0     */
    ADI_EBIU_CMD_SET_ASYNCH_AMBCTL1,                /* set the asynch bank control register 1     */
    ADI_EBIU_CMD_SET_ASYNCH_CLKOUT_ENABLE,          /* for external memory devices that need clock input */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_ENABLE,            /* individual bank enable/disable */

#if defined(__ADSP_TETON__)
    ADI_EBIU_CMD_SET_ASYNCH_BANK_16_BIT_PACKING_ENABLE,
#endif

    ADI_EBIU_CMD_SET_ASYNCH_BANK_TRANSITION_TIME,   /* optimized to avoid bus contention */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_READ_ACCESS_TIME,  /* R-enable assertion to de-assertion */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_WRITE_ACCESS_TIME, /* W-enable assertion to de-assertion */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_SETUP_TIME,        /* beginning of memory cycle to R/W-enable */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_HOLD_TIME,         /* R/W-enable de-assertion  to end of memory cycle */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_ARDY_ENABLE,       /* used to insert extra wait states */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_ARDY_POLARITY      /* ARDY sampled low or high */


} ADI_EBIU_COMMAND;



/*********************************************************************************
*
*               valid EBIU_SDBCTL field values and defaults
*
*********************************************************************************
*********************************************************************************/

/********************************************************************************
* EBE
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_ENABLE {
    ADI_EBIU_SDRAM_EBE_DISABLE=0,
    ADI_EBIU_SDRAM_EBE_ENABLE
} ADI_EBIU_SDRAM_ENABLE;

/********************************************************************************
* EBSZ
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_BANK_SIZE
{
    ADI_EBIU_SDRAM_BANK_16MB,
    ADI_EBIU_SDRAM_BANK_32MB,
    ADI_EBIU_SDRAM_BANK_64MB,
    ADI_EBIU_SDRAM_BANK_128MB,
    ADI_EBIU_SDRAM_BANK_256MB,
    ADI_EBIU_SDRAM_BANK_512MB
} ADI_EBIU_SDRAM_BANK_SIZE;

/********************************************************************************
* EBCAW
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_BANK_COL_WIDTH
{
    ADI_EBIU_SDRAM_BANK_COL_8BIT,
    ADI_EBIU_SDRAM_BANK_COL_9BIT,
    ADI_EBIU_SDRAM_BANK_COL_10BIT,
    ADI_EBIU_SDRAM_BANK_COL_11BIT
} ADI_EBIU_SDRAM_BANK_COL_WIDTH;

/*********************************************************************************
* Memory Module Definitions (Micron parts)
*
* The 32 bit enum is made up of 3 fields:
* 0:2   - Speed Grade identifier
* 3:4   - Column Address Width (CAW)
* 16:31 - Unique identifier in enumerator
*
*********************************************************************************/

typedef enum ADI_EBIU_SDRAM_MODULE_SPEED_GRADE {
    ADI_EBIU_SDRAM_MODULE_6,
    ADI_EBIU_SDRAM_MODULE_6A,
    ADI_EBIU_SDRAM_MODULE_7E,
    ADI_EBIU_SDRAM_MODULE_75,
    ADI_EBIU_SDRAM_MODULE_8E
} ADI_EBIU_SDRAM_MODULE_SPEED_GRADE;

typedef enum ADI_EBIU_SDRAM_REFRESH_CYCLES {
    ADI_EBIU_SDRAM_REFRESH_CYCLES_4K,
    ADI_EBIU_SDRAM_REFRESH_CYCLES_8K
} ADI_EBIU_SDRAM_REFRESH_CYCLES;

#if 0
#define ADI_EBIU_SDRAM_MODULE_ID_VALUE(MODULE,ROWS,COLUMN_ADDRESS_WIDTH,SPEED_GRADE) \
    (                                 \
        (SPEED_GRADE) << 0          | \
        (COLUMN_ADDRESS_WIDTH) << 3 | \
        (ROWS) <<5                  | \
        (MODULE) << 16                \
    )
#endif
#define ADI_EBIU_SDRAM_GET_CAW(MODULE_ID)            (ADI_EBIU_SDRAM_BANK_COL_WIDTH)(((MODULE_ID) >> 3)  & 0x00000003)
#define ADI_EBIU_SDRAM_GET_REFRESH_CYCLES(MODULE_ID) (ADI_EBIU_SDRAM_REFRESH_CYCLES)(((MODULE_ID) >> 5)  & 0x00000001)
#define ADI_EBIU_SDRAM_GET_SPEED_GRADE(MODULE_ID)    (ADI_EBIU_SDRAM_MODULE_SPEED_GRADE)(((MODULE_ID) >> 0)  & 0x00000007)

typedef enum ADI_EBIU_SDRAM_MODULE_TYPE {

    // 8MB (64Mb) modules
    ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_6    = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  0, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_6  ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_6     = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  1, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_6  ),
    ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_6    = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  2, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_6  ),

    ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  3, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_7E    = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  4, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  5, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_7E ),

    ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  6, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_75    = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  7, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  8, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_75 ),

    ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_8E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE(  9, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_8E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_8E    = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 10, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_8E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_8E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 11, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_8E ),

    // 16MB (128Mb), modules
    ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_6A   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 12, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_6A ),
    ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_6A   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 13, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_6A ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_6A   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 14, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_6A ),

    ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 15, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 16, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 17, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_7E ),

    ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 18, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 19, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 20, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_75 ),

    ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_8E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 21, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_8E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_8E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 22, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_8E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_8E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 23, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_8E ),

    // 32MB (256Mb), modules
    ADI_EBIU_SDRAM_MODULE_MT48LC64M4A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 24, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC32M8A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 25, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC16M16A2_7E  = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 26, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_7E ),

    ADI_EBIU_SDRAM_MODULE_MT48LC64M4A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 27, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC32M8A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 28, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC16M16A2_75  = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 29, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_75 ),

    // 64MB (512Mb), modules
    ADI_EBIU_SDRAM_MODULE_MT48LC64M8A2_7E   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 30, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_7E ),
    ADI_EBIU_SDRAM_MODULE_MT48LC32M16A2_7E  = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 31, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E ),

    ADI_EBIU_SDRAM_MODULE_MT48LC64M8A2_75   = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 32, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_75 ),
    ADI_EBIU_SDRAM_MODULE_MT48LC32M16A2_75  = ADI_EBIU_SDRAM_MODULE_ID_VALUE( 33, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 )
} ADI_EBIU_SDRAM_MODULE_TYPE;


/********************************************************************************
* Structure to contain details defining a bank size or column width value with an
* associated bank number.
*********************************************************************************/

typedef struct ADI_EBIU_SDRAM_BANK_VALUE {
    u32 bankno;
    union {
        ADI_EBIU_SDRAM_BANK_SIZE      size;
        ADI_EBIU_SDRAM_BANK_COL_WIDTH width;
    } value;
} ADI_EBIU_SDRAM_BANK_VALUE;



/********************************************************************************
*********************************************************************************
*
*              valid EBIU_SDGCTL field values and defaults
*
*********************************************************************************
*********************************************************************************/

/********************************************************************************
* SCTLE
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_SCTLE {
    ADI_EBIU_SDRAM_SCTLE_DISABLE,
    ADI_EBIU_SDRAM_SCTLE_ENABLE
} ADI_EBIU_SDRAM_SCTLE;

#if defined(__ADSP_TETON__)
/********************************************************************************
* SCK1E
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_SCK1E {
    ADI_EBIU_SDRAM_SCK1E_DISABLE,
    ADI_EBIU_SDRAM_SCK1E_ENABLE
} ADI_EBIU_SDRAM_SCK1E;
#endif

/********************************************************************************
* EMREN
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_EMREN {
    ADI_EBIU_SDRAM_EMREN_DISABLE,
    ADI_EBIU_SDRAM_EMREN_ENABLE
} ADI_EBIU_SDRAM_EMREN;

/********************************************************************************
* SRFS
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_SRFS {
    ADI_EBIU_SDRAM_SRFS_DISABLE=0,
    ADI_EBIU_SDRAM_SRFS_ENABLE
} ADI_EBIU_SDRAM_SRFS;

/********************************************************************************
* EBUFE
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_EBUFE {
    ADI_EBIU_SDRAM_EBUFE_DISABLE=0,
    ADI_EBIU_SDRAM_EBUFE_ENABLE
} ADI_EBIU_SDRAM_EBUFE;

/********************************************************************************
* PUPSD
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_PUPSD {
    ADI_EBIU_SDRAM_PUPSD_NODELAY=0,
    ADI_EBIU_SDRAM_PUPSD_15CYCLES
} ADI_EBIU_SDRAM_PUPSD;

/********************************************************************************
* PSM
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_PSM {
    ADI_EBIU_SDRAM_PSM_REFRESH_FIRST=0,
    ADI_EBIU_SDRAM_PSM_REFRESH_LAST
} ADI_EBIU_SDRAM_PSM;

/********************************************************************************
* PASR
*********************************************************************************/
typedef enum ADI_EBIU_PASR {
    ADI_EBIU_PASR_ALL=0,
    ADI_EBIU_PASR_INT01,
    ADI_EBIU_PASR_INT0_ONLY
} ADI_EBIU_PASR;

/********************************************************************************
* FBBRW
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_FBBRW {
    ADI_EBIU_SDRAM_FBBRW_DISABLE=0,
    ADI_EBIU_SDRAM_FBBRW_ENABLE
} ADI_EBIU_SDRAM_FBBRW;

/********************************************************************************
* TCSR
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_TCSR {
    ADI_EBIU_SDRAM_TCSR_45DEG=0,
    ADI_EBIU_SDRAM_TCSR_85DEG
} ADI_EBIU_SDRAM_TCSR;

/********************************************************************************
* CDDBG
*********************************************************************************/
typedef enum ADI_EBIU_SDRAM_CDDBG {
    ADI_EBIU_SDRAM_CDDBG_DISABLE=0,
    ADI_EBIU_SDRAM_CDDBG_ENABLE
} ADI_EBIU_SDRAM_CDDBG;

/*********************************************************************************
* EZ-KIT revisions
* NOTE: Moab and Kookaburra/Mockingbird/Brodie do not define the EZ-Kit shortcut commands
*********************************************************************************/
#if defined(__ADSP_EDINBURGH__)

typedef enum ADI_EBIU_EZKIT {
    ADI_EBIU_EZKIT_BF533=0,
    ADI_EBIU_EZKIT_BF533_REV1_7
} ADI_EBIU_EZKIT;

#endif

#if defined(__ADSP_BRAEMAR__)

typedef enum ADI_EBIU_EZKIT {
    ADI_EBIU_EZKIT_BF537=0
} ADI_EBIU_EZKIT;

#endif

#if defined(__ADSP_TETON__)

typedef enum ADI_EBIU_EZKIT {
    ADI_EBIU_EZKIT_BF561=0
} ADI_EBIU_EZKIT;

#endif

#if defined(__ADSP_STIRLING__)

typedef enum ADI_EBIU_EZKIT {
    ADI_EBIU_EZKIT_BF538=0,
    ADI_EBIU_EZKIT_BF538_REV1_0
} ADI_EBIU_EZKIT;

#endif


/********************************************************************************
* Default values for SDRAM timings - (-75 SDRAM)
*********************************************************************************/
#define ADI_EBIU_SDRAM_CL_THRESHOLD_DEFAULT 100  // MHz
#define ADI_EBIU_SDRAM_TRASMIN_DEFAULT      (44, ADI_EBIU_TIMING_UNIT_NANOSEC)
#define ADI_EBIU_SDRAM_TRPMIN_DEFAULT       (20, ADI_EBIU_TIMING_UNIT_NANOSEC)
#define ADI_EBIU_SDRAM_TRCDMIN_DEFAULT      (20, ADI_EBIU_TIMING_UNIT_NANOSEC)
#define ADI_EBIU_SDRAM_TWRMIN_DEFAULT       (1 /* SCLK cycle  + */ , 7500 ,ADI_EBIU_TIMING_UNIT_PICOSEC /* 7.5 ns */)
#define ADI_EBIU_SDRAM_REFRESH_DEFAULT      (8192 /* Cycles in */, 64, ADI_EBIU_TIMING_UNIT_MILLISEC /* 64 ms */)


/********************************************************************************
 ************* this section for EBIU which supports DDR *************************
 ********************************************************************************/
#else


/********************************************************************************
* EBIU Module result codes
*********************************************************************************/
typedef enum ADI_EBIU_RESULT {

    ADI_EBIU_RESULT_SUCCESS = 0,                           /* Successfull completion                  */
    ADI_EBIU_RESULT_FAILED = 1,                            /* generic failure                         */
    ADI_EBIU_RESULT_START=ADI_EBIU_ENUMERATION_START,      /* start of non-generic result codes       */
    ADI_EBIU_RESULT_BAD_COMMAND,                           /* Invalid 'ADI_EBIU_'  Command value      */
    ADI_EBIU_RESULT_NOT_INITIALIZED,                       /* ebiu module not initialized             */

    /* DDR memory related Result codes */
    ADI_EBIU_RESULT_INVALID_DDR_MODULE,                    /* invalid SDRAM module type               */
    ADI_EBIU_RESULT_INVALID_DDR_REFI,                      /* invalid refresh interval                */
    ADI_EBIU_RESULT_INVALID_DDR_RFC,                       /* invalid auto refresh command            */
    ADI_EBIU_RESULT_INVALID_DDR_RP,                        /* invalid precharge to active interval    */
    ADI_EBIU_RESULT_INVALID_DDR_RAS,                       /* invalid active to precharge interval    */
    ADI_EBIU_RESULT_INVALID_DDR_RC,                        /* invalid active to active interval       */
    ADI_EBIU_RESULT_INVALID_DDR_WTR,                       /* invalid write to read interval          */
    ADI_EBIU_RESULT_INVALID_DDR_DEVICE_SIZE,               /* invalid  device size                    */
    ADI_EBIU_RESULT_INVALID_DDR_DEVICE_WIDTH,              /* invalid device width                    */
    ADI_EBIU_RESULT_INVALID_DDR_EXTERNAL_BANKS,            /* invalid number of external banks        */
    ADI_EBIU_RESULT_INVALID_DDR_DATA_WIDTH,                /* invalid data width                      */
    ADI_EBIU_RESULT_INVALID_DDR_WR,                        /* invalid write recovery time             */
    ADI_EBIU_RESULT_INVALID_DDR_MRD,                       /* invalid mode reg set to active interval */
    ADI_EBIU_RESULT_INVALID_DDR_RCD,                       /* invalid active to r/w interval          */
    ADI_EBIU_RESULT_INVALID_DDR_CAS,                       /* invalid cycles from R/W to valid data)  */
    ADI_EBIU_RESULT_INVALID_DDR_PASR,                      /* invalid partial array self-refresh      */
    ADI_EBIU_RESULT_INVALID_DDR_SOFT_RESET,                /* invalid soft reset selection            */
    ADI_EBIU_RESULT_INVALID_DDR_SELF_REFRESH_REQUEST,      /* invalid self refresh request            */
    ADI_EBIU_RESULT_INVALID_DDR_MOBILE_ENABLE,             /* invalid mobile DDR enable request       */

    ADI_EBIU_RESULT_ALREADY_INITIALIZED,                   /* EBIU service already initialized        */

    /* Asynch memory controller result codes  */
    ADI_EBIU_RESULT_INVALID_ASYNCH_CLKOUT_ENABLE,          /* invalid clock out enable/disable choice                            */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ENABLE,            /* invalid bank enable/disable choice                                 */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_NUMBER,            /* invalid bank number specified in command argument                  */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_TRANSITION_TIME,   /* invalid transition time (used to avoid bus contention)             */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_READ_ACCESS_TIME,  /* invalid read access time - R-enable assertion to de-assertion      */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_WRITE_ACCESS_TIME, /* invalid write access time W-enable assertion to de-assertion       */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_SETUP_TIME,        /* invalid setup time - start of memory cycle to R/W-enable           */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_HOLD_TIME,         /* invalid hold time - R/W-enable de-assertion to end of memory cycle */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ARDY_ENABLE,       /* invalid ARDY enable/disable - used to insert extra wait states     */
    ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ARDY_POLARITY,     /* invalid ARDY sample polarity - low or high                         */


    ADI_EBIU_RESULT_INVALID_DDR_DS                         /* invalid memory drive strength           */

} ADI_EBIU_RESULT;




/********************************************************************************
* EBIU Module Command codes
*********************************************************************************/
typedef enum ADI_EBIU_COMMAND
{
    ADI_EBIU_CMD_START=ADI_EBIU_ENUMERATION_START,       /* start of command pair table                      */
    ADI_EBIU_CMD_END,                                    /* end of command pair table                        */
    ADI_EBIU_CMD_PAIR,                                   /* command pair follows                             */
    ADI_EBIU_CMD_TABLE,                                  /* command table follows                            */

    /* DDR memory related commands */
    ADI_EBIU_CMD_SET_DDR_MODULE,                         /* sets parameters for a given micron DDR memory    */
    ADI_EBIU_CMD_SET_DDRCTL0,                            /* 'shortcut' to set EBIU control register 0        */
    ADI_EBIU_CMD_SET_DDRCTL1,                            /* 'shortcut' to set EBIU control register 1        */
    ADI_EBIU_CMD_SET_DDRCTL2,                            /* 'shortcut' to set EBIU control register 2        */
    ADI_EBIU_CMD_SET_DDR_REFI,                           /* sets minimum refresh interval                    */
    ADI_EBIU_CMD_SET_DDR_RFC,                            /* set auto refresh period                          */
    ADI_EBIU_CMD_SET_DDR_RP,                             /* set precharge to active time                     */
    ADI_EBIU_CMD_SET_DDR_RAS,                            /* set active to precharge time                     */
    ADI_EBIU_CMD_SET_DDR_RC,                             /* set active to active time                        */
    ADI_EBIU_CMD_SET_DDR_WTR,                            /* set write to read time                           */
    ADI_EBIU_CMD_SET_DDR_DEVICE_SIZE,                    /* size of device                                   */
    ADI_EBIU_CMD_SET_DDR_DEVICE_WIDTH,                   /* width of device                                  */
    ADI_EBIU_CMD_SET_DDR_EXTERNAL_BANKS,                 /* set number of external banks                     */
    ADI_EBIU_CMD_SET_DDR_DATA_WIDTH,                     /* set data width                                   */
    ADI_EBIU_CMD_SET_DDR_WR,                             /* set write recovery time                          */
    ADI_EBIU_CMD_SET_DDR_MRD,                            /* set cycles from setting mode reg until next command      */
    ADI_EBIU_CMD_SET_DDR_RCD,                            /* set cycles from active command to a read/write assertion */
    ADI_EBIU_CMD_SET_DDR_CAS,                            /* cycles from read/write signal until first valid data     */
    ADI_EBIU_CMD_SET_DDR_PASR,                           /* partial array self-refresh - mobile DDR only     */
    ADI_EBIU_CMD_SET_DDR_SOFT_RESET,                     /* issue a soft reset                               */
    ADI_EBIU_CMD_DDR_SELF_REFRESH_REQUEST,               /* request self-refresh                             */
    ADI_EBIU_CMD_MOBILE_DDR_ENABLE,                      /* mobile DDR enable                                */
    ADI_EBIU_CMD_SET_FREQ_AS_MHZ,                        /* sets the frequency units to megahertz            */

/* Added Asynch commands May 22, 2007 */
    ADI_EBIU_CMD_SET_ASYNCH_AMGCTL,                      /* set the global asynch control register            */
    ADI_EBIU_CMD_SET_ASYNCH_AMBCTL0,                     /* set the asynch bank control register 0            */
    ADI_EBIU_CMD_SET_ASYNCH_AMBCTL1,                     /* set the asynch bank control register 1            */
    ADI_EBIU_CMD_SET_ASYNCH_CLKOUT_ENABLE,               /* for external memory devices that need clock input */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_ENABLE,                 /* individual bank enable/disable                    */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_TRANSITION_TIME,        /* optimized to avoid bus contention                 */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_READ_ACCESS_TIME,       /* R-enable assertion to de-assertion                */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_WRITE_ACCESS_TIME,      /* W-enable assertion to de-assertion                */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_SETUP_TIME,             /* start of memory cycle to R/W-enable               */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_HOLD_TIME,              /* R/W-enable de-assertion  to end of memory cycle   */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_ARDY_ENABLE,            /* used to insert extra wait states                  */
    ADI_EBIU_CMD_SET_ASYNCH_BANK_ARDY_POLARITY,          /* ARDY sampled low or high                          */
    ADI_EBIU_CMD_SET_DDR_DS                              /* set memory drive strength - mobile or non-mobile */

} ADI_EBIU_COMMAND;

/* The EBIU service does not support setting of DDR queue registers or reading of the DDR error
   registers & metrics registers          */


/*********************************************************************************
* Module Types (that support DDR memory)
*********************************************************************************/

typedef enum ADI_EBIU_SDRAM_MODULE_TYPE

{

/* (8 Meg x 16 x 4 banks) 512Mbits */
/* 8k rows, 1k columns*/

    ADI_EBIU_SDRAM_MODULE_MT46V32M16P_6T_F,
    ADI_EBIU_SDRAM_MODULE_MT46V64M16P_6T_F,
    ADI_EBIU_SDRAM_MODULE_MT46V128M16P_6T_F,
    ADI_EBIU_SDRAM_MODULE_MT46V32M16P_5B_F

} ADI_EBIU_SDRAM_MODULE_TYPE;



/********************************************************************************
* DS - Memory Device Drive Strength (mobile DDR)
*********************************************************************************/
typedef enum ADI_EBIU_DDR_MOBILE_DS
{
    ADI_EBIU_DDR_DS_1=0,     /* 00: Full Strength Drive           */
    ADI_EBIU_DDR_DS_2,       /* 01: Half Strength Drive (Default) */
    ADI_EBIU_DDR_DS_4,       /* 10: Quarter Strength Drive        */
    ADI_EBIU_DDR_DS_8        /* 11: One-eighth Strength Drive     */
} ADI_EBIU_DDR_MOBILE_DS;


/********************************************************************************
* DS - Memory Device Drive Strength (standard DDR)
*********************************************************************************/
typedef enum ADI_EBIU_DDR_DS
{
    ADI_EBIU_DDR_DS_FULL=0,     /* 00: Full Strength Drive              */
    ADI_EBIU_DDR_DS_REDUCED     /* 01: Reduced Strength Drive (Default) */
} ADI_EBIU_DDR_DS;



/********************************************************************************
*   PASR Partial Array Self-Refresh (DDRCTL3 Valid ONLY in mobile DDR mode )
*********************************************************************************/
typedef enum ADI_EBIU_DDR_PASR
{

    ADI_EBIU_DDR_PASR_1,         /* 0 Full array (all banks)     */
    ADI_EBIU_DDR_PASR_2,         /* 1 Half Array (BA1=0)         */
    ADI_EBIU_DDR_PASR_4,         /* 2 Quarter Array(BA1=BA0=0)   */
    ADI_EBIU_DDR_PASR_RESERVED3,   /* 3 reserved                   */
    ADI_EBIU_DDR_PASR_RESERVED4,   /* 4 reserved                   */
    ADI_EBIU_DDR_PASR_8,         /* 5 1/8 Array (BA1=BA0=Row Addr MSB=0)  */
    ADI_EBIU_DDR_PASR_16         /* 6 1/16 Array BA1=BA0=Row Addr MSBs=0) */
} ADI_EBIU_DDR_PASR;



/********************************************************************************
*   CAS Latency (DDRCTL2)
*********************************************************************************/


#define ADI_EBIU_DDR_CAS_1_5 0x5   /* 1.5 cycles */
#define ADI_EBIU_DDR_CAS_2   0x2   /* 2.0 cycles */
#define ADI_EBIU_DDR_CAS_2_5 0x6   /* 2.5 cycles */
#define ADI_EBIU_DDR_CAS_3   0x3   /* 3.0 cycles */



/**********************************************************************************
  END of section for EBIU which supports DDR
***********************************************************************************/

#endif /* whether or not the EBIU supports DDR */


/********************************************************************************
*           C/C++ SECTION
*********************************************************************************/


/********************************************************************************
* Timing unit values (used where values are expressed in SCLK cycles + time,
* i.e. min TWR, and Refresh period)
*********************************************************************************/
typedef enum ADI_EBIU_TIMING_UNIT {
    ADI_EBIU_TIMING_UNIT_MILLISEC =-1,           // control flag
    ADI_EBIU_TIMING_UNIT_MICROSEC =0x00000001,   // 10**0
    ADI_EBIU_TIMING_UNIT_NANOSEC  =0x000003E8,   // 10**3
    ADI_EBIU_TIMING_UNIT_PICOSEC  =0x000F4240,   // 10**6
    ADI_EBIU_TIMING_UNIT_FEMTOSEC =0x3B9ACA00    // 10**9
} ADI_EBIU_TIMING_UNIT;

/********************************************************************************
* Time structure - value and units, eg { 7500, ADI_EBIU_TIMING_UNIT_PICOSEC} is
* equivalent to 7.5 ns (avoids using floating point math)
*********************************************************************************/
typedef struct ADI_EBIU_TIME {

    u32                  value;
    ADI_EBIU_TIMING_UNIT units;
} ADI_EBIU_TIME;

/********************************************************************************
* Timing value structure, eg. min TWR fro EZKIT is expressed as
{1, {7500, ADI_EBIU_TIMING_UNIT_PICOSEC} } i.e. 1 SCLK cycle + 7.5ns
*********************************************************************************/
typedef struct ADI_EBIU_TIMING_VALUE {
    u32             cycles;
    ADI_EBIU_TIME   time;
} ADI_EBIU_TIMING_VALUE;



/********************************************************************************
* enumeration for enabling/disabling asynch clock out
*********************************************************************************/

typedef enum ADI_EBIU_ASYNCH_CLKOUT
{
    ADI_EBIU_ASYNCH_CLKOUT_DISABLE,
    ADI_EBIU_ASYNCH_CLKOUT_ENABLE
} ADI_EBIU_ASYNCH_CLKOUT;


/********************************************************************************
* enumeration for enabling/disabling asynch banks
*********************************************************************************/

typedef enum ADI_EBIU_ASYNCH_BANK_ENABLE
{
   ADI_EBIU_ASYNCH_DISABLE_All,
   ADI_EBIU_ASYNCH_BANK0,
   ADI_EBIU_ASYNCH_BANK0_1,
   ADI_EBIU_ASYNCH_BANK0_1_2,
   ADI_EBIU_ASYNCH_BANK0_1_2_3
} ADI_EBIU_ASYNCH_BANK_ENABLE;

/********************************************************************************
* enumeration for specifying bank numbers
*********************************************************************************/

typedef enum ADI_EBIU_BANK_NUMBER
{
 ADI_EBIU_BANK_0,
 ADI_EBIU_BANK_1,
 ADI_EBIU_BANK_2,
 ADI_EBIU_BANK_3,
 ADI_EBIU_BANK_ALL
} ADI_EBIU_BANK_NUMBER;


/********************************************************************************
 ADI_EBIU_ASYNCH_BANK_TIMING enum for setting individual asynch bank parameters


      bank_number
      bank_time _____cycles
               |
               |_____time_____value
                       |
                       |_____units


*********************************************************************************/

typedef struct ADI_EBIU_ASYNCH_BANK_TIMING
{
    ADI_EBIU_BANK_NUMBER          bank_number;
    ADI_EBIU_TIMING_VALUE         bank_time;
} ADI_EBIU_ASYNCH_BANK_TIMING;



/********************************************************************************
* enumerations to support the union fields of ADI_EBIU_ASYNCH_BANK_VALUE
*********************************************************************************/

typedef enum ADI_EBIU_ASYNCH_BANK_ARDY_POLARITY
{
    ADI_EBIU_ASYNCH_ARDY_POLARITY_LOW,
    ADI_EBIU_ASYNCH_ARDY_POLARITY_HIGH
} ADI_EBIU_ASYNCH_BANK_ARDY_POLARITY;


typedef enum ADI_EBIU_ASYNCH_BANK_ARDY_ENABLE
{
    ADI_EBIU_ASYNCH_ARDY_DISABLE,
    ADI_EBIU_ASYNCH_ARDY_ENABLE
} ADI_EBIU_ASYNCH_BANK_ARDY_ENABLE;


#if defined(__ADSP_TETON__)
typedef enum ADI_EBIU_ASYNCH_BANK_DATA_PATH
{
    ADI_EBIU_ASYNCH_BANK_DATA_PATH_32,
    ADI_EBIU_ASYNCH_BANK_DATA_PATH_16
} ADI_EBIU_ASYNCH_BANK_DATA_PATH;

#endif


/********************************************************************************
* union of enums for setting 3 kinds of binary asynch bank parameters (0/1)
*********************************************************************************/

typedef struct ADI_EBIU_ASYNCH_BANK_VALUE
{
    ADI_EBIU_BANK_NUMBER bank_number;

    union
    {
        ADI_EBIU_ASYNCH_BANK_ARDY_POLARITY     ardy_polarity;
        ADI_EBIU_ASYNCH_BANK_ARDY_ENABLE       ardy_enable;

#if defined(__ADSP_TETON__)
        ADI_EBIU_ASYNCH_BANK_DATA_PATH         data_path;
#endif

    } value;

} ADI_EBIU_ASYNCH_BANK_VALUE;



/********************************************************************************
* EBIU Module Command pair structure
********************************************************************************/
#pragma pack(4)
typedef struct ADI_EBIU_COMMAND_PAIR {
    ADI_EBIU_COMMAND kind;
    void* value;
} ADI_EBIU_COMMAND_PAIR;
#pragma pack()


/********************************************************************************
* EBIU Config structure handle and size
*********************************************************************************/
typedef void *ADI_EBIU_CONFIG_HANDLE;

/********************************************************************************
* API function prototypes
*********************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


ADI_EBIU_RESULT adi_ebiu_Init(              // Initializes the EBIU Module and sets the SDC to reset values
        const ADI_EBIU_COMMAND_PAIR *ConfigData,    // Table of command-value pairs to define the actual hardware in use
        const u16 Reserved                  // Previously Adjust refresh rate flag (no longer required)
);

ADI_EBIU_RESULT adi_ebiu_Control(               // Sets/Queries the module settings using command-value pairs
        ADI_EBIU_COMMAND Command,           // Command
        void *Value                     // Value
);




ADI_EBIU_RESULT adi_ebiu_LoadConfig(            // Sets the EBIU to the settings in the given configuration structure
        ADI_EBIU_CONFIG_HANDLE hConfig,     // Address of configuration structure to be applied
        size_t szConfig                 // Size of memory being passed (for checking puproses)
);

ADI_EBIU_RESULT adi_ebiu_SaveConfig(            // Saves the current EBIU settings to the given memory location
        ADI_EBIU_CONFIG_HANDLE hConfig,         // Address of configuration structure to save values to
        size_t szConfig                 // Size of memory being passed (for checking puproses)
);


/* ADjusts the timings and refresh rate to match the given SCLK frequency. */
ADI_EBIU_RESULT adi_ebiu_AdjustSDRAM(
        u32 fsclk
);

size_t adi_ebiu_GetConfigSize(void);            // Returns the size in bytes of the modules configuration structure


ADI_EBIU_RESULT adi_ebiu_Terminate(void);           // Terminates use of the module


#ifdef __cplusplus
}
#endif


#else // END OF C/C++ SECTION


/****************************************************************************************
* Assembler Section - This section has been reinstated solely for the benefit of the
* CRTGen "Custom Clock & Powersettings, a feature which is not supported, from Moab onward.
****************************************************`**********************************/
#if defined(__ADSP_TETON__) || defined(__ADSP_EDINBURGH__) || defined(__ADSP_BRAEMAR__) || defined(__ADSP_STIRLING__)

/********************************************************************************
*           ASSEMBLER SECTION
*********************************************************************************/


/********************************************************************************
* EBIU Module result codes
*********************************************************************************/


#define ADI_EBIU_RESULT_SUCCESS                         0   // Successfull completion
#define ADI_EBIU_RESULT_FAILED                          1   // Generic failure
#define ADI_EBIU_RESULT_BAD_COMMAND                     (1 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_COMMAND Command value
#define ADI_EBIU_RESULT_NOT_INITIALIZED                 (2 + ADI_EBIU_ENUMERATION_START)    // Call ignored (module not initialized)
#define ADI_EBIU_RESULT_INVALID_SDRAM_EBE               (3 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_ENABLE value
#define ADI_EBIU_RESULT_INVALID_SDRAM_BANK_SIZE         (4 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_BANK_SIZE value
#define ADI_EBIU_RESULT_INVALID_SDRAM_COL_WIDTH         (5 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_BANK_COL_WIDTH value
#define ADI_EBIU_RESULT_INVALID_SDRAM_CDDBG             (6 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_CDDBG value
#define ADI_EBIU_RESULT_INVALID_SDRAM_EBUFE             (7 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_EBUFE value
#define ADI_EBIU_RESULT_INVALID_SDRAM_EMREN             (8 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_EMREN value
#define ADI_EBIU_RESULT_INVALID_SDRAM_FBBRW             (9 + ADI_EBIU_ENUMERATION_START)    // Invalid ADI_EBIU_RESULT_SDRAM_FBBRW value
#define ADI_EBIU_RESULT_INVALID_SDRAM_PASR              (10 + ADI_EBIU_ENUMERATION_START)   // Invalid ADI_EBIU_RESULT_SDRAM_PASR value
#define ADI_EBIU_RESULT_INVALID_SDRAM_PSM               (11 + ADI_EBIU_ENUMERATION_START)   // Invalid ADI_EBIU_RESULT_SDRAM_PSM value
#define ADI_EBIU_RESULT_INVALID_SDRAM_PUPSD             (13 + ADI_EBIU_ENUMERATION_START)   // Invalid ADI_EBIU_RESULT_SDRAM_PUPSD value
#define ADI_EBIU_RESULT_INVALID_SDRAM_SRFS              (14 + ADI_EBIU_ENUMERATION_START)   // Invalid ADI_EBIU_RESULT_SDRAM_SRFS value
#define ADI_EBIU_RESULT_INVALID_SDRAM_TCSR              (15 + ADI_EBIU_ENUMERATION_START)   // Invalid ADI_EBIU_RESULT_SDRAM_TCRS value
#define ADI_EBIU_RESULT_INVALID_SDRAM_TWRMIN            (16 + ADI_EBIU_ENUMERATION_START)   // Invalid value for TWRMIN - would cause TWR>3
#define ADI_EBIU_RESULT_NO_MEMORY                       (17 + ADI_EBIU_ENUMERATION_START)   // Insufficient memory to load/save configuration
#define ADI_EBIU_RESULT_INVALID_EZKIT                   (18 + ADI_EBIU_ENUMERATION_START)   // Invalid EZKIT revision number
#define ADI_EBIU_RESULT_INVALID_SDRAM_SCTLE             (19 + ADI_EBIU_ENUMERATION_START)   // invalid SCTLE value
#define ADI_EBIU_RESULT_INVALID_SDRAM_MODULE            (20 + ADI_EBIU_ENUMERATION_START)   // invalid SDRAM module type
#if defined(__ADSP_TETON__)
#define ADI_EBIU_RESULT_INVALID_IVG                     (21 + ADI_EBIU_ENUMERATION_START)   // invlaid IVG level for supplemental interrupt
#define ADI_EBIU_RESULT_INVALID_SDRAM_BANK              (22 + ADI_EBIU_ENUMERATION_START)   // Invalid bank number given
#endif

/* Asynch memory results added May 22, 2007 */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_CLKOUT_ENABLE    (24 + ADI_EBIU_ENUMERATION_START)/* invalid clock out enable/disable choice           */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ENABLE      (25 + ADI_EBIU_ENUMERATION_START)/* invalid bank enable/disable choice                */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_NUMBER      (26 + ADI_EBIU_ENUMERATION_START)/* invalid bank number specified in command argument */

#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_TRANSITION_TIME     (27 + ADI_EBIU_ENUMERATION_START)/* invalid transition time (used to avoid bus contention)              */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_READ_ACCESS_TIME    (28 + ADI_EBIU_ENUMERATION_START)/* invalid read access time - R-enable assertion to de-assertion       */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_WRITE_ACCESS_TIME   (29 + ADI_EBIU_ENUMERATION_START)/* invalid write access time W-enable assertion to de-assertion        */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_SETUP_TIME          (30 + ADI_EBIU_ENUMERATION_START)/* invalid setup time - start of memory cycle to R/W-enable            */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_HOLD_TIME           (31 + ADI_EBIU_ENUMERATION_START)/* invalid hold time - R/W-enable de-assertion to end of memory cycle  */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ARDY_ENABLE         (32 + ADI_EBIU_ENUMERATION_START)/* invalid ARDY enable/disable - used to insert extra wait states      */
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_ARDY_POLARITY       (33 + ADI_EBIU_ENUMERATION_START)/* invalid ARDY sample polarity - low or high                          */

#if defined(__ADSP_TETON__)
#define ADI_EBIU_RESULT_INVALID_ASYNCH_BANK_16_BIT_PACKING_ENABLE   (34 + ADI_EBIU_ENUMERATION_START)/* invalid data packing selection         */
#endif

#define ADI_EBIU_RESULT_CALL_IGNORED  ADI_EBIU_RESULT_NOT_INITIALIZED      // obsoleted

/********************************************************************************
* EBIU Module Command codes
*********************************************************************************/
#define ADI_EBIU_CMD_END                        (1 + ADI_EBIU_ENUMERATION_START)    // end of table
#define ADI_EBIU_CMD_PAIR                       (2 + ADI_EBIU_ENUMERATION_START)    // command pair follows
#define ADI_EBIU_CMD_TABLE                      (3 + ADI_EBIU_ENUMERATION_START)    // command table follows
#define ADI_EBIU_CMD_SET_EZKIT                  (4 + ADI_EBIU_ENUMERATION_START)    // set details as per given EZKIT board
#define ADI_EBIU_CMD_SET_SDRAM_ENABLE           (5 + ADI_EBIU_ENUMERATION_START)    // set EBIU_SDBCTL::EBE field
#define ADI_EBIU_CMD_SET_SDRAM_BANK_SIZE        (6 + ADI_EBIU_ENUMERATION_START)    // set EBIU_SDBCTL::EBSZ field
#define ADI_EBIU_CMD_SET_SDRAM_BANK_COL_WIDTH   (7 + ADI_EBIU_ENUMERATION_START)    // set EBIU_SDBCTL::EBCAW field
#define ADI_EBIU_CMD_SET_SDRAM_PASR             (8 + ADI_EBIU_ENUMERATION_START)    // set EBIU_SDGCTL::PASR field
#define ADI_EBIU_CMD_SET_SDRAM_EBUFE            (9 + ADI_EBIU_ENUMERATION_START)    // set EBIU_SDGCTL::EBUFE field
#define ADI_EBIU_CMD_SET_SDRAM_PUPSD            (10 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::PUPSD field
#define ADI_EBIU_CMD_SET_SDRAM_PSM              (11 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::PSM field
#define ADI_EBIU_CMD_SET_SDRAM_SCTLE            (12 + ADI_EBIU_ENUMERATION_START)   // sets the SCTLE bit to enable/disable CLKOUT, SRAS, SCAS, SDQM[1:0]
#define ADI_EBIU_CMD_SET_SDRAM_FBBRW            (13 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::FBBRW field
#define ADI_EBIU_CMD_SET_SDRAM_CDDBG            (14 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::CDDBG field
#define ADI_EBIU_CMD_SET_SDRAM_SRFS             (15 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::SRFS field (set SDRAM in self refresh mode)
#define ADI_EBIU_CMD_SET_SDRAM_EMREN            (16 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::EMREN field (using low-power SDRAM)
#define ADI_EBIU_CMD_SET_SDRAM_TCSR             (17 + ADI_EBIU_ENUMERATION_START)   // set EBIU_SDGCTL::TCSR field
#define ADI_EBIU_CMD_SET_SDRAM_CL_THRESHOLD     (18 + ADI_EBIU_ENUMERATION_START)   // set CAS latency threshold as per SDRAM datasheet
#define ADI_EBIU_CMD_SET_SDRAM_TRASMIN          (19 + ADI_EBIU_ENUMERATION_START)   // set min TRAS value as per SDRAM datasheet
#define ADI_EBIU_CMD_SET_SDRAM_TRPMIN           (20 + ADI_EBIU_ENUMERATION_START)   // set min TRP value as per SDRAM datasheet
#define ADI_EBIU_CMD_SET_SDRAM_TRCDMIN          (21 + ADI_EBIU_ENUMERATION_START)   // set min TRCD value as per SDRAM datasheet
#define ADI_EBIU_CMD_SET_SDRAM_TWRMIN           (22 + ADI_EBIU_ENUMERATION_START)   // set min TWR value as per SDRAM datasheet
#define ADI_EBIU_CMD_SET_SDRAM_REFRESH          (23 + ADI_EBIU_ENUMERATION_START)   // set REFRESH period value as per SDRAM datasheet
#define ADI_EBIU_CMD_SET_SDGCTL_REG             (24 + ADI_EBIU_ENUMERATION_START)   // set whole EBIU_SDGCTL word
#define ADI_EBIU_CMD_SET_SDBCTL_REG             (25 + ADI_EBIU_ENUMERATION_START)   // set whole EBIU_SDBCTL word
#define ADI_EBIU_CMD_SET_CRITICAL_REGION_DATA   (26 + ADI_EBIU_ENUMERATION_START)   // sets the data location for critical region data to be stored (eg IMASK)
#define ADI_EBIU_CMD_SET_SDRAM_MODULE           (27 + ADI_EBIU_ENUMERATION_START)   // sets the timings etc for a given (Micron) SDRAM module
#if defined(__ADSP_TETON__)
#define ADI_EBIU_CMD_SET_COREB_SUPP_INT0_IVG    (40 + ADI_EBIU_ENUMERATION_START)   // set bCore B Supplemental interrupt level
#define ADI_EBIU_CMD_SET_AUTO_SYNC_DISABLED     (41 + ADI_EBIU_ENUMERATION_START)   // disable core synchronisation within module.
#endif

/* Added Asynch commands May 22, 2007 */
#define ADI_EBIU_CMD_SET_ASYNCH_AMGCTL            (42 + ADI_EBIU_ENUMERATION_START )
#define ADI_EBIU_CMD_SET_ASYNCH_AMBCTL0           (43 + ADI_EBIU_ENUMERATION_START )
#define ADI_EBIU_CMD_SET_ASYNCH_AMBCTL1            (44 + ADI_EBIU_ENUMERATION_START )
#define ADI_EBIU_CMD_SET_ASYNCH_CLKOUT_ENABLE      (45 + ADI_EBIU_ENUMERATION_START )        /* for external memory devices that need clock input */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_ENABLE        (46 + ADI_EBIU_ENUMERATION_START )        /* individual bank enable/disable */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_TRANSITION_TIME  (47 + ADI_EBIU_ENUMERATION_START )     /* optimized to avoid bus contention */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_READ_ACCESS_TIME (48 + ADI_EBIU_ENUMERATION_START )     /* R-enable assertion to de-assertion */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_WRITE_ACCESS_TIME (49 + ADI_EBIU_ENUMERATION_START )    /* W-enable assertion to de-assertion */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_SETUP_TIME    (50 + ADI_EBIU_ENUMERATION_START )        /* beginning of memory cycle to R/W-enable */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_HOLD_TIME     (51 + ADI_EBIU_ENUMERATION_START )        /* R/W-enable de-assertion  to end of memory cycle */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_ARDY_ENABLE   (52 + ADI_EBIU_ENUMERATION_START )        /* used to insert extra wait states */
#define ADI_EBIU_CMD_SET_ASYNCH_BANK_ARDY_POLARITY (53 + ADI_EBIU_ENUMERATION_START )        /* ARDY sampled low or high */


/********************************************************************************
*********************************************************************************
*
*               valid EBIU_SDBCTL field values and defaults
*
*********************************************************************************
*********************************************************************************/

/********************************************************************************
* EBE
*********************************************************************************/
#define ADI_EBIU_SDRAM_EBE_DISABLE  0
#define ADI_EBIU_SDRAM_EBE_ENABLE       1


/********************************************************************************
* EBSZ
*********************************************************************************/
#define ADI_EBIU_SDRAM_BANK_16MB    0
#define ADI_EBIU_SDRAM_BANK_32MB    1
#define ADI_EBIU_SDRAM_BANK_64MB    2
#define ADI_EBIU_SDRAM_BANK_128MB   3
#define ADI_EBIU_SDRAM_BANK_256MB   4
#define ADI_EBIU_SDRAM_BANK_512MB   5

/********************************************************************************
* EBCAW
*********************************************************************************/
#define ADI_EBIU_SDRAM_BANK_COL_8BIT    0
#define ADI_EBIU_SDRAM_BANK_COL_9BIT    1
#define ADI_EBIU_SDRAM_BANK_COL_10BIT   2
#define ADI_EBIU_SDRAM_BANK_COL_11BIT   3

/********************************************************************************
*********************************************************************************
*
*              valid EBIU_SDGCTL field values and defaults
*
*********************************************************************************
*********************************************************************************/

/********************************************************************************
* SCTLE
*********************************************************************************/
#define ADI_EBIU_SDRAM_SCTLE_DISABLE    0
#define ADI_EBIU_SDRAM_SCTLE_ENABLE     1

/********************************************************************************
* EMREN
*********************************************************************************/
#define ADI_EBIU_SDRAM_EMREN_DISABLE    0
#define ADI_EBIU_SDRAM_EMREN_ENABLE     1

/********************************************************************************
* SRFS
*********************************************************************************/
#define ADI_EBIU_SDRAM_SRFS_DISABLE     0
#define ADI_EBIU_SDRAM_SRFS_ENABLE      1

/********************************************************************************
* EBUFE
*********************************************************************************/
#define ADI_EBIU_SDRAM_EBUFE_DISABLE    0
#define ADI_EBIU_SDRAM_EBUFE_ENABLE     1

/********************************************************************************
* PUPSD
*********************************************************************************/
#define ADI_EBIU_SDRAM_PUPSD_NODELAY    0
#define ADI_EBIU_SDRAM_PUPSD_15CYCLES   1

/********************************************************************************
* PSM
*********************************************************************************/
#define ADI_EBIU_SDRAM_PSM_REFRESH_FIRST    0
#define ADI_EBIU_SDRAM_PSM_REFRESH_LAST     1

/********************************************************************************
* PASR
*********************************************************************************/
#define ADI_EBIU_PASR_ALL               0
#define ADI_EBIU_PASR_INT01             1
#define ADI_EBIU_PASR_INT0_ONLY         2

/********************************************************************************
* FBBRW
*********************************************************************************/
#define ADI_EBIU_SDRAM_FBBRW_DISABLE    0
#define ADI_EBIU_SDRAM_FBBRW_ENABLE     1

/********************************************************************************
* TCSR
*********************************************************************************/
#define ADI_EBIU_SDRAM_TCSR_45DEG       0
#define ADI_EBIU_SDRAM_TCSR_85DEG       1

/********************************************************************************
* CDDBG
*********************************************************************************/
#define ADI_EBIU_SDRAM_CDDBG_DISABLE    0
#define ADI_EBIU_SDRAM_CDDBG_ENABLE     1

/*********************************************************************************
* EZ-KIT revisions
*********************************************************************************/
#if defined(__ADSP_EDINBURGH__)
#define ADI_EBIU_EZKIT_BF533            0
#define ADI_EBIU_EZKIT_BF533_REV1_7     1
#endif

#if defined(__ADSP_TETON__)
#define ADI_EBIU_EZKIT_BF561    0
#endif

#if defined(__ADSP_BRAEMAR__)
#define ADI_EBIU_EZKIT_BF537    0
#endif

#if defined(__ADSP_STIRLING__)
#define ADI_EBIU_EZKIT_BF538    0
#endif



/********************************************************************************
* Timing unit values (used where values are expressed in SCLK cycles + time
* i.e. min TWR and Refresh period)
*********************************************************************************/
#define ADI_EBIU_TIMING_UNIT_MILLISEC  0xFFFFFFFF   // control flag
#define ADI_EBIU_TIMING_UNIT_MICROSEC  0x00000001   // 10**0
#define ADI_EBIU_TIMING_UNIT_NANOSEC   0x000003E8    // 10**3
#define ADI_EBIU_TIMING_UNIT_PICOSEC   0x000F4240   // 10**6
#define ADI_EBIU_TIMING_UNIT_FEMTOSEC  0x3B9ACA00   // 10**9


/*********************************************************************************
* Memory Module Definitions (Micron parts)
*
* The 32 bit enum is made up of 3 fields:
* 0:2   - Speed Grade identifier
* 3:4   - Column Address Width (CAW)
* 16:31 - Unique identifier in enumerator
*
*********************************************************************************/

#define ADI_EBIU_SDRAM_MODULE_6     0
#define ADI_EBIU_SDRAM_MODULE_6A    1
#define ADI_EBIU_SDRAM_MODULE_7E    2
#define ADI_EBIU_SDRAM_MODULE_75    3
#define ADI_EBIU_SDRAM_MODULE_8E    4


#define ADI_EBIU_SDRAM_REFRESH_CYCLES_4K 0
#define ADI_EBIU_SDRAM_REFRESH_CYCLES_8K 1



    // 8MB (64Mb) modules
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_6      ADI_EBIU_SDRAM_MODULE_ID_VALUE(  0, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_6  )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_6       ADI_EBIU_SDRAM_MODULE_ID_VALUE(  1, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_6  )
#define ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_6      ADI_EBIU_SDRAM_MODULE_ID_VALUE(  2, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_6  )

#define ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE(  3, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_7E      ADI_EBIU_SDRAM_MODULE_ID_VALUE(  4, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE(  5, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_7E )

#define ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE(  6, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_75      ADI_EBIU_SDRAM_MODULE_ID_VALUE(  7, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE(  8, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_75 )

#define ADI_EBIU_SDRAM_MODULE_MT48LC16M4A2_8E     ADI_EBIU_SDRAM_MODULE_ID_VALUE(  9, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_8E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M8A2_8E      ADI_EBIU_SDRAM_MODULE_ID_VALUE( 10, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_8E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC4M16A2_8E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 11, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_8BIT,  ADI_EBIU_SDRAM_MODULE_8E )

// 16MB (128Mb), modules
#define ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_6A     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 12, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_6A )
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_6A     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 13, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_6A )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_6A     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 14, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_6A )

#define ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 15, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 16, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 17, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_7E )

#define ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 18, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 19, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 20, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_75 )

#define ADI_EBIU_SDRAM_MODULE_MT48LC32M4A2_8E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 21, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_8E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M8A2_8E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 22, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_8E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC8M16A2_8E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 23, ADI_EBIU_SDRAM_REFRESH_CYCLES_4K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_8E )

// 32MB (256Mb), modules
#define ADI_EBIU_SDRAM_MODULE_MT48LC64M4A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 24, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC32M8A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 25, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M16A2_7E    ADI_EBIU_SDRAM_MODULE_ID_VALUE( 26, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_7E )

#define ADI_EBIU_SDRAM_MODULE_MT48LC64M4A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 27, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC32M8A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 28, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC16M16A2_75    ADI_EBIU_SDRAM_MODULE_ID_VALUE( 29, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_9BIT,  ADI_EBIU_SDRAM_MODULE_75 )

// 64MB (512Mb), modules
#define ADI_EBIU_SDRAM_MODULE_MT48LC64M8A2_7E     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 30, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_7E )
#define ADI_EBIU_SDRAM_MODULE_MT48LC32M16A2_7E    ADI_EBIU_SDRAM_MODULE_ID_VALUE( 31, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_7E )

#define ADI_EBIU_SDRAM_MODULE_MT48LC64M8A2_75     ADI_EBIU_SDRAM_MODULE_ID_VALUE( 32, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_11BIT, ADI_EBIU_SDRAM_MODULE_75 )
#define ADI_EBIU_SDRAM_MODULE_MT48LC32M16A2_75    ADI_EBIU_SDRAM_MODULE_ID_VALUE( 33, ADI_EBIU_SDRAM_REFRESH_CYCLES_8K, ADI_EBIU_SDRAM_BANK_COL_10BIT, ADI_EBIU_SDRAM_MODULE_75 )




/********************************************************************************
* API function prototypes
*********************************************************************************/

.extern _adi_ebiu_Init;
.type _adi_ebiu_Init,STT_FUNC;

.extern _adi_ebiu_Control;
.type _adi_ebiu_Control,STT_FUNC;

.extern _adi_ebiu_AdjustSDRAM;
.type _adi_ebiu_AdjustSDRAM,STT_FUNC;

.extern _adi_ebiu_GetConfigSize;
.type _adi_ebiu_GetConfigSize,STT_FUNC;

.extern _adi_ebiu_LoadConfig;
.type _adi_ebiu_LoadConfig,STT_FUNC;

.extern _adi_ebiu_SaveConfig;
.type _adi_ebiu_SaveConfig,STT_FUNC;


.extern _adi_ebiu_Terminate;

.type _adi_ebiu_Terminate,STT_FUNC;


#endif // processors for which we still have assembler API

#endif // END OF ASSEMBLER SECTION

#define ADI_EBIU_SIZEOF_CONFIG  64

#define ADI_EBIU_EBE_DEFAULT                    ADI_EBIU_SDRAM_EBE_DISABLE
#define ADI_EBIU_SDRAM_BANK_SIZE_DEFAULT        ADI_EBIU_SDRAM_BANK_32MB
#define ADI_EBIU_SDRAM_BANK_COL_WIDTH_DEFAULT   ADI_EBIU_SDRAM_BANK_COL_9BIT
#define ADI_EBIU_VOLTS_DEFAULT                  ADI_EBIU_VOLTS_33
#define ADI_EBIU_SDRAM_SRFS_DEFAULT             ADI_EBIU_SDRAM_SRFS_DISABLE
#define ADI_EBIU_SDRAM_EBUFE_DEFAULT            ADI_EBIU_SDRAM_EBUFE_DISABLE
#define ADI_EBIU_SDRAM_PUPSD_DEFAULT            ADI_EBIU_SDRAM_PUPSD_NODELAY
#define ADI_EBIU_SDRAM_PSM_DEFAULT              ADI_EBIU_SDRAM_PSM_REFRESH_FIRST
#define ADI_EBIU_PASR_DEFAULT                   ADI_EBIU_PASR_ALL
#define ADI_EBIU_SDRAM_FBBRW_DEFAULT            ADI_EBIU_SDRAM_FBBRW_DISABLE
#define ADI_EBIU_TCSR_DEFAULT                   ADI_EBIU_TCSR_45DEG
#define ADI_EBIU_SDRAM_CDDBG_DEFAULT            ADI_EBIU_SDRAM_CDDBG_DISABLE

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif     /* __ADI_EBIU_H__ */
