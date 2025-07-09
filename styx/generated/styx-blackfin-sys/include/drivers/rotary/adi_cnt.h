/*********************************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_cnt.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the Rotary Counter (CNT) driver.

*********************************************************************************/

#ifndef __ADI_CNT_H__
#define __ADI_CNT_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************************
 Counter Operating Mode
*********************************************************************************/
#define ADI_CNT_QUAD_ENC    0x000   /* quadrature encoder mode                          */
#define ADI_CNT_BIN_ENC     0x001   /* binary encoder mode                              */
#define ADI_CNT_UD_CNT      0x010   /* up/down counter mode                             */
#define ADI_CNT_DIR_CNT     0x100   /* direction counter mode                           */
#define ADI_CNT_DIR_TMR     0x101   /* direction timer mode                             */

/*********************************************************************************
 Boundary Register Mode
*********************************************************************************/
#define ADI_CNT_BND_COMP    0x00    /*  */
#define ADI_CNT_BND_ZERO    0x01    /*  */
#define ADI_CNT_BND_CAPT    0x10    /*  */
#define ADI_CNT_BND_AEXT    0x11    /*  */

/*********************************************************************************

Extensible enumerations and defines

*********************************************************************************/
/* CNT driver Command IDs */
enum{
    ADI_CNT_CMD_START=ADI_ROTARY_ENUMERATION_START,    /* 0x401b0000           */
    /* direct register transactions                                             */
    /* maintain this order                                                      */
    /******* order start                                                        */
    ADI_CNT_CMD_SET_CONFIG_REG,     /* Set CNT config reg (u16)                 */
    ADI_CNT_CMD_SET_IMASK_REG,      /* Set CNT prescale reg (u16)               */
    ADI_CNT_CMD_SET_COMMAND_REG,    /* Set CNT multiplier select reg (u16)      */
    ADI_CNT_CMD_SET_DEBOUNCE_REG,   /* Set CNT debounce reg (u16)               */
    ADI_CNT_CMD_SET_MAX_REG,        /* Set CNT max reg (u16)                    */
    ADI_CNT_CMD_SET_MIN_REG,        /* Set CNT min reg (u16)                    */
    ADI_CNT_CMD_GET_STATUS_REG,
    ADI_CNT_CMD_GET_COUNTER_REG,
    ADI_CNT_CMD_GET_MAX_REG,
    ADI_CNT_CMD_GET_MIN_REG,
    /* ***** order end */

    ADI_CNT_CMD_SET_CNT_ENABLE,
    ADI_CNT_CMD_SET_DEBOUNCE_ENABLE,
    ADI_CNT_CMD_CUD_CDG_DISABLE,
    ADI_CNT_CMD_SET_ZMZC_ENABLE,

    ADI_CNT_CMD_SET_CNTMODE,
    ADI_CNT_CMD_SET_BNDMODE,
    /*imperative that the following commands remain in this exact order */
    /* ****** order start */
    ADI_CNT_CMD_SET_CDG_POL_ALOW,
    ADI_CNT_CMD_SET_CUD_POL_ALOW,
    ADI_CNT_CMD_SET_CZM_POL_ALOW,
    ADI_CNT_CMD_SET_CDG_POL_AHIGH,
    ADI_CNT_CMD_SET_CUD_POL_AHIGH,
    ADI_CNT_CMD_SET_CZM_POL_AHIGH,
    /* Interrupt enable/disable commands */
    ADI_CNT_CMD_ILLEGAL_CODE_INT_EN,    /* Illegal gray/binary code int enable  */
    ADI_CNT_CMD_UPCOUNT_INT_EN,         /* Upcount interrupt enable             */
    ADI_CNT_CMD_DOWNCOUNT_INT_EN,       /* Downcount interrupt enable           */
    ADI_CNT_CMD_MINCOUNT_INT_EN,        /* Min count interrupt enable           */
    ADI_CNT_CMD_MAXCOUNT_INT_EN,        /* Max count interrupt enable           */
    ADI_CNT_CMD_OVERFLOW31_INT_EN,
    ADI_CNT_CMD_OVERFLOW15_INT_EN,
    ADI_CNT_CMD_COUNTZERO_INT_EN,
    ADI_CNT_CMD_CZMPIN_INT_EN,
    ADI_CNT_CMD_CZM_ERROR_INT_EN,
    ADI_CNT_CMD_CZM_COUNTZERO_INT_EN,
    ADI_CNT_CMD_ILLEGAL_CODE_INT_DIS,   /* Illegal gray/binary code int disable */
    ADI_CNT_CMD_UPCOUNT_INT_DIS,        /* Upcount interrupt disable            */
    ADI_CNT_CMD_DOWNCOUNT_INT_DIS,      /* Downcount interrupt disable          */
    ADI_CNT_CMD_MINCOUNT_INT_DIS,       /* Min count interrupt disable          */
    ADI_CNT_CMD_MAXCOUNT_INT_DIS,       /* Max count interrupt disable          */
    ADI_CNT_CMD_OVERFLOW31_INT_DIS,
    ADI_CNT_CMD_OVERFLOW15_INT_DIS,
    ADI_CNT_CMD_COUNTZERO_INT_DIS,
    ADI_CNT_CMD_CZMPIN_INT_DIS,
    ADI_CNT_CMD_CZM_ERROR_INT_DIS,
    ADI_CNT_CMD_CZM_COUNTZERO_INT_DIS,
    /* ***** order end */

    ADI_CNT_CMD_ZERO_CNT_COUNTER,
    ADI_CNT_CMD_LOAD_MIN_TO_COUNTER,
    ADI_CNT_CMD_LOAD_MAX_TO_COUNTER,
    ADI_CNT_CMD_ZERO_CNT_MIN,
    ADI_CNT_CMD_COUNTER_TO_CNT_MIN,
    ADI_CNT_CMD_CNT_MAX_TO_CNT_MIN,
    ADI_CNT_CMD_ZERO_CNT_MAX,
    ADI_CNT_CMD_COUNTER_TO_CNT_MAX,
    ADI_CNT_CMD_CNT_MIN_TO_CNT_MAX,
    ADI_CNT_CMD_CZM_CLEAR_COUNTER_ONCE,





    ADI_CNT_CMD_END
};

/* CNT Event IDs */
enum{
    ADI_CNT_EVENT_START=ADI_ROTARY_ENUMERATION_START,  /* 0x401b0000           */
    ADI_CNT_EVENT_ILLEGAL_CODE_INT,     /* illegal gray/binary code interrupt   */
    ADI_CNT_EVENT_UPCOUNT_INT,          /* Upcount interrupt                    */
    ADI_CNT_EVENT_DOWNCOUNT_INT,        /* Downcount interrupt                  */
    ADI_CNT_EVENT_MINCOUNT_INT,         /* CNT_COUNTER == CNT_MIN interrupt     */
    ADI_CNT_EVENT_MAXCOUNT_INT,         /* CNT_COUNTER == CNT_MAX interrupt     */
    ADI_CNT_EVENT_OVERFLOW31_INT,       /* Bit 31 overflow interrupt            */
    ADI_CNT_EVENT_OVERFLOW15_INT,       /* Bit 15 overflow interrupt            */
    ADI_CNT_EVENT_COUNT_TO_ZERO_INT,    /* count to zero interrupt              */
    ADI_CNT_EVENT_CZMPIN_INT,           /* CZM pin/push button interrupt        */
    ADI_CNT_EVENT_CZM_ERROR_INT,        /* Zero marker error interrupt          */
    ADI_CNT_EVENT_CZM_COUNTZERO_INT     /* Counter zeroes by zero marker int    */
};

  /* CNT Result codes */
enum{
    ADI_CNT_RESULT_START=ADI_ROTARY_ENUMERATION_START, /* 0x401b0000           */
    ADI_CNT_RESULT_CMD_NOT_SUPPORTED,   /* 0x401b0001 command not supported     */
    ADI_CNT_RESULT_CNTMODE_INVALID    /* invalid Counter mode                 */
};

/* entry point to the device driver */
extern ADI_DEV_PDD_ENTRY_POINT ADICNTEntryPoint;



/*Pointer to structure is passed as callback argument for the Counter interrupt */
typedef struct
{
    s32     CntCounter; /* CNT_COUNTER register value */
}ADI_CNT_CBSTATUS;

/*********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_CNT_H__ */
