/*********************************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.


Description:
            This is the include file for the KPAD driver.

*********************************************************************************/

#ifndef __ADI_KPAD_H__
#define __ADI_KPAD_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************************

Extensible enumerations and defines

*********************************************************************************/
/* KPAD driver Command IDs */
enum{
    ADI_KPAD_CMD_START=ADI_KEYPAD_ENUMERATION_START,    /* 0x40190000           */
    /* direct register transactions                                             */
    /* maintain this order                                                      */
    /******* order start                                                        */
    ADI_KPAD_CMD_SET_CONTROL_REG,   /* Set the KPAD control reg (u16)           */
	ADI_KPAD_CMD_GET_CONTROL_REG,   /* Get the KPAD control reg (u16)           */
    ADI_KPAD_CMD_SET_PRESCALE_REG,  /* Set the KPAD prescale reg (u16)          */
    ADI_KPAD_CMD_SET_MSEL_REG,      /* Set the KPAD multiplier select reg (u16) */
    ADI_KPAD_CMD_GET_ROWCOL_REG,    /* Get the KPAD row column reg (u16)        */
    ADI_KPAD_CMD_GET_STAT_REG,      /* Get the KPAD status reg (u16)            */
    ADI_KPAD_CMD_SET_SOFTEVAL_REG,  /* Set the KPAD software evaluate reg (u16) */
    /* ***** order end */

    /*imperative that the following commands remain in this exact order */
    /* ****** order start */
    ADI_KPAD_CMD_SET_KPAD_ENABLE,
    ADI_KPAD_CMD_SET_IRQMODE,
    ADI_KPAD_CMD_SET_ROW_NUMBER,
    ADI_KPAD_CMD_SET_COLUMN_NUMBER,
    ADI_KPAD_CMD_SET_PRESCALE_VAL,
    ADI_KPAD_CMD_SET_DBON_SCALE,
    ADI_KPAD_CMD_SET_COLDRV_SCALE,
    ADI_KPAD_CMD_SET_SOFTEVAL,
    /* ***** order end */

    ADI_KPAD_CMD_SET_DBON_COLDRV_TIME,

    ADI_KPAD_CMD_END
};

 /* KPAD Event IDs */
enum{
    ADI_KPAD_EVENT_START=ADI_KEYPAD_ENUMERATION_START,  /* 0x40190000           */
    ADI_KPAD_EVENT_KEYPRESSED                          /* 0x40190001           */
};

/* KPAD Result codes */
enum{
    ADI_KPAD_RESULT_START=ADI_KEYPAD_ENUMERATION_START, /* 0x40190000           */
    ADI_KPAD_RESULT_CMD_NOT_SUPPORTED,  /* 0x40190001 - command not supported   */
    ADI_KPAD_RESULT_BAD_ACCESS,        /* register is not allow to change      */
    ADI_KPAD_RESULT_BAD_ACCESS_WIDTH   /* reg isn't config'd with access width */
};

/* entry point to the device driver */
extern ADI_DEV_PDD_ENTRY_POINT ADIKPADEntryPoint;


/* This structure contains single or multiple key pressed result.               */
/* Pointer to this structure passed as callback argument for the key pressed    */
typedef struct {
    u16     rowcolpos;      /* holds single or multiple key pressed positions   */
    u8      mrowcol;        /* holds info about multiple key press              */
    u8      keypressed;     /* holds status of the key pressed or released      */
}ADI_KPAD_KEY_PRESSED_RESULT;

/*********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_KPAD_H */
