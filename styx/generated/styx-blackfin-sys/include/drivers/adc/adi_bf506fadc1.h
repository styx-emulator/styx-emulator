/******************************************************************************
Copyright (c), 2010 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: ADI Device Drivers - BF506F ADC

Description:
    This is the primary include file for ADSP-BF506F ADC driver

    This file defines enumerations and data structures specific to ADC

*****************************************************************************/
#ifndef __ADI_BF506ADC1_H__
#define __ADI_BF506ADC1_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* IF (Build for C Langugage) */
#if defined(_LANGUAGE_C)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*==============  E X T E R N S  ===============*/

/*
** ADSP-BF506F ADC Entry point
*/
extern ADI_DEV_PDD_ENTRY_POINT  ADI_BF506ADC1_EntryPoint;

/* C-specific definitions  */

/*==============  E N U M E R A T I O N S  ===============*/

/*
** Enumerations for ADC driver specific Command IDs
*/
enum
{

    /* 0x40330000 - ADSP-BF506F ADC command enumeration start (defined in adi_dev.h) */
    ADI_BF506ADC1_CMD_START = ADI_BF506ADC1_ENUMERATION_START,

    /* 0x40330001 - Sets ACM Device number to control ADC
                    Value - u8 (ACM Device Number)
                    Default - ACM 0 */
    ADI_BF506ADC1_CMD_SET_ACM_DEV_NUMBER,

    /* 0x40330002 - Sets SPORT Device number connected to ADC
                    Value - u8 (SPORT Device Number)
                    Default - SPORT 0 */
    ADI_BF506ADC1_CMD_SET_SPORT_DEV_NUMBER,

    /* 0x40330003 - Sets Flag IDs of all ADC control signals and configures
                    the driver to control ADC via Flag pins
                    Value - address to structure of type ADI_BF506FADC1_CTRL_FLAG_PINS
                    Default - No Flag pins, uses ACM to control ADC */
    ADI_BF506ADC1_CMD_SET_ADC_CTRL_FLAG_PINS,

    /* 0x40330004 - Opens/Closes the device used to control ADC  (ACM or GPIO Flags)
                    Value - true/false ('true' to open, 'false' to close)
                    Default - Closed */
    ADI_BF506ADC1_CMD_OPEN_ADC_CTRL_DEV,

    /* 0x40330005 - Opens/Closes SPORT device connected to ADC
                    Value - true/false ('true' to open, 'false' to close)
                    Default - Closed */
    ADI_BF506ADC1_CMD_OPEN_SPORT_DEV,

    /* 0x40330006 - Sets the value/state of ADC control signals when the driver is
                    set to control ADC via GPIO flag pins
                    Value - address to structure of type ADI_BF506FADC1_CTRL_FLAG_STATE
                    Default - No Flag pins, uses ACM to control ADC */
    ADI_BF506ADC1_CMD_SET_ADC_CTRL_FLAG_STATE,

    /* 0x40330007 - Sets Serial data mode to receive ADC data
                    Value - Enumeration of type ADI_BF506FADC1_DATA_MODE
                    Default - ADI_BF506FADC1_DATA_DOUT_A_ONLY */
    ADI_BF506ADC1_CMD_SET_SERIAL_DATA_MODE,

    /* 0x40330008 - Sets ADC Operating mode
                    Value - enumeration of type ADI_BF506ADC1_OP_MODE
                    Default - ADI_BF506ADC1_MODE_POWERDOWN */
    ADI_BF506ADC1_CMD_SET_OPERATING_MODE,

    /* 0x40330009 - Sets ADC sampling rate / ACLK frequency
                    Value - u32 (Sampling rate / ACLK freq in Hertz)
                    Note: The value will be considered as
                          - ADC sample rate when driver is configured to use
                            Flag pins to control ADC
                          - ACLK Frequency when driver is configured to use ACM
                            to control ADC */
    ADI_BF506ADC1_CMD_SET_SAMPLE_RATE_ACLK_FREQ

    /*
    ** In addition to the above commands, application can issue
    ** SPORT driver specific commands defined in 'adi_sport.h' and
    ** ACM service specific commands defined in 'adi_acm'h'
    ** to configure/sense corresponding peripherals.
    ** Note that ACM commands are supported only when the ADC driver is
    ** configured to use ACM to control ADC
    */
};

/*
** Enumerations for ADC driver specific Return codes
*/

enum
{

    /* 0x40330000 - ADSP-BF506F ADC result enumeration start (defined in adi_dev.h) */
    ADI_BF506ADC1_RESULT_START = ADI_BF506ADC1_ENUMERATION_START,
    /* 0x40330001 - Results when the issued command is not supported */
    ADI_BF506ADC1_RESULT_CMD_NOT_SUPPORTED,
    /* 0x40330002 - Results when the issued command is supported, but
                    can not be processed at current stage */
    ADI_BF506ADC1_RESULT_CANNOT_PROCESS_CMD,
    /* 0x40330003 - Results when the issued Data mode is invalid */
    ADI_BF506ADC1_RESULT_DATA_MODE_INVALID,
    /* 0x40330004 - Results when the issued Operating mode is invalid */
    ADI_BF506ADC1_RESULT_OPERATING_MODE_INVALID,
    /* 0x40330005 - Results when the issued Sample Rate / ACLK Freq is invalid */
    ADI_BF506ADC1_RESULT_SAMPLE_RATE_ACLK_INVALID,
    /* 0x40330006 - Results when the issued Sample Rate / ACLK Freq is
         not supported by current SCLK */
    ADI_BF506ADC1_RESULT_SAMPLE_RATE_ACLK_NOT_SUPPORTED
};

/*
** Enumerations for ADC driver specific Event codes
*/

enum
{

    /* 0x40330000 - ADSP-BF506F ADC event enumeration start (defined in adi_dev.h) */
    ADI_BF506ADC1_EVENT_START = ADI_BF506ADC1_ENUMERATION_START

};

/*
** Enumerations of ADC data modes supported
*/
typedef enum __AdiBf506fadc1DataMode
{
    /*
    ** Note that regardless of the mode, the first two bits of
    ** each ADC sample will always be zero
    */

    /* Receive Data only from Data port A with no extended zeros (14-bits) */
    ADI_BF506FADC1_DATA_DOUT_A_ONLY = 0,
    /* Receive Data only from Data port A with extended zeros (16-bits) */
    ADI_BF506FADC1_DATA_DOUT_A_ONLY_XTND_ZERO,
    /* Receive (interleaved) data from Data from Port A and B using separate
       receive (Rx) channels with no extended zeros (14-bits) */
    ADI_BF506FADC1_DATA_DOUT_A_B_SEPERATE_RX,
    /* Receive (interleaved) data from Data from Port A and B using separate
       receive (Rx) channels with extended zeros (16-bits) */
    ADI_BF506FADC1_DATA_DOUT_A_B_SEPERATE_RX_XTND_ZERO,
    /* Receive (interleaved) data from Data from Port A and B using
       a single receive (Rx) channel with extended zeros (16-bits) */
    ADI_BF506FADC1_DATA_DOUT_A_B_SHARED_RX

} ADI_BF506FADC1_DATA_MODE;

/*
** Enumerations of ADC Operating mode
*/
typedef enum __AdcBf506fadc1OpMode
{
    /* Operate ADC in Normal mode */
    ADI_BF506ADC1_MODE_NORMAL = 0,
    /* Operate ADC in Partial Power-down mode */
    ADI_BF506ADC1_MODE_PARTIAL_POWERDOWN,
    /* Operate ADC in Complete Power-down mode */
    ADI_BF506ADC1_MODE_POWERDOWN

} ADI_BF506FADC1_OP_MODE;

/*==============  D A T A   S T R U C T U R E S  ===============*/

/*
** Structure to pass Flag IDs of all ADC control signals
*/
typedef struct __AdiBf506fadc1CtrlFlagPins
{
    /* ADC Channel select (A0) Flag */
    ADI_FLAG_ID     eA0Flag;

    /* ADC Channel select (A1) Flag */
    ADI_FLAG_ID     eA1Flag;

    /* ADC Channel select (A2) Flag */
    ADI_FLAG_ID     eA2Flag;

    /* ADC Logic select Flag */
    ADI_FLAG_ID     eRangeSelFlag;

    /* ADC Logic select Flag */
    ADI_FLAG_ID     eLogicSelFlag;

} ADI_BF506FADC1_CTRL_FLAG_PINS;

/*
** Structure to pass value/state of ADC control signals when
** the driver is configured to use Flag IDs to control ADC
*/
typedef struct __AdiBf506fadc1CtrlFlagState
{
    /* ADC Channel select (A0) Flag State
       'true' to set, 'false' to clear */
    bool    bSetA0;

    /* ADC Channel select (A1) Flag State
       'true' to set, 'false' to clear */
    bool    bSetA1;

    /* ADC Channel select (A2) Flag State
       'true' to set, 'false' to clear */
    bool    bSetA2;

    /* ADC Logic select Flag State
       'true' to set, 'false' to clear */
    bool    eSetRangeSel;

    /* ADC Logic select Flag State
       'true' to set, 'false' to clear */
    bool    eSetLogicSel;

} ADI_BF506FADC1_CTRL_FLAG_STATE;

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* IF _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /*__ADI_BF506ADC1_H__ */
