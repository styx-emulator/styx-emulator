/****************************************************************************
Copyright (c), 2010  - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: ADI System Services - ADC Control Module (ACM)

Description:
    This is the primary include file for ADC Control Module (ACM)

    This file defines enumerations and data structures specific to ACM

*****************************************************************************/
#ifndef __ADI_ACM_H__
#define __ADI_ACM_H__

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

/* C-specific definitions  */

/*==============  D E F I N E S  ===============*/

/* Maximum number of events supported by ACM
    ### THIS VALUE MUST NOT BE MODIFIED ### */
#define     ADI_ACM_MAX_EVENTS      (16u)

/* Handle to an ACM device */
typedef void    *ADI_ACM_DEV_HANDLE;

/*==============  E N U M E R A T I O N S  ===============*/

/*
** Enumerations for ACM Command IDs
*/
typedef enum __AdiAcmCommand
{

    /* 0x00110000 - ACM command enumeration start (defined in services.h) */
    ADI_ACM_CMD_START = ADI_ACM_ENUMERATION_START,

    /* 0x00110001 - Pass a command pair
                    Value = ADI_ACM_CMD_VALUE_PAIR*
                            (Address of a structure of type ADI_ACM_CMD_VALUE_PAIR) */
    ADI_ACM_CMD_PAIR,
    /* 0x00110002 - Pass a command pair table
                    Value = ADI_ACM_CMD_VALUE_PAIR*
                            (Address of a table of structure of type
                             ADI_ACM_CMD_VALUE_PAIR, terminated with ADI_ACM_CMD_END) */
    ADI_ACM_CMD_TABLE,
    /* 0x00110003 - End of command pair table
                    Value = NULL */
    ADI_ACM_CMD_END,

    /*
    ** ACM Register Configuration commands
    */

    /* 0x00110004 - Set ACM Control register value
                    Value = u32 */
    ADI_ACM_CMD_SET_CTRL_REG,
    /* 0x00110005 - Set Event control register corresponding to an event number
                    Value = ADI_ACM_EVENT_CONFIG*
                            (Address of a structure of type ADI_ACM_EVENT_CONFIG) */
    ADI_ACM_CMD_SET_EVENT_CTRL_REG,
    /* 0x00110006 - Configure time value register corresponding to an event number
                    Value = ADI_ACM_EVENT_CONFIG*
                            (Address of a structure of type ADI_ACM_EVENT_CONFIG) */
    ADI_ACM_CMD_SET_EVENT_TIME_REG,
    /* 0x00110007 - Configure a table of event numbers and its
                    corresponding control registers
                    Value = ADI_ACM_EVENT_CONFIG_TABLE*
                            (Address of a structure of type ADI_ACM_EVENT_CONFIG_TABLE) */
    ADI_ACM_CMD_SET_EVENT_CTRL_REG_TABLE,
    /* 0x00110008 - Configure a table of event numbers and its
                    corresponding time value registers
                    Value = ADI_ACM_EVENT_CONFIG_TABLE*
                            (Address of a structure of type ADI_ACM_EVENT_CONFIG_TABLE) */
    ADI_ACM_CMD_SET_EVENT_TIME_REG_TABLE,

    /*
    ** ACM Register Query commands
    */

    /* 0x00110009 - Get ACM Status register value
                    Value = u32* (Location to store status register value) */
    ADI_ACM_CMD_GET_STAT_REG,

    /*
    ** ACM Register Field configuration commands
    */

    /* 0x0011000A - Enable/Disable ACM
                    Value = true/false */
    ADI_ACM_CMD_ENABLE_ACM,
    /* 0x0011000B - Enable selected event
                    Value = u8 (Event number to enable) */
    ADI_ACM_CMD_ENABLE_EVENT,
    /* 0x0011000C - Disable selected event
                    Value = u8 (Event number to disable) */
    ADI_ACM_CMD_DISABLE_EVENT,
    /* 0x0011000D - Configure ACM Timer specific fields
                    Value = ADI_ACM_TMR_CONFIG *
                    (Address of a structure of type ADI_ACM_TMR_CONFIG) */
    ADI_ACM_CMD_CONFIG_TMR,
    /* 0x0011000E - Chip Select / Start Conversion (CS) polarity
                    Value = 0 or 1 (0 for Active low, 1 for Active high) */
    ADI_ACM_CMD_SET_CS_POL,
    /* 0x0011000F - ADC Clock (ACLK) polarity after CS gets activated
                    Value = 0 or 1 (0 for falling edge, 1 for raising edge) */
    ADI_ACM_CMD_SET_ADC_CLK_POL,
    /* 0x00110010 - External Peripheral Select
                    Accepted values = 0, 1 */
    ADI_ACM_CMD_SET_EXT_PERIPHERAL_SEL,
    /* 0x00110011 - Enable event completion interrupt for given event number
                    Value = u8 (Event number) */
    ADI_ACM_CMD_ENABLE_EVENT_COMPLETE_INT,
    /* 0x00110012 - Disable event completion interrupt for given event number
                    Value = u8 (Event number) */
    ADI_ACM_CMD_DISABLE_EVENT_COMPLETE_INT,
    /* 0x00110013 - Enable Event missed interrupt for given event number
                    Value = u8 (Event number) */
    ADI_ACM_CMD_ENABLE_EVENT_MISS_INT,
    /* 0x00110014 - Disable event missed interrupt for given event number
                    Value = u8 (Event number) */
    ADI_ACM_CMD_DISABLE_EVENT_MISS_INT,
    /* 0x00110015 - Command to pass all parameters applicable to an event
                    Value = ADI_ACM_EVENT_PARAMS*
                    (Address of a structure of type ADI_ACM_EVENT_PARAMS) */
    ADI_ACM_CMD_SET_EVENT_PARAMS,
    /* 0x00110016 - Command to pass a table of event parameters
                    Value = ADI_ACM_EVENT_PARAMS_TABLE*
                    (Address of a structure of type ADI_ACM_EVENT_PARAMS_TABLE) */
    ADI_ACM_CMD_SET_EVENT_PARAMS_TABLE,
    /* 0x00110017 - Set ACM Clock frequency (Clock output for ADC and SPORT)
                    Value = u32 (Frequency in Hertz) */
    ADI_ACM_CMD_SET_ACLK_FREQ,
    /* 0x00110018 - Set ACM Clock Divisor
                    Value = u8 (Clock Divisor - 0 to 255) */
    ADI_ACM_CMD_SET_ACLK_DIVISOR,
    /* 0x00110019 - Set setup cycle time in terms of SCLK
                    Value = u16 (Number of SCLKs - between 1 and 256 for MOY) */
    ADI_ACM_CMD_SET_SETUP_CYCLES,
    /* 0x0011001A - Set Chip Select/Start Conversion (CS) Width in terms of ACLK
                    Active duration of active CS in ACLK cycles
                    Value = u16 (Number of ACLKs - between 1 and 256 for MOY) */
    ADI_ACM_CMD_SET_CS_WIDTH,
    /* 0x0011001B - Set Hold Cycles in terms of ACLK (Hold in ACLK cycles after
                    the inactive edge of CS for all ADC controls)
                    Value = u8 (Number of ACLKs - between 0 and 15 for MOY) */
    ADI_ACM_CMD_SET_HOLD_CYCLES,
    /* 0x0011001C - Set Zero Cycles in terms of ACLK (Zero duration (driven low)
                    in ACLK cycles for all ADC controls)
                    Value = u8 (Number of ACLKs - between 0 and 15 for MOY) */
    ADI_ACM_CMD_SET_ZERO_CYCLES,

    /*
    ** ACM Register Field Query commands
    */

    /* 0x0011001D - Get status of a particular event number
                    Value = ADI_ACM_EVENT_STAT*
                           (Address of a structure of type ADI_ACM_EVENT_STAT) */
    ADI_ACM_CMD_GET_EVENT_STAT,
    /* 0x0011001E - Query if all events related to current trigger is completed
                    Value = bool* (Pointer to a boolen type to store ACM status)
                            ('true' when all enabled events of current trigger completed
                             'false' on pending incomplete events) */
    ADI_ACM_CMD_GET_EVENT_COMPLETE_STAT,
    /* 0x0011001F - Query if any events related to current trigger was missed
                    Value = bool* (Pointer to a boolen type to store ACM status)
                            ('true' when ACM has missed event(s))
                             'false' when no events are missed) */
    ADI_ACM_CMD_GET_EVENT_MISS_STAT,
    /* 0x00110020 - Gets a list of event numbers that are completed/done
                    Value = ADI_ACM_EVENT_LIST*
                            (Address of a structure of type ADI_ACM_EVENT_LIST) */
    ADI_ACM_CMD_GET_EVENT_COMPLETE_LIST,
    /* 0x00110021 - Gets a list of event numbers missed
                    Value = ADI_ACM_EVENT_LIST*
                            (Address of a structure of type ADI_ACM_EVENT_LIST) */
    ADI_ACM_CMD_GET_EVENT_MISS_LIST,

    /*
    ** Callback control commands
    */

    /* 0x00110022 - Set Application callback function
                    Value = ADI_DCB_CALLBACK_FN */
    ADI_ACM_CMD_SET_CALLBACK_FN,
    /* 0x00110023 - Set Callback parameter passed to
                    Application callback function
                    Value = void* */
    ADI_ACM_CMD_SET_CALLBACK_PARAM,
    /* 0x00110024 - Set Deferred Callback manager handle
                    Value = of type ADI_DCB_HANDLE or NULL */
    ADI_ACM_CMD_SET_DCB_MANAGER_HANDLE

} ADI_ACM_COMMAND;

/*
** Enumerations for ACM Result codes
*/
typedef enum __AdiAcmResult
{
    /* Generic success */
    ADI_ACM_RESULT_SUCCESS  = 0,
    /* Generic failure */
    ADI_ACM_RESULT_FAILED   = 1,

    /* 0x00110000 - ACM Specific return codes (defined in services.h) */
    ADI_ACM_RESULT_START    = ADI_ACM_ENUMERATION_START,
    /* 0x00110001 - ACM has been initialised and already in use */
    ADI_ACM_RESULT_ALREADY_IN_USE,
    /* 0x00110002 - ACM device handle is invalid */
    ADI_ACM_RESULT_BAD_HANDLE,
    /* 0x00110003 - ACM device number is invalid */
    ADI_ACM_RESULT_BAD_DEVICE_NUMBER,
    /* 0x00110004 - Given command is invalid/not recognised by ACM */
    ADI_ACM_RESULT_COMMAND_INVALID,
    /* 0x00110005 - ACM device does not have a valid callback function
                    to report interrupts to application */
    ADI_ACM_RESULT_CALLBACK_FN_INALID,
    /* 0x00110006 - Issued command is not permitted at this stage */
    ADI_ACM_RESULT_COMMAND_NOT_PERMITTED,
    /* 0x00110007 - Issued Event number is invalid */
    ADI_ACM_RESULT_EVENT_NUMBER_INVALID,
    /* 0x00110008 - Issued ACM Timer Number is invalid */
    ADI_ACM_RESULT_TIMER_NUMBER_INVALID,
    /* 0x00110009 - Issued ACM Timer configuration is invalid */
    ADI_ACM_RESULT_TIMER_CONFIG_INVALID,
    /* 0x0011000A - Issued Event parameter configuration is invalid */
    ADI_ACM_RESULT_EVENT_PARAM_INVALID,
    /* 0x0011000B - Issued ACM External Peripheral ID is invalid */
    ADI_ACM_RESULT_EXT_PERIPHERAL_INVALID,
    /* 0x0011000C - Issued ACLK frequency is out of range and can't be supported */
    ADI_ACM_RESULT_ACLK_OUT_OF_RANGE,
    /* 0x0011000D - Issued ACLK frequency can't be derived from current SCLK */
    ADI_ACM_RESULT_CANNOT_DERIVE_ACLK,
    /* 0x0011000E - Issued ACLK Divisor is invalid */
    ADI_ACM_RESULT_CLKDIV_INVALID,
    /* 0x0011000F - Issued ACM Setup cycle value is invalid */
    ADI_ACM_RESULT_SETUP_CYCLES_INVALID,
    /* 0x00110010 - Issued CS Width value is invalid */
    ADI_ACM_RESULT_CS_WIDTH_INVALID,
    /* 0x00110011 - Issued Hold Cycles value is invalid */
    ADI_ACM_RESULT_HOLD_CYCLES_INVALID,
    /* 0x00110012 - Issued Zero Cycles value is invalid */
    ADI_ACM_RESULT_ZERO_CYCLES_INVALID,
    /* 0x00110013 - Failed to Hook ACM Status interrupt to interrupt manager */
    ADI_ACM_RESULT_INT_HOOK_FAILED,
    /* 0x00110014 - Failed to Unhook ACM Status interrupt from interrupt manager */
    ADI_ACM_RESULT_INT_UNHOOK_FAILED,
    /* 0x00110015 - Failed to configure ports for ACM */
    ADI_ACM_RESULT_PORT_CONTROL_FAILED,
    /* 0x00110016 - Failed to get present system clock frequency */
    ADI_ADC_RESULT_GET_SCLK_FAILED

} ADI_ACM_RESULT;

/*
** Enumerations for ACM Event IDs
*/
typedef enum __AdiAcmEvents
{

    /* 0x00110000 - ACM Event start */
    ADI_ACM_EVENT_START    = ADI_ACM_ENUMERATION_START,
    /* 0x00110001 - Reports completion of a particular event
                    Argument = u8 (Event number completed) */
    ADI_ACM_EVENT_EVENT_COMPLETE,
    /* 0x00110001 - Reports when an event was missed
                    Argument = u8 (Event number missed) */
    ADI_ACM_EVENT_EVENT_MISS

} ADI_ACM_EVENT;

/*==============  D A T A   S T R U C T U R E S  ===============*/

/*
** Command - Value Pair structure
*/
typedef struct ADI_ACM_CMD_VALUE_PAIR
{
    /* Command ID */
    ADI_ACM_COMMAND     eCommandID;

    /* Command specific value */
    void                *Value;

} ADI_ACM_CMD_VALUE_PAIR;


/*
** Structure to pass ACM Timer specific configuration values
*/
typedef struct __AdiAcmTmrConfig
{

    /* Timer number to configure
       Accepted values = 0, 1 */
    u8      nTmrNumber;

    /* Flag to enable/disable Timer
       'true' to enable, 'false' to disable */
    bool    bEnable;

    /* Trigger select value
       Accepted values = between 0 and 3 (inclusive) */
    u8      nTriggerSelect;

    /* Trigger polarity value
       Accepted values = 0 or 1 (0 for raising edge, 1 for falling edge) */
    u8      nTriggerPolarity;

} ADI_ACM_TMR_CONFIG;

/*
** Structure to configure a register/register field corresponding to an event
*/
typedef struct __AdiAcmEventConfig
{

    /* Holds the Event number to configure */
    u8      nEventNumber;

    /* Configuration value of the register/register field
       corresponding to the event number */
    u32     nConfigValue;

} ADI_ACM_EVENT_CONFIG;

/*
** Structure to configure a table of registers/register fields corresponding to
** specfied event numbers
*/
typedef struct __AdiAcmEventConfigTable
{

    /* Number of Event register/register field configuration enteries */
    u32                     nNumEntries;

    /* Pointer to an array of event register/register field configurations with
       number of entries mentioned above */
    ADI_ACM_EVENT_CONFIG    *paConfig;

} ADI_ACM_EVENT_CONFIG_TABLE;

/*
** Structure to pass configure fields related to a particular event
*/
typedef struct __AdiAcmEventParams
{

    /* Event number to configure
       Accepted values = between 0 and 15 (inclusive) */
    u8      nEventNumber;

    /* Flag to enable/disable event ('true' to enable, 'false' to disable) */
    bool    bEnable;

    /* ADC Channel select value
       Accepted values = between 0 and 7 (inclusive) */
    u8      nAdcCannelSelect;

    /* ADC Range
       Accepted values = 0, 1 */
    u8      nRange;

    /* ADC Logic
       Accepted values = 0, 1 */
    u8      nLogic;

    /* Time value to execute the corresponding event */
    u32     nTime;

} ADI_ACM_EVENT_PARAMS;

/*
** Structure to configure a table of events and its fields
*/
typedef struct __AdiAcmEventParamsTable
{

    /* Number of Event parameter configuration enteries */
    u32                     nNumEntries;

    /* Pointer to an array of event - parameter configurations with
       number of entries mentioned above */
    ADI_ACM_EVENT_PARAMS    *paEventParams;

} ADI_ACM_EVENT_PARAMS_TABLE;

/*
** Structure to Query current status of an event
*/
typedef struct __AdiAcmEventStat
{

    /* Holds the Event number to query
       Accepted values = between 0 and 15 (inclusive) */
    u8      nEventNumber;

    /* returns 'true' when conversion is completed, 'false' otherwise */
    bool    bIsCompleted;

    /* returns 'true' when event is missed, 'false' otherwise */
    bool    bIsMissed;

    /* returns 'true' when this is the current event in progress, 'false' otherwise */
    bool    bIsCurrent;

} ADI_ACM_EVENT_STAT;

/*
** Structure to get the list of event numbers that are
** processed or missed (based on the given command)
*/
typedef struct __AdiAcmEventList
{

    /* Number of valid event number entries in the below list */
    u32     nNumEntries;

    /* Pointer to an array that can support ADI_ACM_MAX_EVENTS entries
       ACM service will fill this array with valid event numbers that are
       completed or missed */
    u8      *paEventList;

} ADI_ACM_EVENT_LIST;

/*=======  P U B L I C   P R O T O T Y P E S  ========*/
/*            (globally-scoped functions)             */
/*
**  Function: adi_acm_Open
**
**      Opens an ADC Control Module (ACM) device
**
**  Parameters:
**      nDeviceNumber       - Physical ACM Device number to open
**      pCriticalRegionArg  - Critical region parameter
**      phAcmDevice         - Pointer to location to store handle
**                            to this ACM device
*/
ADI_ACM_RESULT  adi_acm_Open (
    u32                     nDeviceNumber,
    void                    *pCriticalRegionArg,
    ADI_ACM_DEV_HANDLE      *phAcmDevice
);

/*
**  Function: adi_acm_Close
**
**      Closes an ADC Control Module (ACM) device
**
**  Parameters:
**      hAcmDevice - Handle to an active ACM device to close
*/
ADI_ACM_RESULT  adi_acm_Close (
    ADI_ACM_DEV_HANDLE      hAcmDevice
);

/*
**  Function: adi_acm_Control
**
**      Set/Sense ADC Control Module (ACM) device specific settings
**
**  Parameters:
**      hAcmDevice - Handle to an active ACM device to set/sense
**      nCommandID - ACM specific command ID to process
**      pValue     - Command specific value
*/
ADI_ACM_RESULT  adi_acm_Control (
    ADI_ACM_DEV_HANDLE      hAcmDevice,
    ADI_ACM_COMMAND         eCommandID,
    void                    *pValue
);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* IF _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /*__ADI_ACM_H__ */
