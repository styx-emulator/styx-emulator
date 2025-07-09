/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

$RCSfile: adi_pwm.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

File:
    'adi_pwm.h'

Description:

    Header file containing Pulse Width Modulation unit API in the System Services Library.
    This file contains prototypes for the following functions:

        adi_pwm_Init
        adi_pwm_Terminate
        adi_pwm_InstallCallback
        adi_pwm_RemoveCallback
        adi_pwm_Control

    These functions are only supported for ADSP-BF51x

********************************************************************************/

#ifndef __ADI_PWM_H__
#define __ADI_PWM_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)



/******************************************************************

  Enumerations for PWM RESULT CODES

  ******************************************************************/

typedef enum ADI_PWM_RESULT
{
    ADI_PWM_RESULT_SUCCESS=0,                       /* Generic success */
    ADI_PWM_RESULT_FAILED=1,                        /* Generic failure */
    ADI_PWM_RESULT_START=ADI_PWM_ENUMERATION_START, /* defined in services.h */
    ADI_PWM_RESULT_INVALID_EVENT_ID,                /* (0x0001) The specified Event ID does not exist */
    ADI_PWM_RESULT_INTERRUPT_MANAGER_ERROR,         /* (0x0002) Error returned from interrupt manager */
    ADI_PWM_RESULT_ERROR_REMOVING_CALLBACK,         /* (0x0003) Can't find callback for given ID      */
    ADI_PWM_RESULT_NOT_INITIALIZED,                 /* (0x0004) PWM service has not been initialized  */
    ADI_PWM_RESULT_CALLBACK_NOT_INSTALLED,          /* (0x0005) The specified callback was never installed    */
    ADI_PWM_RESULT_SERVICE_NOT_SUPPORTED,           /* (0x0006) PWM service not supported for this processor  */
    ADI_PWM_RESULT_ALREADY_INITIALIZED,             /* (0x0007) Service has already been initialized   */
    ADI_PWM_RESULT_CALLBACK_ALREADY_INSTALLED,      /* (0x0008) Cannot install the same callback twice */
    ADI_PWM_RESULT_INVALID_COMMAND,                 /* (0x0009) The specified Command does not exist   */
    ADI_PWM_RESULT_INVALID_CHANNEL,                 /* (0x000A) The specified channel does not exst         */
    ADI_PWM_RESULT_INVALID_ENABLE_STATUS,           /* Invalid parameter passed with enable/disable command */
    ADI_PWM_RESULT_INVALID_DUTY_CYCLE,              /* Invalid duty cycle                              */
    ADI_PWM_RESULT_INVALID_DEAD_TIME,               /* Invalid switching dead time                     */
    ADI_PWM_RESULT_INVALID_PERIOD,                  /* Invalid period for sync pulse                   */
    ADI_PWM_RESULT_INVALID_PULSE_WIDTH,             /* Invalid pulse width for a signal                */
    ADI_PWM_RESULT_INVALID_CROSSOVER,               /* Invalid crossover mode                          */
    ADI_PWM_RESULT_INVALID_POLARITY,                /* Invalid polarity for a signal                   */
    ADI_PWM_RESULT_INVALID_GATE_CHOPPING_FREQ,      /* Invalid gate drive chopping mode/frequency      */
    ADI_PWM_RESULT_INVALID_GATE_ENABLE,             /* Invalid argument passed with gate chopping enable command   */
    ADI_PWM_RESULT_INVALID_LOW_SIDE_INVERT,         /* Invalid parameter passed with Low Side Invert command       */
    ADI_PWM_RESULT_INVALID_SWITCH_RELUCTANCE,       /* Invalid switch reluctance mode                              */
    ADI_PWM_RESULT_INVALID_SYNC_INT_ENABLE,         /* Invalid parameter passed with sync pulse interrupt command  */
    ADI_PWM_RESULT_INVALID_SYNC_SOURCE,             /* Invalid parameter passed with sync pulse source command     */
    ADI_PWM_RESULT_INVALID_SYNC_SEL,                /* Invalid external Sync Select                                */
    ADI_PWM_RESULT_INVALID_SYNC_OUT_ENABLE,         /* Invalid parameter passed with Sync Pulse Output Enable Command */
    ADI_PWM_RESULT_INVALID_TRIP_INT_ENABLE,         /* Invalid parameter passed with Trip pulse interrupt Command     */
    ADI_PWM_RESULT_INVALID_UPDATE_MODE,             /* Invalid PWM Operating Mode                     */
    ADI_PWM_RESULT_INVALID_PWM_ENABLE,              /* Invalid PWM Enable status                      */
    ADI_PWM_RESULT_PERIOD_NOT_SET,                  /* Period was not passed to adi_pwm_Init          */
    ADI_PWM_RESULT_DEAD_TIME_NOT_SET,               /* Dead time was not passed to adi_pwm_Init                      */
    ADI_PWM_RESULT_DUTY_CYCLE_A_NOT_SET,            /* Duty cycle was not passed to adi_pwm_Init for channel A       */
    ADI_PWM_RESULT_DUTY_CYCLE_B_NOT_SET,            /* Duty cycle was not passed to adi_pwm_Init for channel B       */
    ADI_PWM_RESULT_DUTY_CYCLE_C_NOT_SET,            /* Duty cycle was not passed to adi_pwm_Init for channel C       */
    ADI_PWM_RESULT_SYNC_PULSE_WIDTH_NOT_SET,        /* Sync pulse width was not passed to adi_pwm_Init               */
    ADI_PWM_RESULT_OPERATING_MODE_NOT_SET,          /* Operating mode was not passed to adi_pwm_Init                 */
    ADI_PWM_RESULT_CHANNEL_ENABLE_NOT_SET,          /* Channel enable command was not passed to adi_pwm_Init         */
    ADI_PWM_RESULT_POLARITY_NOT_SET,                /* Polarity was not passed to adi_pwm_Init                       */
    ADI_PWM_RESULT_SWITCH_RELUCTANCE_IS_ACTIVE,     /* Command is meaningless in switch reluctance mode              */
    ADI_PWM_RESULT_SWITCH_RELUCTANCE_NOT_ACTIVE,    /* Command is meaningless when not in switch reluctance mode     */
    ADI_PWM_RESULT_PORT_MUX_MAPPING_NOT_SET,        /* Port Mux Mapping was not passed to adi_pwm_Init */
    ADI_PWM_RESULT_INVALID_IVG,                     /* Invalid IVG specified for event                 */
    ADI_PWM_RESULT_INVALID_PWM_NUMBER               /* Invalid PWM Enable status                       */
} ADI_PWM_RESULT;


/*********************************************************************************

  Enumerations for PWM Command values

*********************************************************************************/

typedef enum ADI_PWM_COMMAND
{
    ADI_PWM_CMD_START=ADI_PWM_ENUMERATION_START,   /* defined in services.h */
    ADI_PWM_CMD_END,                    /* end of a command pair table                              */
    ADI_PWM_CMD_PAIR,                   /* passing a command pair                                   */
    ADI_PWM_CMD_TABLE,                  /* passing a command pair table                             */

/* Commands to set register values */

    ADI_PWM_CMD_SET_CHANNEL_ENABLE,    /* enable a PWM signal channel in PWMSEG register           */
    ADI_PWM_CMD_SET_DUTY_CYCLE,         /* set the duty cycle in PWMCHA, PWMCHB, PWMCHC Registers   */
    ADI_PWM_CMD_SET_DEAD_TIME,          /* set dead time for a signal in PWMDT Register             */
    ADI_PWM_CMD_SET_PERIOD,             /* set the period for a signal in PWMTM Register            */
    ADI_PWM_CMD_SET_SYNC_PULSE_WIDTH,   /* set sync pulse width in PWMSYNCWT    register            */
    ADI_PWM_CMD_SET_CROSSOVER,          /* enable/disable crossover for a channel PWMSEG register   */
    ADI_PWM_CMD_SET_POLARITY,           /* set the polarity for all signals in PWMCTRL reg          */
    ADI_PWM_CMD_SET_GATE_CHOPPING_FREQ, /* set gate drive chopping frequency in PWMGATE             */
    ADI_PWM_CMD_SET_GATE_ENABLE_LOW,    /* enable/disable gate chopping for low side - PWMGATE      */
    ADI_PWM_CMD_SET_GATE_ENABLE_HIGH,   /* enable/disable gate chopping for high side - PWMGATE     */
    ADI_PWM_CMD_SET_LOW_SIDE_INVERT,    /* set Low Side Invert in PWMLSI reg, for a given channel   */
    ADI_PWM_CMD_SET_SWITCH_RELUCTANCE,  /* enable/disable switch reluctance mode  in PWMCTRL        */
    ADI_PWM_CMD_SET_SYNC_INT_ENABLE,    /* enables/disables sync pulse interrupt input in PWMCTRL   */
    ADI_PWM_CMD_SET_SYNC_SOURCE,        /* set sync pulse source to internal/external in PWMCTRL    */
    ADI_PWM_CMD_SET_SYNC_SEL,           /* set external Sync Select 0=asynch, 1=sync def=1          */
    ADI_PWM_CMD_SET_SYNC_OUT_ENABLE,    /* enable/disable SyncEnable in PWMCTRL-pulse on output pin */
    ADI_PWM_CMD_SET_TRIP_INT_ENABLE,    /* enables/disables trip pulse interrupt input in PWMCTRL   */
    ADI_PWM_CMD_SET_TRIP_INPUT_ENABLE,  /* enable/disable Trip Input  1=disabled, 0=enabled def=0   */
    ADI_PWM_CMD_SET_UPDATE_MODE,        /* set PWM Operating Mode in PWMCTRL - single/double update */
    ADI_PWM_CMD_SET_PWM_ENABLE,         /* software shutdown all 6 channels to PWMCTRL              */
    ADI_PWM_CMD_CLEAR_SYNC_INT,         /* set W1C to clear SYNC in PWMSTAT                         */
    ADI_PWM_CMD_CLEAR_TRIP_INT,         /* set W1C to clear TRIP in PWMSTAT                         */
    ADI_PWM_CMD_SET_TRIP_IVG,           /* Change the IVG level of the Trip interrupt               */
    ADI_PWM_CMD_SET_SYNC_IVG,           /* Change the IVG level of the Sync interrupt               */
    ADI_PWM_CMD_SET_PORT_MUX,           /* select between primary and secondary port mux mapping    */

/* Commands to sense register values */

    ADI_PWM_CMD_GET_CHANNEL_ENABLE,     /* get enable status of a channel from PWMSEG                */
    ADI_PWM_CMD_GET_DUTY_CYCLE,         /* get the duty cycle in PWMCHA, PWMCHB, PWMCHC Registers    */
    ADI_PWM_CMD_GET_DEAD_TIME,          /* get dead time for a signal from PWMDT Register            */
    ADI_PWM_CMD_GET_PERIOD,             /* get the period for a signal from PWMTM Register           */
    ADI_PWM_CMD_GET_SYNC_PULSE_WIDTH,   /* get sync pulse width in PWMSYNCWT    register             */
    ADI_PWM_CMD_GET_CROSSOVER,          /* get crossover mode  for a channel PWMSEG register         */
    ADI_PWM_CMD_GET_POLARITY,           /* get PWM polarity - PWMSTAT 1=active hi, 0=active lo def=0 */
    ADI_PWM_CMD_GET_GATE_CHOPPING_FREQ, /* get gate drive chopping frequency from PWMGATE            */
    ADI_PWM_CMD_GET_GATE_ENABLE_LOW,    /* get gate chopping enable status for low side from PWMGATE */
    ADI_PWM_CMD_GET_GATE_ENABLE_HIGH,   /* get gate chopping enable status for low side from PWMGATE */
    ADI_PWM_CMD_GET_LOW_SIDE_INVERT,    /* get Low Side Invert  in PWMLSI register                   */
    ADI_PWM_CMD_GET_SWITCH_RELUCTANCE,  /* get SR mode - PWMSTAT (PWM_SRMODEB??) 0=active, 1-not active def=0    */
    ADI_PWM_CMD_GET_SYNC_INT,           /* get sync interrupt from PWMSTAT W1C def=0                 */
    ADI_PWM_CMD_GET_SYNC_SOURCE,        /* get sync pulse source (internal or external) PWMCTRL      */
    ADI_PWM_CMD_GET_SYNC_SEL,           /* get extern Sync Select  0=asynch, 1=sync def=1            */
    ADI_PWM_CMD_GET_TRIP_INT,           /* get trip interrupt in PWMSTAT HW Pin, or SW  W1C, def=0   */
    ADI_PWM_CMD_GET_UPDATE_MODE,        /* get PWM Operating Mode from PWMSTAT- single/double update */
    ADI_PWM_CMD_GET_PWM_ENABLE,         /* get software shutdown status (all 6 channel disable)      */
    ADI_PWM_CMD_GET_PHASE,              /* get PWM phase from PWMSTAT, 0=1st half, 1=2nd half  def=0 */
    ADI_PWM_CMD_GET_TRIP_PIN,           /* get trip pin value in PWMSTAT                             */
    ADI_PWM_CMD_GET_OUTPUT              /* get output signal from PWMSTAT2                           */

} ADI_PWM_COMMAND;



/*********************************************************************************

  enumeration for PWM MUX setting (primary or secondary)

*********************************************************************************/

typedef enum ADI_PWM_PORT_MUX
{
    ADI_PWM_MUX_PRI,     /* primary port mapping */
    ADI_PWM_MUX_SEC      /* secondary port mapping */
} ADI_PWM_PORT_MUX;


/*********************************************************************************

  Port multiplexing PWM structure

*********************************************************************************/

typedef struct ADI_PWM_PORT_MAP
{

#if defined(__ADSP_MOY__)

    u32 AH_0_MUX:1;
    u32 AL_0_MUX:1;
    u32 BH_0_MUX:1;
    u32 BL_0_MUX:1;
    u32 CH_0_MUX:1;
    u32 CL_0_MUX:1;
    u32 SYNC_0_MUX:1;
    u32 TRIP_0_MUX:1;
    u32 AH_1_MUX:1;
    u32 AL_1_MUX:1;
    u32 BH_1_MUX:1;
    u32 BL_1_MUX:1;
    u32 CH_1_MUX:1;
    u32 CL_1_MUX:1;
    u32 SYNC_1_MUX:1;
    u32 TRIP_1_MUX:1;
#else
    u32 AH_MUX:1;
    u32 AL_MUX:1;
    u32 BH_MUX:1;
    u32 BL_MUX:1;
    u32 CH_MUX:1;
    u32 CL_MUX:1;
    u32 SYNC_MUX:1;
    u32 TRIP_MUX:1;
#endif

} ADI_PWM_PORT_MAP,  * pADI_PWM_PORT_MAP;



/*********************************************************************************

  Command Pair structure

*********************************************************************************/

typedef struct ADI_PWM_COMMAND_PAIR
{
    ADI_PWM_COMMAND kind;
    void* value;
} ADI_PWM_COMMAND_PAIR;



#if defined(__ADSP_MOY__)
/*********************************************************************************

 PWM Number - Used to select which PWM a command is for (0 or 1)
*********************************************************************************/
typedef enum ADI_PWM_NUMBER
{
    ADI_PWM_0,    /* PWM0 */
    ADI_PWM_1,    /* PWM1 */
    ADI_NUM_PWM
} ADI_PWM_NUMBER;

#endif

/*********************************************************************************

  enumeration for PWM channels

*********************************************************************************/

typedef enum ADI_PWM_CHANNEL
{

    ADI_PWM_CHANNEL_CH,    /* high side output channel A   */
    ADI_PWM_CHANNEL_CL,    /* low side output channel B   */
    ADI_PWM_CHANNEL_BH,    /* high side output channel B   */
    ADI_PWM_CHANNEL_BL,    /* low side output channel B  */
    ADI_PWM_CHANNEL_AH,    /* high side output channel A  */
    ADI_PWM_CHANNEL_AL,    /* low side output channel A   */

    ADI_PWM_CHANNEL_C,    /*   channel pair C  */
    ADI_PWM_CHANNEL_B,    /*   channel pair B */
    ADI_PWM_CHANNEL_A,    /*   channel pair A */

    ADI_PWM_CHANNEL_ALL     /* applies to all channels */

} ADI_PWM_CHANNEL;




/*********************************************************************

  Enumerations for PWM Event IDs

 *********************************************************************/
typedef enum ADI_PWM_EVENT_ID
{
    ADI_PWM_EVENT_START=ADI_PWM_ENUMERATION_START,   /* defined in services.h  */

#if defined(__ADSP_MOY__)
    ADI_PWM0_EVENT_TRIP,
    ADI_PWM0_EVENT_SYNC,
    ADI_PWM1_EVENT_TRIP,
    ADI_PWM1_EVENT_SYNC,
#else
    ADI_PWM_EVENT_TRIP,
    ADI_PWM_EVENT_SYNC,
#endif
    ADI_PWM_EVENT_LAST
}   ADI_PWM_EVENT_ID;

#define ADI_PWM_MAX_EVENTS (u32)(ADI_PWM_EVENT_LAST - ADI_PWM_ENUMERATION_START)-1

/*********************************************************************************

 PWM Enable/Disable status
 Use to enable or disable channels, gate chopping, switch reluctance,
 Sync and Trip interrupts.  WHen this is the only parameter passed, with a
 command, for multiple PWMs, it is also used to determine which PWM.

*********************************************************************************/

#if defined(__ADSP_MOY__)



typedef enum ADI_PWM_ENABLE_STATUS
{
    ADI_PWM_DISABLE = 0,
    ADI_PWM0_DISABLE = 0,          /* Disable just PWM0    */
    ADI_PWM_ENABLE = 1,
    ADI_PWM0_ENABLE = 1,           /* Enable just PWM0    */
    ADI_PWM1_DISABLE,          /* Disable just PWM1   */
    ADI_PWM1_ENABLE            /* Enable just PWM1   */
} ADI_PWM_ENABLE_STATUS, pADI_PWM_ENABLE_STATUS;

#else

typedef enum ADI_PWM_ENABLE_STATUS
{
    ADI_PWM_DISABLE,           /* Disable - used as 0  */
    ADI_PWM_ENABLE             /* Enable  - used as 1  */
} ADI_PWM_ENABLE_STATUS, pADI_PWM_ENABLE_STATUS;

#endif

/*********************************************************************************

 PWM Internal/External Sync Pulse Source
 Use to set   ADI_PWM_EXTSYNC

*********************************************************************************/
typedef enum ADI_PWM_SYNC_SOURCE
{

#if defined(__ADSP_MOY__)
    ADI_PWM0_SYNC_SOURCE_INTERNAL,     /* internal sync source */
    ADI_PWM0_SYNC_SOURCE_EXTERNAL,     /* external sync source */
    ADI_PWM1_SYNC_SOURCE_INTERNAL,     /* internal sync source */
    ADI_PWM1_SYNC_SOURCE_EXTERNAL      /* external sync source */
#else
    ADI_PWM_SYNC_SOURCE_INTERNAL,     /* internal sync source */
    ADI_PWM_SYNC_SOURCE_EXTERNAL      /* external sync source */
#endif
} ADI_PWM_SYNC_SOURCE;


/*********************************************************************************

 PWM External Sync Pulse Source Select to set
 ADI_PWM_SYNCSEL to synchronous / asynchronous

*********************************************************************************/
typedef enum ADI_PWM_SYNC_SELECT
{
#if defined(__ADSP_MOY__)
    ADI_PWM0_SYNC_ASYNCH,    /* PWM 0 external sync source is asynchronous*/
    ADI_PWM0_SYNC_SYNCH,      /* PWM 0 external sync source is synchronous */
    ADI_PWM1_SYNC_ASYNCH,    /* PWM 1 external sync source is asynchronous*/
    ADI_PWM1_SYNC_SYNCH       /* PWM 1 external sync source is synchronous */
#else
    ADI_PWM_SYNC_ASYNCH,    /* external sync source is asynchronous*/
    ADI_PWM_SYNC_SYNCH      /* external sync source is synchronous */
#endif
} ADI_PWM_SYNC_SELECT;


/*********************************************************************************

 PWM Polariy - Used to set the polarity for all signals in PWMCTRL register.

*********************************************************************************/
typedef enum ADI_PWM_POLARITY
{

#if defined(__ADSP_MOY__)
    ADI_PWM0_POLARITY_LOW,    /* PWM 0 polarity low  */
    ADI_PWM0_POLARITY_HIGH,   /* PWM 0 polarity high (hardware default)  */
    ADI_PWM1_POLARITY_LOW,    /* PWM 1 polarity low  */
    ADI_PWM1_POLARITY_HIGH    /* PWM 1 polarity high(hardware default)  */
#else
    ADI_PWM_POLARITY_LOW,    /* polarity low                      */
    ADI_PWM_POLARITY_HIGH    /* polarity high (hardware default)  */
#endif
} ADI_PWM_POLARITY;




/********************************************************************************
   Structure to pass along with the commands ADI_PWM_CMD_SET_CHANNEL_ENABLE,
   ADI_PWM_CMD_SET_CROSSOVER, ADI_PWM_CMD_SET_LOW_SIDE_INVERT to the adi_pwm_Init
   or adi_pwm_Control functions.  Enables channel to be combined with channel
   specific enable status.

*********************************************************************************/

typedef struct ADI_PWM_CHANNEL_STATUS
{

    ADI_PWM_CHANNEL        Channel;        /* a channel or a channel pair */
    ADI_PWM_ENABLE_STATUS  Status;          /* the value to set for that channel  */
} ADI_PWM_CHANNEL_STATUS, *pADI_PWM_CHANNEL_STATUS;


/********************************************************************************
   Structure to pass along with any command that requires a simple u32 value.
   When there are multiple PWMs, the value should be passed in conjunction with
   the PWM NUMBER, to the adi_pwm_Init or adi_pwm_Control functions.

   For example, the PWM number is combined with the dead time or the period value.

*********************************************************************************/
#if defined(__ADSP_MOY__)

typedef struct ADI_PWM_NUMBER_AND_VALUE
{
     ADI_PWM_NUMBER  PwmNumber;         /* PWM0 or PWM1 */
     u32             Value;             /* the value to set  */

} ADI_PWM_NUMBER_AND_VALUE, *pADI_PWM_NUMBER_AND_VALUE;


typedef struct ADI_PWM_NUMBER_AND_ENABLE_STATUS
{
     ADI_PWM_NUMBER  PwmNumber;        /* PWM0 or PWM1 */
     ADI_PWM_ENABLE_STATUS  Status;    /* the enable/value    */

} ADI_PWM_NUMBER_AND_ENABLE_STATUS, *pADI_PWM_NUMBER_AND_ENABLE_STATUS;


typedef struct ADI_PWM_NUMBER_AND_CHANNEL_STATUS
{
     ADI_PWM_NUMBER  PwmNumber;                      /* PWM0 or PWM1 */
     ADI_PWM_CHANNEL_STATUS  ChannelStatus;          /* the value to set  */

} ADI_PWM_NUMBER_AND_CHANNEL_STATUS, *pADI_PWM_NUMBER_AND_CHANNEL_STATUS;


#endif

/********************************************************************************
   Structure to pass along with ADI_PWM_SET_DUTY_CYCLE command to the adi_pwm_Init
   or adi_pwm_Control functions.  The channel ID is combined with the channel
   specific duty cycle value.

   For Moy, which has two PWMs, also specifies the PWM number.

*********************************************************************************/

typedef struct ADI_PWM_CHANNEL_DUTY_CYCLE
{
#if defined(__ADSP_MOY__)
    ADI_PWM_NUMBER     Number;          /* PWM0 or PWM1 */
#endif
    ADI_PWM_CHANNEL Channel;            /* a channel or a channel pair */
    u32             Value;              /* the value to set for that channel  */

} ADI_PWM_CHANNEL_DUTY_CYCLE, *pADI_PWM_CHANNEL_DUTY_CYCLE;


/*********************************************************************************

  Operating Update Mode (Double/Single)

*********************************************************************************/
typedef enum ADI_PWM_UPDATE_MODE
{
#if defined(__ADSP_MOY__)
    ADI_PWM0_SINGLE_UPDATE,      /* single update operating mode */
    ADI_PWM0_DOUBLE_UPDATE,      /* double update operating mode */
    ADI_PWM1_SINGLE_UPDATE,      /* single update operating mode */
    ADI_PWM1_DOUBLE_UPDATE       /* double update operating mode */
#else
    ADI_PWM_SINGLE_UPDATE,      /* single update operating mode */
    ADI_PWM_DOUBLE_UPDATE       /* double update operating mode */
#endif
} ADI_PWM_UPDATE_MODE;




/*************************************************************************

    API functions

*************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* Function to initialize the Pulse Width Modulation service    */

ADI_PWM_RESULT adi_pwm_Init( const ADI_PWM_COMMAND_PAIR *table, void *pCriticalRegionArg );


 /* Function to terminate the Pulse Width Modulation service   */
ADI_PWM_RESULT adi_pwm_Terminate( void );



/* Function to read the date and time from the pwm_STAT register */
ADI_PWM_RESULT adi_pwm_Control( ADI_PWM_COMMAND Command, void *Value  );


/* Function to install a callback for a pwm event  */
ADI_PWM_RESULT adi_pwm_InstallCallback(

    ADI_PWM_EVENT_ID   EventID,          /* ID of the Interrupting Event          */
    void               *ClientHandle,    /* application data passed to callback   */
    ADI_DCB_HANDLE      DCBHandle,       /* deferred callback service handle      */
    ADI_DCB_CALLBACK_FN ClientCallback   /* name of client callback function      */
);


/* Function to remove a callback from the pwm callback list  */
ADI_PWM_RESULT adi_pwm_RemoveCallback(
    ADI_PWM_EVENT_ID EventID
);


#ifdef __cplusplus
}
#endif

#endif /* asm */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /*__ADI_PWM_H__ */
