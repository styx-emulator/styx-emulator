/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.


This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

File:
    'adi_rtc.h'

Description:

    Header file for the Real Time Clock module of the System Services Library.
    This file contains prototypes for the following functions:

        adi_rtc_Init
        adi_rtc_Terminate
        adi_rtc_SetDateTime
        adi_rtc_GetDateTime
        adi_rtc_InstallCallback
        adi_rtc_RemoveCallback
        adi_rtc_EnableWakeup
        adi_rtc_DisableWakeup
        adi_rtc_ResetStopwatch
        adi_rtc_GetEpoch
        adi_rtc_SetEpoch

********************************************************************************/

#ifndef __ADI_RTC_H__
#define __ADI_RTC_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

/* include this file for the "tm" date/time structure */
#include <time.h>


/* *****************************************************************
 * RESULT CODES
 * *****************************************************************
 */

typedef enum {
    ADI_RTC_RESULT_SUCCESS=0,                       /* Generic success */
    ADI_RTC_RESULT_FAILED=1,                        /* Generic failure */
    ADI_RTC_RESULT_START=ADI_RTC_ENUMERATION_START, /* defined in services.h */
    ADI_RTC_RESULT_INVALID_EVENT_ID,                /* (0xA0001) Invalid ID */
    ADI_RTC_RESULT_INTERRUPT_MANAGER_ERROR,         /* (0xA0002) Error returned from interrupt manager */
    ADI_RTC_RESULT_ERROR_REMOVING_CALLBACK,         /* (0xA0003) Can't find callback for given ID */
    ADI_RTC_RESULT_CALL_IGNORED,                    /* (0xA0004) Function call was not executed */
    ADI_RTC_RESULT_NOT_INITIALIZED,                 /* (0xA0005) RTC service has not been initialized */
    ADI_RTC_RESULT_CALLBACK_NOT_INSTALLED,          /* (0xA0006) callback was never installed. */
    ADI_RTC_RESULT_DATETIME_OUT_OF_RANGE,           /* (0xA0007) tm struct seconds field out of range */
    ADI_RTC_RESULT_SERVICE_NOT_SUPPORTED,           /* (0xA0008) No RTC service for this processor  */
    ADI_RTC_RESULT_ALREADY_INITIALIZED,             /* (0xA0009) service has already been initialized */
    ADI_RTC_RESULT_CALLBACK_ALREADY_INSTALLED,      /* (0xA000A) cannot install same callback twice */
    ADI_RTC_RESULT_CALLBACK_CONFLICT                /* (0xA000B) cannot install day and once callback simultaneously */
} ADI_RTC_RESULT;


/* ********************************************************************
 * Enum for RTC Event IDs (eight total possible events)
 * ********************************************************************
 */
enum {
    ADI_RTC_EVENT_START=ADI_RTC_ENUMERATION_START,  /* starting point */
                                    /* DON'T CHANGE THIS ORDER */
    ADI_RTC_EVENT_SECONDS,          /* (0xA0001) one second periodic  */
    ADI_RTC_EVENT_MINUTES,          /* (0xA0002) one minute periodic  */
    ADI_RTC_EVENT_HOURS,            /* (0xA0003) hourly periodic      */
    ADI_RTC_EVENT_DAYS,             /* (0xA0004) daily periodic       */
    ADI_RTC_EVENT_STOPWATCH,        /* (0xA0005) 'stopwatch' (countdown timeout) */
    ADI_RTC_EVENT_EACH_DAY_ALARM,   /* (0xA0006) specific time each day alarm    */
    ADI_RTC_EVENT_ONCE_ALARM,       /* (0xA0007) specific time on a specific day alarm */
    ADI_RTC_EVENT_WRITES_COMPLETE   /* (0xA0008) completion of pending register writes */
};


typedef u32 ADI_RTC_EVENT_ID;


typedef struct ADI_RTC_EPOCH {
    u32 year;     /* year - [0, *] */
    u32 month;    /* month of the year - [1,12] */
    u32 day;      /* day of the month - [1,31] */
} ADI_RTC_EPOCH, *pADI_RTC_EPOCH;


/*************************************************************************
 *
 *   API functions
 *
*************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* Function to initialize the Real Time Clock service   */
ADI_RTC_RESULT adi_rtc_Init( void *pCriticalRegionArg    /* parameter for the critical region   */
);


 /* Function to terminate the Real Time Clock service   */
ADI_RTC_RESULT adi_rtc_Terminate( void );


/* Function to arite the date and time to the RTC_STAT register */
ADI_RTC_RESULT adi_rtc_SetDateTime(
    struct tm *pDateTime               /* points to a "tm" structure.      */
);


/* Function to read the date and time from the RTC_STAT register */
ADI_RTC_RESULT adi_rtc_GetDateTime(
    struct tm *pDateTime                 /* value is returned as "tm" structure.  */
);


/* Function to install a callback for a RTC event  */
ADI_RTC_RESULT adi_rtc_InstallCallback(

    ADI_RTC_EVENT_ID   EventID,          /* ID of the Interrupting Event          */
    void               *ClientHandle,    /* application data passed to callback   */
    ADI_DCB_HANDLE      DCBHandle,       /* deferred callback service handle      */
    ADI_DCB_CALLBACK_FN ClientCallback,  /* name of client callback function      */
    void               *Value            /* points to the time, for daily alarm callbacks,   */
                                         /* the date/time for once-only alarm callbacks, the */
                                         /* stopwatch count value, for stopwatch countdown   */
                                         /* callbacks, NULL, for all other callbacks.        */
);


/* Function to remove a callback from the RTC callback list  */
ADI_RTC_RESULT adi_rtc_RemoveCallback( ADI_RTC_EVENT_ID EventID );

/* Function to enable the RTC wakeup to processor */
ADI_RTC_RESULT adi_rtc_EnableWakeup( void );

/* Function to disable the RTC wakeup to processor */
ADI_RTC_RESULT adi_rtc_DisableWakeup( void );

/* Function to reenable the stopwatch event */
ADI_RTC_RESULT adi_rtc_ResetStopwatch( u32 );

/* Function to return the epoch's year, month and day. */
ADI_RTC_RESULT adi_rtc_GetEpoch( ADI_RTC_EPOCH *pEpoch );

/* Function to set the epoch. */
ADI_RTC_RESULT adi_rtc_SetEpoch(ADI_RTC_EPOCH *pEpoch );

#ifdef __cplusplus
}

#endif

#endif /* Not ASM */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /*__ADI_RTC_H__ */
