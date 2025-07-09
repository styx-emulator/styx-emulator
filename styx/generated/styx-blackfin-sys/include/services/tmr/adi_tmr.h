/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_tmr.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the Timer Services.

*********************************************************************************/

#ifndef __ADI_TMR_H__
#define __ADI_TMR_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)


/*********************************************************************

Macros to manipulate the timer IDs

Users need not care about these macros. Users only need to know the timer IDs
in the sections below this one.

Timer IDs are a 32 bit value.  Bits 27-31 of the timer ID are used to index
into the timer info table in the adi_tmr.c file.  Bits 0-26, used only in GP
timers, are used as a mask so that we can enable/disable multiple GP timers
simultaneously.

*********************************************************************/

#define ADI_TMR_CREATE_GP_TIMER_ID(x)   (((x) << 27) | (1 << (x)))  // creates the timer ID for a GP timer
#define ADI_TMR_CREATE_CORE_TIMER_ID(x) ((x) << 27)                 // creates the timer ID for a core timer
#define ADI_TMR_CREATE_WDOG_TIMER_ID(x) ((x) << 27)                 // creates the timer ID for a watchdog timer

#define ADI_TMR_GET_TIMER_INDEX(x)      ((((u32)(x)) >> 27))        // gets index into the timer info table given a timer ID
#define ADI_TMR_GET_GP_TIMER_MASK(x)    ((x) & 0x7ffffff)           // get the mask for a GP timer given a GP timer ID

/*********************************************************************

Processor specific macros (Timer IDs)

*********************************************************************/

/********************
    Edinburgh
********************/

#if defined(__ADSP_EDINBURGH__) // settings for Edinburgh class devices

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(3),  // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(4)   // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (3)     // number of gp timers

#endif


/********************
    Braemar
********************/

#if defined(__ADSP_BRAEMAR__)   // settings for Braemar class devices

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_GP_TIMER_3      = ADI_TMR_CREATE_GP_TIMER_ID(3),    // timer 3
    ADI_TMR_GP_TIMER_4      = ADI_TMR_CREATE_GP_TIMER_ID(4),    // timer 4
    ADI_TMR_GP_TIMER_5      = ADI_TMR_CREATE_GP_TIMER_ID(5),    // timer 5
    ADI_TMR_GP_TIMER_6      = ADI_TMR_CREATE_GP_TIMER_ID(6),    // timer 6
    ADI_TMR_GP_TIMER_7      = ADI_TMR_CREATE_GP_TIMER_ID(7),    // timer 7
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(8),  // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(9)   // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (8)     // number of gp timers

#endif


/********************
    Teton_Lite
********************/

#if defined(__ADSP_TETON__) // settings for Teton class devices

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_GP_TIMER_3      = ADI_TMR_CREATE_GP_TIMER_ID(3),    // timer 3
    ADI_TMR_GP_TIMER_4      = ADI_TMR_CREATE_GP_TIMER_ID(4),    // timer 4
    ADI_TMR_GP_TIMER_5      = ADI_TMR_CREATE_GP_TIMER_ID(5),    // timer 5
    ADI_TMR_GP_TIMER_6      = ADI_TMR_CREATE_GP_TIMER_ID(6),    // timer 6
    ADI_TMR_GP_TIMER_7      = ADI_TMR_CREATE_GP_TIMER_ID(7),    // timer 7
    ADI_TMR_GP_TIMER_8      = ADI_TMR_CREATE_GP_TIMER_ID(8),    // timer 8
    ADI_TMR_GP_TIMER_9      = ADI_TMR_CREATE_GP_TIMER_ID(9),    // timer 9
    ADI_TMR_GP_TIMER_10     = ADI_TMR_CREATE_GP_TIMER_ID(10),   // timer 10
    ADI_TMR_GP_TIMER_11     = ADI_TMR_CREATE_GP_TIMER_ID(11),   // timer 11
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(12), // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(13)  // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (12)    // number of gp timers

#endif


/********************
    Stirling
********************/

#if defined(__ADSP_STIRLING__) // settings for Stirling class devices

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(3),  // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(4)   // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (3)     // number of gp timers

#endif


/********************
    Moab
********************/

#if defined(__ADSP_MOAB__) // settings for BF54x class devices

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_GP_TIMER_3      = ADI_TMR_CREATE_GP_TIMER_ID(3),    // timer 3
    ADI_TMR_GP_TIMER_4      = ADI_TMR_CREATE_GP_TIMER_ID(4),    // timer 4
    ADI_TMR_GP_TIMER_5      = ADI_TMR_CREATE_GP_TIMER_ID(5),    // timer 5
    ADI_TMR_GP_TIMER_6      = ADI_TMR_CREATE_GP_TIMER_ID(6),    // timer 6
    ADI_TMR_GP_TIMER_7      = ADI_TMR_CREATE_GP_TIMER_ID(7),    // timer 7
    ADI_TMR_GP_TIMER_8      = ADI_TMR_CREATE_GP_TIMER_ID(8),    // timer 8
    ADI_TMR_GP_TIMER_9      = ADI_TMR_CREATE_GP_TIMER_ID(9),    // timer 9
    ADI_TMR_GP_TIMER_10     = ADI_TMR_CREATE_GP_TIMER_ID(10),   // timer 10
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(11), // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(12)  // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (11)        // number of gp timers

#endif  // end of all Moabs


/*************************************
    Kookaburra/Mockingbird/Brodie/Moy
*************************************/

/* settings for Kookaburra, Mockingbird, Brodie and Moy class devices */
#if defined(__ADSP_KOOKABURRA__)  ||\
    defined(__ADSP_MOCKINGBIRD__) ||\
    defined(__ADSP_BRODIE__)      ||\
    defined(__ADSP_MOY__)

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_GP_TIMER_3      = ADI_TMR_CREATE_GP_TIMER_ID(3),    // timer 3
    ADI_TMR_GP_TIMER_4      = ADI_TMR_CREATE_GP_TIMER_ID(4),    // timer 4
    ADI_TMR_GP_TIMER_5      = ADI_TMR_CREATE_GP_TIMER_ID(5),    // timer 5
    ADI_TMR_GP_TIMER_6      = ADI_TMR_CREATE_GP_TIMER_ID(6),    // timer 6
    ADI_TMR_GP_TIMER_7      = ADI_TMR_CREATE_GP_TIMER_ID(7),    // timer 7
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(8),  // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(9)   // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (8)     // number of gp timers

#endif

#if defined(__ADSP_DELTA__) // settings for Delta class devices

enum {                                                      // enumeration of timers in the processor
    ADI_TMR_GP_TIMER_0      = ADI_TMR_CREATE_GP_TIMER_ID(0),    // timer 0
    ADI_TMR_GP_TIMER_1      = ADI_TMR_CREATE_GP_TIMER_ID(1),    // timer 1
    ADI_TMR_GP_TIMER_2      = ADI_TMR_CREATE_GP_TIMER_ID(2),    // timer 2
    ADI_TMR_CORE_TIMER      = ADI_TMR_CREATE_CORE_TIMER_ID(3),  // core timer
    ADI_TMR_WDOG_TIMER      = ADI_TMR_CREATE_WDOG_TIMER_ID(4)   // watchdog timer
};

#define ADI_TMR_GP_TIMER_COUNT  (3)     // number of gp timers

#endif


/*********************************************************************

GP timer control commands

*********************************************************************/

typedef enum ADI_TMR_GP_CMD {       // general purpose timer command IDs

    ADI_TMR_GP_CMD_START=ADI_TMR_ENUMERATION_START, // 0x70000 - starting point

    ADI_TMR_GP_CMD_END,                     // 0x70001 - end of table                                   (Value = NULL)
    ADI_TMR_GP_CMD_PAIR,                    // 0x70002 - single command pair being passed               (Value = ADI_TMR_GP_CMD_VALUE_PAIR *)
    ADI_TMR_GP_CMD_TABLE,                   // 0x70003 - table of command pairs being passed            (Value = ADI_TMR_GP_CMD_VALUE_PAIR *)
    ADI_TMR_GP_CMD_SET_PERIOD,              // 0x70004 - sets the period value of the timer             (Value = u32)
    ADI_TMR_GP_CMD_SET_WIDTH,               // 0x70005 - sets the width register value of the timer     (Value = u32)
    ADI_TMR_GP_CMD_GET_WIDTH,               // 0x70006 - gets the width register value of the timer     (Value = u32 *)
    ADI_TMR_GP_CMD_GET_COUNTER,             // 0x70007 - gets the counter value                         (Value = u32 *)

    // maintain this order
    // ****** order start
    ADI_TMR_GP_CMD_SET_TIMER_MODE,          // 0x70008 - set timer mode                                 (Value = 0 - not used, 1 - PWM mode, 2 - WDTH_CAP mode, 3 - EXT_CLK mode)TRUE/FALSE)
    ADI_TMR_GP_CMD_SET_PULSE_HI,            // 0x70009 - set PULSE_HI                                   (Value = TRUE - positive action pulse, FALSE - negative action pulse)
    ADI_TMR_GP_CMD_SET_COUNT_METHOD,        // 0x7000a - set count method                               (Value = TRUE - count to end of period, FALSE - count to end of width)
    ADI_TMR_GP_CMD_SET_INTERRUPT_ENABLE,    // 0x7000b - enable/disable interrupt generation            (Value = TRUE - enable interrupt, FALSE - disable interrupt)
    ADI_TMR_GP_CMD_SET_INPUT_SELECT,        // 0x7000c - selects the timer input                        (Value = TRUE - UART_RX or PPI_CLK, FALSE - TMRx or PF1)
    ADI_TMR_GP_CMD_SET_OUTPUT_PAD_DISABLE,  // 0x7000d - disables the output pad in PWM mode            (Value = TRUE - disabled, FALSE - ENABLED)
    ADI_TMR_GP_CMD_SET_CLOCK_SELECT,        // 0x7000e - sets the time clock select                     (Value = TRUE - use PWM_CLK for counter, FALSE - use SCLK for counter)
    ADI_TMR_GP_CMD_SET_TOGGLE_HI,           // 0x7000f - sets toggle hi state                           (Value = TRUE - PULSE_HI alternates each period, FALSE - use programmed state)
    ADI_TMR_GP_CMD_RUN_DURING_EMULATION,    // 0x70010 - run timer during emulation mode                (Value = TRUE - timer runs during emulation mode, FALSE - timer doesn't run)
    ADI_TMR_GP_CMD_GET_ERROR_TYPE,          // 0x70011 - senses the error type                          (Value = u32 *, 0 - no error, 1 - counter overflow, 2 - period register error, 3 - width register error)
    // ****** order end

    ADI_TMR_GP_CMD_IS_INTERRUPT_ASSERTED,   // 0x70012 - senses if the timer's interrupt is asserted    (Value = u32 *, TRUE - asserted, FALSE - not asserted)
    ADI_TMR_GP_CMD_CLEAR_INTERRUPT,         // 0x70013 - clears a timer's interrupt                     (Value = n/a)
    ADI_TMR_GP_CMD_IS_ERROR,                // 0x70014 - senses if the timer has an error               (Value = u32 *, TRUE - error FALSE - no error)
    ADI_TMR_GP_CMD_CLEAR_ERROR,             // 0x70015 - clears a timer's error status                  (Value = n/a)
    ADI_TMR_GP_CMD_IS_SLAVE_ENABLED,        // 0x70016 - senses slave enable status                     (Value = u32 *, TRUE - enabled, FALSE - not enabled)
    ADI_TMR_GP_CMD_IMMEDIATE_HALT,          // 0x70017 - stops time immediately in PWM mode             (Value = n/a)
    ADI_TMR_GP_CMD_ENABLE_TIMER,            // 0x70018 - starts/stops the timer                         (Value = TRUE - timer enabled, FALSE - timer disabled)
    ADI_TMR_GP_CMD_SET_ENABLE_DELAY,        // 0x70019 - sets number of sys clocks to delay enable by   (Value = u32)
    ADI_TMR_GP_CMD_GET_PERIOD               // 0x7001A - gets the period register value of the timer    (Value = u32 *)


} ADI_TMR_GP_CMD;


typedef struct ADI_TMR_GP_CMD_VALUE_PAIR {  // GP timer command value pair
    ADI_TMR_GP_CMD  CommandID;                  // command ID
    void            *Value;                     // parameter
} ADI_TMR_GP_CMD_VALUE_PAIR;


/*********************************************************************

Core timer control commands

*********************************************************************/

typedef enum ADI_TMR_CORE_CMD {     // core timer command IDs

    ADI_TMR_CORE_CMD_START=ADI_TMR_ENUMERATION_START,   // 0x70000 - starting point

    ADI_TMR_CORE_CMD_END,                       // 0x70001 - end of table                                           (Value = NULL)
    ADI_TMR_CORE_CMD_PAIR,                      // 0x70002 - single command pair being passed                       (Value = ADI_TMR_CORE_CMD_VALUE_PAIR *)
    ADI_TMR_CORE_CMD_TABLE,                     // 0x70003 - table of command pairs being passed                    (Value = ADI_TMR_CORE_CMD_VALUE_PAIR *)

    // maintain this order
    // ****** order start
    ADI_TMR_CORE_CMD_SET_ACTIVE_MODE,           // 0x70004 - sets the time into active or low power mode            (Value = TRUE - active mode, FALSE - low power mode)
    ADI_TMR_CORE_CMD_ENABLE_TIMER,              // 0x70005 - starts/stops the timer                                 (Value = TRUE - timer enabled, FALSE - timer disabled)
    ADI_TMR_CORE_CMD_SET_AUTO_RELOAD,           // 0x70006 - set/clears auto reload mode of timer                   (Value = TRUE - automatically reload, FALSE - no reload)
    // ****** order end

    ADI_TMR_CORE_CMD_HAS_INTERRUPT_OCCURRED,    // 0x70007 - senses if the timer's interrupt has been generated     (Value = u32 *, TRUE - occurred, FALSE - not occurred)
    ADI_TMR_CORE_CMD_RESET_INTERRUPT_OCCURRED,  // 0x70008 - clears indication that timer's interrupt has occurred  (Value = n/a)
    ADI_TMR_CORE_CMD_SET_COUNT,                 // 0x70009 - sets the timer's tcount register                       (Value = u32)
    ADI_TMR_CORE_CMD_SET_PERIOD,                // 0x7000a - sets the timer's tperiod register                      (Value = u32)
    ADI_TMR_CORE_CMD_SET_SCALE,                 // 0x7000b - sets the timer's tscale register                       (Value = u32)
    ADI_TMR_CORE_CMD_GET_COUNT                  // 0x7000c - senses the core timer value (tar 31844)                (Value = u32)

} ADI_TMR_CORE_CMD;


typedef struct ADI_TMR_CORE_CMD_VALUE_PAIR {    // core timer command value pair
    ADI_TMR_CORE_CMD    CommandID;                  // command ID
    void                *Value;                     // parameter
} ADI_TMR_CORE_CMD_VALUE_PAIR;


/*********************************************************************

Watchdog timer control commands

*********************************************************************/

typedef enum ADI_TMR_WDOG_CMD {     // watchdog timer command IDs

    ADI_TMR_WDOG_CMD_START=ADI_TMR_ENUMERATION_START,   // 0x70000 - starting point

    ADI_TMR_WDOG_CMD_END,               // 0x70001 - end of table                                           (Value = NULL)
    ADI_TMR_WDOG_CMD_PAIR,              // 0x70002 - single command pair being passed                       (Value = ADI_TMR_WDOG_CMD_VALUE_PAIR *)
    ADI_TMR_WDOG_CMD_TABLE,             // 0x70003 - table of command pairs being passed                    (Value = ADI_TMR_WDOG_CMD_VALUE_PAIR *)

    // maintain this order
    // ****** order start
    ADI_TMR_WDOG_CMD_EVENT_SELECT,      // 0x70005 - defines the event which occurs when WDOG expires       (Value = 0 - reset, 1 - NMI, 2 - GP interrupt, 3 - no event)
    ADI_TMR_WDOG_CMD_ENABLE_TIMER,      // 0x70004 - starts/stops the timer                                 (Value = TRUE - timer enabled, FALSE - timer disabled)
    // ****** order end

    ADI_TMR_WDOG_CMD_HAS_EXPIRED,       // 0x70006 - senses if the watchdog timer has expired               (Value = u32 *, TRUE - expired, FALSE - not expired)
    ADI_TMR_WDOG_CMD_RESET_EXPIRED,     // 0x70007 - clears indication that watchdog timer has expired      (Value = n/a)
    ADI_TMR_WDOG_CMD_GET_STATUS,        // 0x70008 - gets the watchdog status                               (Value = u32 *, filled with current count value)
    ADI_TMR_WDOG_CMD_SET_COUNT,         // 0x70009 - sets the watchdog's count value                        (Value = u32)
    ADI_TMR_WDOG_CMD_RELOAD_STATUS      // 0x7000a - reloads the status register from the count register    (Value = NULL)

} ADI_TMR_WDOG_CMD;


typedef struct ADI_TMR_WDOG_CMD_VALUE_PAIR {    // watchdog timer command value pair
    ADI_TMR_WDOG_CMD    CommandID;                  // command ID
    void                *Value;                     // parameter
} ADI_TMR_WDOG_CMD_VALUE_PAIR;



/*********************************************************************

Timer Services API return codes

*********************************************************************/

typedef enum {                          // timer service return codes
    ADI_TMR_RESULT_SUCCESS=0,                       // generic success
    ADI_TMR_RESULT_FAILED=1,                        // generic failure

    ADI_TMR_RESULT_START=ADI_TMR_ENUMERATION_START, // 0x70000 - starting point

    ADI_TMR_RESULT_NOT_SUPPORTED,                   // 0x70001 - not supported
    ADI_TMR_RESULT_BAD_TIMER_ID,                    // 0x70002 - bad timer ID
    ADI_TMR_RESULT_BAD_TIMER_IDS,                   // 0x70003 - bad timer IDs
    ADI_TMR_RESULT_BAD_TIMER_TYPE,                  // 0x70004 - bad timer type
    ADI_TMR_RESULT_BAD_COMMAND,                     // 0x70005 - bad command ID
    ADI_TMR_RESULT_INTERRUPT_MANAGER_ERROR,         // 0x70006 - error from interrupt manager
    ADI_TMR_RESULT_CALLBACK_ALREADY_INSTALLED       // 0x70007 - callback already installed for timer
} ADI_TMR_RESULT;


/*********************************************************************

Timer Services callback events

*********************************************************************/

typedef enum {                          // timer service return codes
    ADI_TMR_EVENT_START=ADI_TMR_ENUMERATION_START,  // 0x70000 - starting point

    ADI_TMR_EVENT_TIMER_EXPIRED                     // 0x70001 - a timer has expired
} ADI_TMR_EVENT;


/*********************************************************************

API function prototypes

*********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

//******************
// common functions
//******************

ADI_TMR_RESULT adi_tmr_Init(                // initializes the timer service
    void    *pCriticalRegionArg                 // parameter for critical region function
);

ADI_TMR_RESULT adi_tmr_Terminate(           // terminates the timer service
    void
);

ADI_TMR_RESULT adi_tmr_Open(                // opens a general purpose, core or watchdog timer for use
    u32 TimerID                                 // timer ID
);

ADI_TMR_RESULT adi_tmr_Close(               // closes a general purpose, core or watchdog timer from further use
    u32 TimerID                                 // timer ID
);

ADI_TMR_RESULT adi_tmr_Reset(               // resets a general purpose, core or watchdog timer to reset values
    u32 TimerID                                 // timer ID
);

ADI_TMR_RESULT adi_tmr_InstallCallback(     // installs a callback for a general purpose, core or watchdog timer
    u32                 TimerID,                // timer ID
    u32                 WakeupFlag,             // wakeup flag (TRUE/FALSE)
    void                *ClientHandle,          // client handle argument passed in callbacks
    ADI_DCB_HANDLE      DCBHandle,              // deferred callback service handle
    ADI_DCB_CALLBACK_FN ClientCallback          // client callback function
);

ADI_TMR_RESULT adi_tmr_RemoveCallback(      // removes a callback for a general purpose, core or watchdog timer
    u32 TimerID                                 // timer ID
);

//******************
// general purpose and watchdog timer functions
//******************

ADI_TMR_RESULT adi_tmr_GetPeripheralID(     // gets the interrupt peripheral ID for a general purpose or watchdog timer
    u32                     TimerID,            // timer ID
    ADI_INT_PERIPHERAL_ID   *pPeripheralID      // location where peripheral ID of timer will be stored
);

//******************
// general purpose timer only functions
//******************

ADI_TMR_RESULT adi_tmr_GPControl(           // controls a general purpose timer
    u32             TimerID,                    // timer ID
    ADI_TMR_GP_CMD  Command,                    // command ID
    void            *Value                      // command specific value
);

ADI_TMR_RESULT adi_tmr_GPGroupEnable(       // simultaneously enable/disable a group of timers
    u32 TimerIDs,                               // OR-ing of timer IDs to enable/disable
    u32 EnableFlag                              // enable/disable flag (TRUE - enable, FALSE - disable)
);


//******************
// core timer only functions
//******************

ADI_TMR_RESULT adi_tmr_CoreControl(         // controls the core timer
    ADI_TMR_CORE_CMD    Command,                // command ID
    void                *Value                  // command specific value
);



//******************
// watchdog timer only functions
//******************

ADI_TMR_RESULT adi_tmr_WatchdogControl(     // controls the watchdog timer
    ADI_TMR_WDOG_CMD    Command,                // command ID
    void                *Value                  // command specific value
);



#ifdef __cplusplus
}
#endif


/********************************************************************************/

#endif //!defined(_LANGUAGE_ASM)

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_TMR_H__ */
