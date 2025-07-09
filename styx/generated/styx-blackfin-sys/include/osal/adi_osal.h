/*
****************************************************************************
Copyright (c), 2009-2011 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.
******************************************************************************
$Revision: 5506 $
$Date: 2011-07-26 10:45:48 -0400 (Tue, 26 Jul 2011) $

Title: OS Abstraction Layer (OSAL) public definitions and function prototypes


Description:
       This file contains the public API definition for the
       Operating System Abstraction Layer.

*****************************************************************************/

#ifndef __ADI_OSAL_H__
#define __ADI_OSAL_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  I N C L U D E S   =============*/

#if defined(_LANGUAGE_C)

#include <adi_types.h>
#include <sys/exception.h>

#endif /* Language C */



/*==============  D E F I N E S  ===============*/

/*
 *  Generic Constants usable in both C and ASM
 */


/*
 *   Current API version (major.minor)
 */
#define     ADI_OSAL_MAJOR_VER    2u
#define     ADI_OSAL_MINOR_VER    0u


/*-------------------------------------------------------------------*
     Return/Status codes - these correspond to the codes
     in the enum ADI_OSAL_STATUS
 *-------------------------------------------------------------------*/

#define     E_ADI_OSAL_SUCCESS                  0x00       /* Generic Success */

#define     E_ADI_OSAL_FAILED                   0x01       /* Generic Failure */

#define     E_ADI_OSAL_BAD_COUNT                0x02       /* The value specified for the initial semaphore count exceeds
                                                              the underlying operating systems count range*/
#define     E_ADI_OSAL_BAD_EVENT                0x03       /* An invalid event flag was specified (an attempt was made to
                                                              utilize bit 31). */
#define     E_ADI_OSAL_BAD_HANDLE               0x04       /* The supplied handle is invalid */

#define     E_ADI_OSAL_BAD_HEAP                 0x05       /* Heap pointer is not 4-bytes aligned */

#define     E_ADI_OSAL_BAD_IVG_LEVEL            0x06       /* An attempt was made to install an ISR into a level that cannot
                                                              be modified */
#define     E_ADI_OSAL_BAD_MEMORY               0x07       /* The pointer to memory is invalid (may not be aligned) */

#define     E_ADI_OSAL_BAD_OPTION               0x08       /* An invalid option was specified for the event pend operation */

#define     E_ADI_OSAL_BAD_PRIO_INHERIT         0x09       /* Priority inheritance is not supported by the underlying OS */

#define     E_ADI_OSAL_BAD_PRIORITY             0x0a       /* The priority level indicated is invalid for the underlying OS */

#define     E_ADI_OSAL_BAD_SLOT_NUM             0x0b       /* The specified thread local storage slot number exceeds the
                                                              available slots */
#define     E_ADI_OSAL_BAD_STACK_ADDR           0x0c       /* The thread stack address supplied as part of the ADI_OSAL_THREAD_ATTR
                                                              structure is not aligned correctly */
#define     E_ADI_OSAL_BAD_STACK_SIZE           0x0d       /* The thread stack size supplied as part of the ADI_OSAL_THREAD_ATTR
                                                              structure does not meet the underlying operating system’s
                                                              minimum requirements */
#define     E_ADI_OSAL_BAD_THREAD_FUNC          0x0e       /* The thread function supplied as part of the ADI_OSAL_THREAD_ATTR
                                                              structure is invalid */
#define     E_ADI_OSAL_BAD_THREAD_NAME          0x0f       /* The string specifying the thread name as part of the ADI_OSAL_THREAD_ATTR
                                                              structure exceeds the size specified by ADI_OSAL_MAX_THREAD_NAME */
#define     E_ADI_OSAL_BAD_TIME                 0x10       /* The time for sleep or timeout exceeds the range allowed by the
                                                              underlying operating system */
#define     E_ADI_OSAL_BAD_TIMER_PERIOD         0x11       /* The value specified for nSysTimerPerioduSec is set to zero,
                                                              yet the underlying operating system does not supply timing information */
#define     E_ADI_OSAL_CALLBACK_FAILED          0x12       /* Startup callback (during adi_osal_OSStart) failed (or something
                                                              called in it failed) */
#define     E_ADI_OSAL_CALLER_ERROR             0x13       /* The function was called from an invalid location (such as in
                                                              an ISR, or during startup) */
#define     E_ADI_OSAL_COUNT_OVERFLOW           0x14       /* An internal counter overflowed (e.g. the semaphore count, the
                                                              mutex ownership count, etc) */
#define     E_ADI_OSAL_DESTROY_SELF             0x15       /* A thread is attempting to destroy itself (not supported) */

#define     E_ADI_OSAL_IVG_LEVEL_IN_USE         0x16       /* Specified IVG level already has an ISR installed */

#define     E_ADI_OSAL_MEM_ALLOC_FAILED         0x17       /* No memory available for allocation of the specified object */

#define     E_ADI_OSAL_NOT_MUTEX_OWNER          0x18       /* The current thread does not own the mutex being destroyed */

#define     E_ADI_OSAL_OS_ERROR                 0x19       /* The underlying OS is not setup in a compatible way or has returned
                                                             an error during initialization */
#define     E_ADI_OSAL_PRIORITY_IN_USE          0x1a       /* Specified priority is already in use (occurs for operating systems
                                                              that do not support more than one thread per priority level)*/
#define     E_ADI_OSAL_QUEUE_EMPTY              0x1b       /* Message queue is empty when fetching a message */

#define     E_ADI_OSAL_QUEUE_FULL               0x1c       /* Message queue is full when sending a message */

#define     E_ADI_OSAL_START_FAILED             0x1d       /* Underlying RTOS failed to start */

#define     E_ADI_OSAL_THREAD_PENDING           0x1e       /* An attempt was made to destroy a semaphore, mutex or message queue
                                                              when a thread is pending on the object*/
#define     E_ADI_OSAL_TIMEOUT                  0x1f       /* Timeout occurred (Pend functions) */

#define     E_ADI_OSAL_SLOT_NOT_ALLOCATED       0x20       /* An attempt was made to use a thread slot before allocating it */

#define     E_ADI_OSAL_MEM_TOO_SMALL            0x21       /* The memory size given is not sufficient for its purpose */

#define     E_ADI_OSAL_INVALID_ARGS             0x22       /* The API arguments are not valid */



/*
 *   Event Flags (only bits 0 - 30 can be used)
 */
#define     ADI_OSAL_EVENT_FLAG0                0x00000001
#define     ADI_OSAL_EVENT_FLAG1                0x00000002
#define     ADI_OSAL_EVENT_FLAG2                0x00000004
#define     ADI_OSAL_EVENT_FLAG3                0x00000008
#define     ADI_OSAL_EVENT_FLAG4                0x00000010
#define     ADI_OSAL_EVENT_FLAG5                0x00000020
#define     ADI_OSAL_EVENT_FLAG6                0x00000040
#define     ADI_OSAL_EVENT_FLAG7                0x00000080
#define     ADI_OSAL_EVENT_FLAG8                0x00000100
#define     ADI_OSAL_EVENT_FLAG9                0x00000200
#define     ADI_OSAL_EVENT_FLAG10               0x00000400
#define     ADI_OSAL_EVENT_FLAG11               0x00000800
#define     ADI_OSAL_EVENT_FLAG12               0x00001000
#define     ADI_OSAL_EVENT_FLAG13               0x00002000
#define     ADI_OSAL_EVENT_FLAG14               0x00004000
#define     ADI_OSAL_EVENT_FLAG15               0x00008000
#define     ADI_OSAL_EVENT_FLAG16               0x00010000
#define     ADI_OSAL_EVENT_FLAG17               0x00020000
#define     ADI_OSAL_EVENT_FLAG18               0x00040000
#define     ADI_OSAL_EVENT_FLAG19               0x00080000
#define     ADI_OSAL_EVENT_FLAG20               0x00100000
#define     ADI_OSAL_EVENT_FLAG21               0x00200000
#define     ADI_OSAL_EVENT_FLAG22               0x00400000
#define     ADI_OSAL_EVENT_FLAG23               0x00800000
#define     ADI_OSAL_EVENT_FLAG24               0x01000000
#define     ADI_OSAL_EVENT_FLAG25               0x02000000
#define     ADI_OSAL_EVENT_FLAG26               0x04000000
#define     ADI_OSAL_EVENT_FLAG27               0x08000000
#define     ADI_OSAL_EVENT_FLAG28               0x10000000
#define     ADI_OSAL_EVENT_FLAG29               0x20000000
#define     ADI_OSAL_EVENT_FLAG30               0x40000000
/* bit 31, 0x80000000 is reserved */

/*
 *   Invalid priority level
 *   (this is a priority level that cannot occur in normal usage)
 */
#define     ADI_OSAL_INVALID_PRIORITY           0xFFFFFFFF

/*
 *   Invalid thread slot number
 *   (this is a thread slot number that cannot occur in normal usage)
 */
#define     ADI_OSAL_INVALID_THREAD_SLOT        0xFFFFFFFF



#if defined(_LANGUAGE_C)
/*
 *  Constants only usable in C ...
 */


/*
 *   Timeout constants
 */
#define     ADI_OSAL_TIMEOUT_NONE               0u
#define     ADI_OSAL_TIMEOUT_FOREVER            0xFFFFFFFFu


/*
    Macros defined for invalid handles for mutex, thread, semaphore etc.
    (these are pointers to locations that are invalid for a normal handle
    i.e. the last address in memory is normally core MMR space)
*/
#define     ADI_OSAL_INVALID_THREAD             ((ADI_OSAL_THREAD_HANDLE) -1)
#define     ADI_OSAL_INVALID_MUTEX              ((ADI_OSAL_MUTEX_HANDLE)  -1)
#define     ADI_OSAL_INVALID_SEM                ((ADI_OSAL_SEM_HANDLE)    -1)
#define     ADI_OSAL_INVALID_QUEUE              ((ADI_OSAL_QUEUE_HANDLE)  -1)
#define     ADI_OSAL_INVALID_EVENT_GROUP        ((ADI_OSAL_EVENT_HANDLE)  -1)


/*
 *  Worst-case size of a mutex object
 *  this size is the size of the mutex object that is the largest amongst the realtime
 *  operating systems that are officially supported.
 */
#define     ADI_OSAL_MAX_MUTEX_SIZE_CHAR        (16u * sizeof(void*))

/*
 * Maximum count for a semaphore
 * Although many RTOS may cope with UINT_MAX as the maximum size for a
 * semaphore, uCOS-II has a 16-bit field. For semaphore creation OSAL limits
 * the count to something that all supported RTOS can manage
 */
#define     ADI_OSAL_SEM_MAX_COUNT              (0xFFFFu)

/*
 * Maximum Timeout
 * Although many RTOS may cope with UINT_MAX as the maximum timeout
 * uCOS-II has a 16-bit field. For semaphore creation OSAL limits
 * the timeout to something that all supported RTOS can manage
 */
#define    ADI_OSAL_MAX_TIMEOUT                (0xFFFFu)


/*
 * Default settings
 */
#define     ADI_OSAL_DEFAULT_PRIO_INHERIT       (ADI_OSAL_PRIO_INHERIT_AUTO)      /* use the underlying OS for priority inheritance setting */
#define     ADI_OSAL_DEFAULT_NUM_TLS_SLOTS      (8u)
#define     ADI_OSAL_DEFAULT_SYS_TIMER_PERIOD   (0u)                              /* use the underlying OS for period information */

#define     ADI_OSAL_MAX_THREAD_NAME            (80u)


#endif /* Language C */





/*============= D A T A T Y P E S =============*/



/*
 *    C-Specific Definitions
 */
#if defined(_LANGUAGE_C)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */



/*-------------------------------------------------------------------*
 *    Handles definitions                                            *
 *-------------------------------------------------------------------*/

/* NOTE: all handles are opaque pointers - these do NOT
   use void * to ensure valid parameter type checking */

/* Those types are incomplete because they are only used for type checking.
   They are always used as pointer to them (handles) so there isn't a need to define them
   most of the time they are typecasted to the underlying OS specific types. */

/*
 *   Typedef for a thread handle
 */
typedef struct _ADI_Thread_Handle *ADI_OSAL_THREAD_HANDLE;

/*
 *   Typedef for a semaphore handle
 */
typedef struct _ADI_Sem_Handle *ADI_OSAL_SEM_HANDLE;

/*
 *   Typedef for a mutex handle
 */
typedef struct _ADI_Mutex_Handle *ADI_OSAL_MUTEX_HANDLE;

/*
 *   Typedef for a message queue handle
 */
typedef struct _ADI_Queue_Handle *ADI_OSAL_QUEUE_HANDLE;

/*
 *   Typedef for a event handle
 */
typedef struct _ADI_Event_Handle *ADI_OSAL_EVENT_HANDLE;


/*-------------------------------------------------------------------*
 *     Return/Status codes from OSAL API                             *
 *-------------------------------------------------------------------*/

typedef enum
{
    ADI_OSAL_SUCCESS                  = E_ADI_OSAL_SUCCESS,
    ADI_OSAL_FAILED                   = E_ADI_OSAL_FAILED,
    ADI_OSAL_BAD_COUNT                = E_ADI_OSAL_BAD_COUNT,
    ADI_OSAL_BAD_EVENT                = E_ADI_OSAL_BAD_EVENT,
    ADI_OSAL_BAD_HANDLE               = E_ADI_OSAL_BAD_HANDLE,
    ADI_OSAL_BAD_HEAP                 = E_ADI_OSAL_BAD_HEAP,
    ADI_OSAL_BAD_IVG_LEVEL            = E_ADI_OSAL_BAD_IVG_LEVEL,
    ADI_OSAL_BAD_MEMORY               = E_ADI_OSAL_BAD_MEMORY,
    ADI_OSAL_BAD_OPTION               = E_ADI_OSAL_BAD_OPTION,
    ADI_OSAL_BAD_PRIO_INHERIT         = E_ADI_OSAL_BAD_PRIO_INHERIT,
    ADI_OSAL_BAD_PRIORITY             = E_ADI_OSAL_BAD_PRIORITY,
    ADI_OSAL_BAD_SLOT_NUM             = E_ADI_OSAL_BAD_SLOT_NUM,
    ADI_OSAL_BAD_STACK_ADDR           = E_ADI_OSAL_BAD_STACK_ADDR,
    ADI_OSAL_BAD_STACK_SIZE           = E_ADI_OSAL_BAD_STACK_SIZE,
    ADI_OSAL_BAD_THREAD_FUNC          = E_ADI_OSAL_BAD_THREAD_FUNC,
    ADI_OSAL_BAD_THREAD_NAME          = E_ADI_OSAL_BAD_THREAD_NAME,
    ADI_OSAL_BAD_TIME                 = E_ADI_OSAL_BAD_TIME,
    ADI_OSAL_BAD_TIMER_PERIOD         = E_ADI_OSAL_BAD_TIMER_PERIOD,
    ADI_OSAL_CALLBACK_FAILED          = E_ADI_OSAL_CALLBACK_FAILED,
    ADI_OSAL_CALLER_ERROR             = E_ADI_OSAL_CALLER_ERROR,
    ADI_OSAL_COUNT_OVERFLOW           = E_ADI_OSAL_COUNT_OVERFLOW,
    ADI_OSAL_DESTROY_SELF             = E_ADI_OSAL_DESTROY_SELF,
    ADI_OSAL_IVG_LEVEL_IN_USE         = E_ADI_OSAL_IVG_LEVEL_IN_USE,
    ADI_OSAL_MEM_ALLOC_FAILED         = E_ADI_OSAL_MEM_ALLOC_FAILED,
    ADI_OSAL_NOT_MUTEX_OWNER          = E_ADI_OSAL_NOT_MUTEX_OWNER,
    ADI_OSAL_OS_ERROR                 = E_ADI_OSAL_OS_ERROR,
    ADI_OSAL_PRIORITY_IN_USE          = E_ADI_OSAL_PRIORITY_IN_USE,
    ADI_OSAL_QUEUE_EMPTY              = E_ADI_OSAL_QUEUE_EMPTY,
    ADI_OSAL_QUEUE_FULL               = E_ADI_OSAL_QUEUE_FULL,
    ADI_OSAL_START_FAILED             = E_ADI_OSAL_START_FAILED,
    ADI_OSAL_THREAD_PENDING           = E_ADI_OSAL_THREAD_PENDING,
    ADI_OSAL_TIMEOUT                  = E_ADI_OSAL_TIMEOUT,
    ADI_OSAL_SLOT_NOT_ALLOCATED       = E_ADI_OSAL_SLOT_NOT_ALLOCATED,
    ADI_OSAL_MEM_TOO_SMALL            = E_ADI_OSAL_MEM_TOO_SMALL,
    ADI_OSAL_INVALID_ARGS             = E_ADI_OSAL_INVALID_ARGS

} ADI_OSAL_STATUS;






/*-------------------------------------------------------------------*
    Pointer to functions definitions
 *-------------------------------------------------------------------*/

/*
 *   ISR prototype definition - used for the pointer to an interrupt service routine
 */
typedef void (*ADI_OSAL_ISR_PTR)(void);

/*
 *   thread function prototype definition - used for the pointer to a thread
 */
typedef void (*ADI_OSAL_THREAD_PTR) (void *);

/*
 *   Callback function prototype definition - used for pointer to a callback function
 */
typedef ADI_OSAL_STATUS (*ADI_OSAL_CALLBACK_PTR) (void *);

/*
 *   Callback function prototype definition for Thread Local Storage Destruction
 *   it is different than regular callbacks because its input and outputs are predefined
 */
typedef void  *ADI_OSAL_SLOT_VALUE;             /*   Typedef for value to be stored in thread's local storage buffer. */
typedef void (*ADI_OSAL_TLS_CALLBACK_PTR) (ADI_OSAL_SLOT_VALUE Slot_value);




/*-------------------------------------------------------------------*
 *    OSAL Objects definitions                                       *
 *-------------------------------------------------------------------*/

/*
 *   Type definition for the thread's local storage slot number (starts at 0)
 */
typedef uint32_t ADI_OSAL_TLS_SLOT_NUM;

/*
 *   Typedef representing a thread priority level (0 is highest priority)
 */
typedef uint32_t ADI_OSAL_PRIORITY;

/*
 *   Typedef for a time represented in system ticks
 *
    valid values:
        0               - no wait/timeout (ADI_OSAL_TIMEOUT_NONE)
        1 .. 0xFFFFFFFE - delay/timeout in system ticks
        0xFFFFFFFF      - wait forever (ADI_OSAL_TIMEOUT_FOREVER)
*/
typedef uint32_t ADI_OSAL_TICKS;

/*
 *   Typedef for event flags (31 flags available)
 *    (See also ADI_OSAL_EVENT_FLAGxx definitions)
 */
typedef uint32_t ADI_OSAL_EVENT_FLAGS;

/*
 *  Enumerations for Event Flag Options  (used by adi_osal_EventPend() function)
 */
typedef enum
{
    ADI_OSAL_EVENT_FLAG_ANY = 0,                        /* Option to check whether any one of specified flag(s) is set. */
    ADI_OSAL_EVENT_FLAG_ALL                             /* Option to check whether all flags specified are set */
} ADI_OSAL_EVENT_FLAG_OPTION;

/*
 *   Enumerations for Interrupt Levels. This enum is used only in C
 *   and hence no corresponding "defines" for these values.
*/
typedef enum
{
    ADI_OSAL_IVG_NMI     = ik_nmi,
    ADI_OSAL_IVG_HWERR   = ik_hardware_err,
    ADI_OSAL_IVG_CTIMER  = ik_timer,
    ADI_OSAL_IVG_7       = ik_ivg7,
    ADI_OSAL_IVG_8       = ik_ivg8,
    ADI_OSAL_IVG_9       = ik_ivg9,
    ADI_OSAL_IVG_10      = ik_ivg10,
    ADI_OSAL_IVG_11      = ik_ivg11,
    ADI_OSAL_IVG_12      = ik_ivg12,
    ADI_OSAL_IVG_13      = ik_ivg13,
    ADI_OSAL_IVG_14      = ik_ivg14,
    ADI_OSAL_IVG_15      = ik_ivg15,
    ADI_OSAL_INVALID_IVG = num_interrupt_kind
} ADI_OSAL_IVG;

/*
 *   Defines the initialization options for priority inheritance support
 */
typedef enum {
    ADI_OSAL_PRIO_INHERIT_ENABLED,                      /* OSAL priority inheritance support is enable */
    ADI_OSAL_PRIO_INHERIT_DISABLED,                     /* OSAL priority inheritance support is disable */
    ADI_OSAL_PRIO_INHERIT_AUTO                          /* OSAL use the underlying RTOS settings for prio inheritance */
} ADI_OSAL_PRIO_INHERIT_OPTION;

/*
 * Structure defining the argument passed during OSAL initialization (adi_osal_Init)
 */
typedef struct __AdiOsalConfig
{
    ADI_OSAL_PRIO_INHERIT_OPTION    eEnablePrioInherit;             /* set priority inheritance initialization option */
    uint32_t                        nNumTLSSlots;                   /* number of TLS allocated (for each thread) */
    uint32_t                        nSysTimerPeriodInUsec;          /* indicate the system tick period in microseconds */
    void                            *pHeap;                         /* pointer to a memory location to use as a heap (4-bytes aligned) */
    uint32_t                        nHeapSizeBytes;                 /* size of the Heap in bytes */
} ADI_OSAL_CONFIG, *ADI_OSAL_CONFIG_PTR;

/*
 *  Structure used to define a Callback
 */
typedef struct __AdiOsalCallbackAttr
{
    ADI_OSAL_CALLBACK_PTR       pCallbackFunc;                      /* pointer to a function to execute by this callback */
    void                        *pParam;                            /* argument to a callback function */
} ADI_OSAL_CALLBACK_ATTR, *ADI_OSAL_CALLBACK_ATTR_PTR;

/*
 *   Structure containing the attributes of a thread (for thread creation)
 */
typedef struct __AdiOsalTaskAttr
{
    ADI_OSAL_THREAD_PTR pThreadFunc;                                /* address of function to invoke for this thread */
    uint32_t            nPriority;                                  /* priority level of this thread */
    void                *pStackBase;                                /* pointer to base address of thread stack */
    uint32_t            nStackSize;                                 /* stack size in bytes */
    void                *pParam;                                    /* app-specific parameter to pass to the thread function */
    const char_t *      szThreadName;                   			/* string defining the thread name */
} ADI_OSAL_THREAD_ATTR, *ADI_OSAL_THREAD_ATTR_PTR;

/*
 *   OSAL Code-base version information (OS-dependent)
 */
typedef struct __AdiOsalVersion
{
    uint16_t   nMajor;                      /* Major revision number - Changes when API incompatibilities are introduced */
    uint16_t   nMinor;                      /* Minor revision number - Changes if features are added */
    uint16_t   nPatch;                      /* Patch number - Changes when bug fixes are made */
    uint16_t   nBuild;                      /* Build revision - Contains the subversion revision of the code */
} ADI_OSAL_VERSION, *ADI_OSAL_VERSION_PTR;




/*-------------------------------------------------------------------*
          Prototypes for OSAL functions
 *-------------------------------------------------------------------*/
/* (globally-scoped functions) */


ADI_OSAL_STATUS adi_osal_GetVersion(ADI_OSAL_VERSION* pVersion);
bool            adi_osal_IsSchedulerActive(void);

/*-------  Prototypes for OS Initialization  function  -------*/

ADI_OSAL_STATUS adi_osal_Init(const ADI_OSAL_CONFIG *pConfig);
ADI_OSAL_STATUS adi_osal_OSStart(const void *pOSInitData,
                                 const ADI_OSAL_CALLBACK_ATTR *pStartCB,
                                 const ADI_OSAL_THREAD_ATTR *pStartThread);


/*-------  Prototypes for Timer APIs  -------*/

ADI_OSAL_STATUS adi_osal_TickPeriodInMicroSec(uint32_t *pnTickPeriod);
void            adi_osal_TimeTick(void);
ADI_OSAL_STATUS adi_osal_GetCurrentTick(uint32_t *pnTicks);


/*-------  Prototypes for Thread management APIs  -------*/

ADI_OSAL_STATUS adi_osal_ThreadCreate(ADI_OSAL_THREAD_HANDLE *phThread, const ADI_OSAL_THREAD_ATTR *pThreadAttr);
ADI_OSAL_STATUS adi_osal_ThreadDestroy(ADI_OSAL_THREAD_HANDLE const hThread);
ADI_OSAL_STATUS adi_osal_ThreadGetPrio(ADI_OSAL_THREAD_HANDLE const hThread, ADI_OSAL_PRIORITY *pnThreadPrio);
ADI_OSAL_STATUS adi_osal_ThreadSetPrio(ADI_OSAL_THREAD_HANDLE const hThread, ADI_OSAL_PRIORITY nNewPriority);
ADI_OSAL_STATUS adi_osal_ThreadSleep(ADI_OSAL_TICKS nTimeInTicks);
ADI_OSAL_STATUS adi_osal_ThreadGetHandle(ADI_OSAL_THREAD_HANDLE *phThread);
ADI_OSAL_STATUS adi_osal_ThreadGetName(ADI_OSAL_THREAD_HANDLE const hThread, char_t *pTaskName, uint32_t    nNumBytesToCopy);
ADI_OSAL_STATUS adi_osal_ThreadEnableCycleCounting(void);
ADI_OSAL_STATUS adi_osal_ThreadGetCycleCount(uint64_t *pnCycles);


/*-------  Prototypes for Thread Local Storage APIs  -------*/

ADI_OSAL_STATUS adi_osal_ThreadSlotAcquire(ADI_OSAL_TLS_SLOT_NUM *pnThreadSlotNum,
                                           ADI_OSAL_TLS_CALLBACK_PTR pTerminateCallbackFunc);
ADI_OSAL_STATUS adi_osal_ThreadSlotRelease(ADI_OSAL_TLS_SLOT_NUM nThreadSlotNum);
ADI_OSAL_STATUS adi_osal_ThreadSlotSetValue(ADI_OSAL_TLS_SLOT_NUM nThreadSlotNum, ADI_OSAL_SLOT_VALUE SlotValue);
ADI_OSAL_STATUS adi_osal_ThreadSlotGetValue(ADI_OSAL_TLS_SLOT_NUM nThreadSlotNum, ADI_OSAL_SLOT_VALUE *pSlotValue);


/*-------  Prototypes for semaphore APIs  -------*/

ADI_OSAL_STATUS adi_osal_SemCreate(ADI_OSAL_SEM_HANDLE *phSem, uint32_t nInitCount);
ADI_OSAL_STATUS adi_osal_SemDestroy(ADI_OSAL_SEM_HANDLE const hSem);
ADI_OSAL_STATUS adi_osal_SemPend(ADI_OSAL_SEM_HANDLE const hSem, ADI_OSAL_TICKS nTimeoutInTicks);
ADI_OSAL_STATUS adi_osal_SemPost(ADI_OSAL_SEM_HANDLE const hSem);


/*-------  Prototypes for mutex APIs  -------*/

ADI_OSAL_STATUS adi_osal_MutexCreate(ADI_OSAL_MUTEX_HANDLE *phMutex);
ADI_OSAL_STATUS adi_osal_MutexCreateStatic(void* const pMutexObject, uint32_t nMutexObjSize, ADI_OSAL_MUTEX_HANDLE *phMutex);
uint32_t        adi_osal_MutexGetMutexObjSize(void);
ADI_OSAL_STATUS adi_osal_MutexDestroy(ADI_OSAL_MUTEX_HANDLE const hMutex);
ADI_OSAL_STATUS adi_osal_MutexDestroyStatic(ADI_OSAL_MUTEX_HANDLE const hMutex);
ADI_OSAL_STATUS adi_osal_MutexPend(ADI_OSAL_MUTEX_HANDLE const hMutex, ADI_OSAL_TICKS nTimeoutInTicks);
ADI_OSAL_STATUS adi_osal_MutexPost(ADI_OSAL_MUTEX_HANDLE const hMutex);


/*-------  Prototypes for message queue APIs  -------*/

ADI_OSAL_STATUS adi_osal_MsgQueueCreate(ADI_OSAL_QUEUE_HANDLE *phMsgQ, void* aMsgQ[],
                                        uint32_t nMaxMsgs);
ADI_OSAL_STATUS adi_osal_MsgQueueDestroy(ADI_OSAL_QUEUE_HANDLE const hMsgQ);
ADI_OSAL_STATUS adi_osal_MsgQueuePost(ADI_OSAL_QUEUE_HANDLE const hMsgQ, void  *pMsg);
ADI_OSAL_STATUS adi_osal_MsgQueuePend(ADI_OSAL_QUEUE_HANDLE const hMsgQ, void **ppMsg,
                                      ADI_OSAL_TICKS nTimeoutInTicks);


/*-------  Prototypes for events APIs  -------*/

ADI_OSAL_STATUS adi_osal_EventGroupCreate(ADI_OSAL_EVENT_HANDLE *phEventGroup);
ADI_OSAL_STATUS adi_osal_EventGroupDestroy(ADI_OSAL_EVENT_HANDLE const hEventGroup);
ADI_OSAL_STATUS adi_osal_EventPend(ADI_OSAL_EVENT_HANDLE const hEventGroup,
                                   ADI_OSAL_EVENT_FLAGS nRequestedEvents,
                                   ADI_OSAL_EVENT_FLAG_OPTION eGetOption,
                                   ADI_OSAL_TICKS nTimeoutInTicks,
                                   ADI_OSAL_EVENT_FLAGS *pnReceivedEvents);
ADI_OSAL_STATUS adi_osal_EventSet(ADI_OSAL_EVENT_HANDLE const hEventGroup, ADI_OSAL_EVENT_FLAGS nEventFlags);
ADI_OSAL_STATUS adi_osal_EventClear(ADI_OSAL_EVENT_HANDLE const hEventGroup, ADI_OSAL_EVENT_FLAGS nEventFlags);


/*-------  Prototypes for Critical section code protection APIs  -------*/

void adi_osal_SchedulerLock(void);
ADI_OSAL_STATUS adi_osal_SchedulerUnlock(void);
void adi_osal_EnterCriticalRegion(void);
void adi_osal_ExitCriticalRegion(void);


/*-------  Prototypes for ISR control APIs  -------*/

ADI_OSAL_STATUS adi_osal_ISRInstall(ADI_OSAL_IVG eIvgLevel, ADI_OSAL_ISR_PTR pISRFunc, bool bAllowNesting);
ADI_OSAL_STATUS adi_osal_ISRUninstall(ADI_OSAL_IVG eIvgLevel);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#else
/*  assembly language specific macros and extern declarations. */

/* These functions may be called from an ISR (assembly)  */
.extern _adi_osal_SemPost;
.extern _adi_osal_TimeTick;
.extern _adi_osal_MsgQueuePost;
.extern _adi_osal_EventSet;
.extern _adi_osal_EventClear;

#endif  /* if !defined(_LANGUAGE_C) */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_OSAL_H__ */
