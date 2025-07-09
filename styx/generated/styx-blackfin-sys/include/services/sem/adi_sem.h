/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_sem.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the Semaphore Service.

*********************************************************************************/

#ifndef __ADI_SEM_H__
#define __ADI_SEM_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)


/******************************************************************

    Macros for pending on a semaphore

******************************************************************/

#define ADI_SEM_TIMEOUT_IMMEDIATE   (0xffffffff)    // return immediately if semaphore not acquired
#define ADI_SEM_TIMEOUT_FOREVER     (0)             // don't return until semaphore is acquired


/******************************************************************

    Macro for the handle to a semaphore

******************************************************************/

typedef void    *ADI_SEM_HANDLE;        // handle to a semaphore


/******************************************************************

    Operating Environment Specific Information

******************************************************************/

// default to standalone if the user hasn't specified an operating environment
#if !defined(ADI_SSL_STANDALONE) && !defined(ADI_SSL_VDK) && !defined(ADI_SSL_UCOS)
#define ADI_SSL_STANDALONE
#endif


// standalone
#if defined(ADI_SSL_STANDALONE)

#define         ADI_SEM_SEMAPHORE_MEMORY    (16)                        // memory needed for each semaphore that's simultaneously active
typedef void    (*ADI_SEM_PENDING_FUNCTION) (ADI_SEM_HANDLE Handle);    // pending function; called when we need to pend
typedef void    (*ADI_SEM_POSTING_FUNCTION) (ADI_SEM_HANDLE Handle);    // posting function; called when posted

typedef struct {    // semaphore attributes in a standalone operating environment
    ADI_SEM_PENDING_FUNCTION    PendingFunction;  // called when we need to pend, NULL if not used
    ADI_SEM_POSTING_FUNCTION    PostingFunction;  // called when a semaphore is posted, NULL if not used
} ADI_SEM_OS_ATTRIBUTES;

#endif


// VDK
#if defined(ADI_SSL_VDK)

#define                 ADI_SEM_SEMAPHORE_MEMORY    (0) // memory needed for each semaphore that's simultaneously active

typedef struct {    // semaphore attributes in a VDK operating environment
    u32 inMaxCount;         // maximum value for the semaphore
    u32 inInitialDelay;     // number of ticks before posting a periodic semaphore
    u32 inPeriod;           // number of ticks to sleep at each cycle after semaphore is posted
} ADI_SEM_OS_ATTRIBUTES;

#endif


// uC/OS-II
#if defined(ADI_SSL_UCOS)

#define             ADI_SEM_SEMAPHORE_MEMORY    (0)                         // memory needed for each semaphore that's simultaneously active

typedef struct {    // semaphore attributes in a uC/OS-II operating environment
} ADI_SEM_OS_ATTRIBUTES;

#endif


// Velocity
#if defined(ADI_SSL_VELOCITY)

#warning Warning::Velocity support is not complete!

#define         ADI_SEM_SEMAPHORE_MEMORY    (0)                         // memory needed for each semaphore that's simultaneously active

typedef struct {    // semaphore attributes in a Velocity operating environment
    u32                 PendMode;       // action when pending on a semaphore
    char                *pName;         // string for naming the semaphore
} ADI_SEM_OS_ATTRIBUTES;

#endif





/******************************************************************

Return codes

******************************************************************/

typedef enum {
    ADI_SEM_RESULT_SUCCESS=0,                       /* Generic success */
    ADI_SEM_RESULT_FAILED=1,                        /* Generic failure */
    ADI_SEM_RESULT_START=ADI_SEM_ENUMERATION_START, /* defined in services.h */
    ADI_SEM_RESULT_NOT_INITIALIZED,                 /* (0xc0001) RTC service has not been initialized */
    ADI_SEM_RESULT_ALREADY_INITIALIZED,             /* (0xc0002) service has already been initialized */
    ADI_SEM_RESULT_BAD_HANDLE,                      /* (0xc0003) Invalid semaphore handle */
    ADI_SEM_RESULT_NOT_ACQUIRED,                    /* (0xc0004) semaphore was not acquired */
    ADI_SEM_RESULT_TIMEOUTS_NOT_SUPPORTED,          /* (0xc0005) timeouts not supported */
    ADI_SEM_RESULT_NONE_AVAILABLE,                  /* (0xc0006) no semaphores are available */
    ADI_SEM_RESULT_NOT_SUPPORTED,                   /* (0xc0007) not a supported feature */
    ADI_SEM_RESULT_BAD_MEMORY_SIZE,                 /* (0xc0008) ADI_SEM_SEMAPHORE_MEMORY is not correct */
    ADI_SEM_RESULT_BAD_TIMEOUT_MODE,                /* (0xc0009) timeout value is not supported */
    ADI_SEM_RESULT_OS_ERROR                         /* (0xc000a) OS returned an error */
} ADI_SEM_RESULT;


/*************************************************************************
 *
 *   API functions
 *
*************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

ADI_SEM_RESULT adi_sem_Init(        // initializes the semaphore service
    void            *pMemory,           // pointer to memory
    const size_t    MemorySize,         // size of memory (in bytes)
    u32             *pMaxSemaphores,    // number of semaphores that can be supported
    void            *pCriticalRegionArg // parameter for critical region function
);

ADI_SEM_RESULT adi_sem_Terminate(void); // terminates the semaphore service

ADI_SEM_RESULT adi_sem_Create(      // creates a semaphore
    u32                     Count,          // initial count
    ADI_SEM_HANDLE          *pHandle,       // location where the semaphore handle is stored
    ADI_SEM_OS_ATTRIBUTES   *pOSAttributes  // OS specific attributes for the semaphore, NULL if not used
);

ADI_SEM_RESULT adi_sem_Delete(      // deletes a semaphore
    ADI_SEM_HANDLE  Handle              // semaphore handle
);

ADI_SEM_RESULT adi_sem_Pend(        // pends on a semaphore
    ADI_SEM_HANDLE  Handle,             // semaphore handle
    u32             Timeout             // timeout, 0 = wait forever, non-zero = wait for Timeout time/clocks, 0xffffffff = return immediately
);

ADI_SEM_RESULT adi_sem_Post(        // posts a semaphore
    ADI_SEM_HANDLE  Handle              // semaphore handle
);

ADI_SEM_RESULT adi_sem_Query(       // queries a semaphore's count
    ADI_SEM_HANDLE  Handle,             // semaphore handle
    u32             *pCount             // location where the semaphore count is stored
);

#ifdef __cplusplus
}

#endif

#endif /* Not ASM */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /*__ADI_SEM_H__ */
