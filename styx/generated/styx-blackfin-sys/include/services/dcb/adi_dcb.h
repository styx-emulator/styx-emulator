/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_dcb.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            DCB Manager Header File

*********************************************************************************/

#ifndef __ADI_DCB_H__
#define __ADI_DCB_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <services/services.h>

#if !defined(_LANGUAGE_ASM)

/*********************************************************************************
* Result codes
*********************************************************************************/
typedef enum ADI_DCB_RESULT {
    ADI_DCB_RESULT_SUCCESS=0,               // normal success
    ADI_DCB_RESULT_FAILED=1,                // generic fail

    ADI_DCB_RESULT_START=ADI_DCB_ENUMERATION_START,

    ADI_DCB_RESULT_NO_MEMORY,               // insufficient memory to set up DCB manager,
                                            // queue servers, or full queue
    ADI_DCB_RESULT_NOT_INITIALIZED,         // DCB service has not been initialized
    ADI_DCB_RESULT_QUEUE_IN_USE,            // The queue IVG level requested is already taken
    ADI_DCB_RESULT_NO_SUCH_QUEUE,           // The server handle is not recognised
    ADI_DCB_RESULT_NONE_FLUSHED,            // No callbacks for given function pointer found in queue
    ADI_DCB_RESULT_FLUSHED_OK,              // Callbacks successfully flushed
    ADI_DCB_RESULT_BAD_COMMAND,             // The command in not recognized or the value is incorrect
    ADI_DCB_RESULT_ALREADY_INITIALIZED,     // DCB service has already been initialized
    ADI_DCB_RESULT_BAD_QUEUE_SIZE_MACRO,    // the ADI_DCB_QUEUE_SIZE macro is invalid (internal error)
    ADI_DCB_RESULT_BAD_ENTRY_SIZE_MACRO,    // the ADI_DCB_ENTRY_SIZE macro is invalid (internal error)

    /***********  obsoleted enumerations ***********/
    ADI_DCB_RESULT_CALL_IGNORED = ADI_DCB_RESULT_NOT_INITIALIZED    // obsoleted
} ADI_DCB_RESULT;

/*********************************************************************************
* Command values
*********************************************************************************/
typedef enum ADI_DCB_COMMAND {
    ADI_DCB_CMD_START=ADI_DCB_ENUMERATION_START,
    ADI_DCB_CMD_END,
    ADI_DCB_CMD_PAIR,
    ADI_DCB_CMD_TABLE,
    ADI_DCB_CMD_FLUSH_QUEUE
} ADI_DCB_COMMAND;

typedef struct ADI_DCB_COMMAND_PAIR {
    ADI_DCB_COMMAND kind;
    void *value;
} ADI_DCB_COMMAND_PAIR;

/*********************************************************************************
* prototype for Client callback function
*********************************************************************************/
typedef void (*ADI_DCB_CALLBACK_FN) (void*, u32, void*);

/*********************************************************************************
* prototype for callback mgr Deferred Routine function (for interfacing with VDK)
*********************************************************************************/
struct ADI_DCB_ENTRY_HDR;
typedef void (*ADI_DCB_DEFERRED_FN) (struct ADI_DCB_ENTRY_HDR *);

/*********************************************************************************
* Queue Entry Header Structure
*********************************************************************************/
typedef struct ADI_DCB_ENTRY_HDR
{
    struct ADI_DCB_ENTRY_HDR *pNext;             // Next entry (set by VDK)
    ADI_DCB_DEFERRED_FN      pDeferredFunction;  // Set to adi_dcb_DeferredFunction by
                                                 // DCB Manager
} ADI_DCB_ENTRY_HDR;


/*********************************************************************************
* Handle to queue server and macros to give sizes of both queue server and entry
*********************************************************************************/
typedef void *ADI_DCB_HANDLE;

/*********************************************************************************
* Size macros. One queue server with 4 entries in its queue requires
* ADI_DCB_QUEUE_SIZE + 4*ADI_DCB_ENTRY_SIZE bytes
*/
// Size of queue server
#define ADI_DCB_QUEUE_SIZE 36

// Size of each entry in the queue
#define ADI_DCB_ENTRY_SIZE 24

/*********************************************************************************
* API prototypes
*********************************************************************************/

#ifdef __cplusplus
extern "C" {

#endif

ADI_DCB_RESULT
adi_dcb_Init(                                   // initialises DCB manager
        void                *ServerMemData,     // address of memory location to use for DCB manager
        size_t              szServer,           // length of available memory to use for DCB manager
        u32                 *NumServers,        // On return, the number of queue servers the available
                                                // memory can support
        void                *hCriticalRegionData // Handle to data area containing critical region data
        );

ADI_DCB_RESULT
adi_dcb_Open(                                   // Opens a Queue Server
        u32                 IvgLevel,           // Required IVG level for the queue
        void                *QueueMemData,      // address of memory location to use for queue
        size_t              szQueue,            // length of available memory to use for queue
        u32                 *NumEntries,        // On return, the number of callback entries the
                                                // available memory can support
        ADI_DCB_HANDLE      *hServer            // On return, contains the handle to the queue server
);

ADI_DCB_RESULT
adi_dcb_Post(                                   // Posts an deferred callback on the required queue
        ADI_DCB_HANDLE      hServer,            // The handle of the required queue server
        u32                 Priority,           // The software priority of the entry
        ADI_DCB_CALLBACK_FN Callback,           // The address of the callback function
        void                *pHandle,           // The value of the first argument to the callback function
        u32                 u32Arg,             // The value of the second argument to the callback function
        void                *pArg               // The value of the third argument to the callback function
);

ADI_DCB_RESULT
adi_dcb_Remove(                                 // Flushes callbacks from the server queue
        ADI_DCB_HANDLE      hServer,            // The handle of the queue server to flush
        ADI_DCB_CALLBACK_FN Callback            // The address of the callback function to be removed from queue
);

ADI_DCB_RESULT
adi_dcb_Close(                                  // Closes the specified queue server
        ADI_DCB_HANDLE      hServer             // The handle of the queue server to close
);

ADI_DCB_RESULT
adi_dcb_Control(                                // Performs certain commands (placeholder for future use)
        ADI_DCB_HANDLE hServer,
        ADI_DCB_COMMAND Command,
        void *Value
);

ADI_DCB_RESULT
adi_dcb_Terminate(                              // Dissociates resources assigne to the DCB manager
        void
);

#ifdef __cplusplus
}
#endif

#endif //!defined(_LANGUAGE_ASM)

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_DCB_H__ */
