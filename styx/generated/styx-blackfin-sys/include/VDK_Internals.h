#ifndef VDK_INTERNALS_H_
#define VDK_INTERNALS_H_


#ifndef SEMAPHORE_H_
#define SEMAPHORE_H_

#ifndef _TMK_H_
#define _TMK_H_

#if defined (DO_NOT_INLINE)
#undef TMK_INLINE
#undef LCK_INLINE
#endif
#include <stddef.h>

#ifndef _LCK_H_
#define _LCK_H_
#include <assert.h>
#ifdef __ADSPBLACKFIN__
#include <sys/platform.h>
#endif
#ifdef __ADSPTS20x__
#include <defts201.h>
#include <sysreg.h>
#endif
#ifdef __ADSPTS101__
#include <defts101.h>
#include <sysreg.h>
#endif
#ifdef __ADSP21000__
#include <sysreg.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_GENERIC_LOCKING
#error Generic locking not tested recently, and implemented only for Blackfin
#endif

#define LCK_MIN_PRECEDENCE    1
#define LCK_MAX_PRECEDENCE    255

#define ACQUIRE_SPINLOCK(ptr)
#define RELEASE_SPINLOCK(ptr)

#ifndef NDEBUG
#define debug(x) (x)
#define debug_swap_precedence(pLock)          \
{                                             \
    unsigned char tmp = (pLock)->precedence;  \
    (pLock)->precedence = lck_currLockPrecedence; \
    lck_currLockPrecedence = tmp;                 \
}
#else
#define debug(x)
#define debug_swap_precedence(pLock)
#endif

#if defined(__ADSPBLACKFIN__)
typedef unsigned short LCK_IMaskUInt;
typedef unsigned int   LCK_LockState;
#elif defined(__ADSPTS__)
typedef unsigned long long LCK_IMaskUInt;
typedef unsigned long long LCK_LockState;
#elif defined(__ADSP21000__)
typedef unsigned int LCK_IMaskUInt;
typedef unsigned int LCK_LockState;
#else
#error Unknown processor family
#endif


typedef struct LCK_Lock {
    volatile unsigned char spinByte:8;


    unsigned char precedence:8;

    unsigned char lockHeld:8;

    unsigned char irpl:8;


} LCK_Lock;

extern unsigned int lck_InterruptLocksHeld;
extern unsigned char lck_currLockPrecedence;

void
LCK_InitInterruptLock(
    LCK_Lock *pLock,
    int precedence,
    LCK_IMaskUInt interruptMask
);
void
LCK_InitGlobalInterruptLock(
    LCK_Lock *pLock,
    int precedence
);
LCK_LockState
LCK_AcquireGlobalInterruptLock(
    LCK_Lock *pLock
);
void
LCK_ReleaseGlobalInterruptLock(
    LCK_Lock *pLock,
    LCK_LockState state
);
LCK_LockState
LCK_AcquireInterruptLock(
    LCK_Lock *pLock
);
void
LCK_ReleaseInterruptLock(
    LCK_Lock *pLock,
    LCK_LockState state
);
LCK_LockState
LCK_AcquireRescheduleInterruptLock(
    LCK_Lock *pLock
);
void
LCK_ReleaseRescheduleInterruptLock(
    LCK_Lock *pLock,
    LCK_LockState state
);
LCK_LockState
LCK_MaskRescheduleInterruptLockForThreadLevel(
    LCK_Lock *pLock
);
void
LCK_AcquireInterruptLockFromInterruptLevel(
    LCK_Lock *pLock
);
void
LCK_ReleaseInterruptLockFromInterruptLevel(
    LCK_Lock *pLock
);
void
LCK_ReleaseGlobalAndRescheduleInterruptLocks(
    LCK_Lock *pGlobalLock,
    const LCK_LockState globalState,
    LCK_Lock *pMasterLock,
    const LCK_LockState masterState
);
LCK_LockState
LCK_MaskInterruptLockForThreadLevel(
    LCK_Lock *pLock
);
void
LCK_ChangeInterruptMaskBits(
    LCK_Lock *pLock,
    LCK_LockState *pState,
    LCK_IMaskUInt setBits,
    LCK_IMaskUInt clrBits
);
LCK_IMaskUInt
LCK_GetInterruptMaskBits(
    LCK_Lock *pLock,
    LCK_LockState state
);
#ifdef __ADSP21000__
void
LCK_ReleaseGlobalInterruptLockAndIdle(
    LCK_Lock *pLock,
    LCK_LockState state
);
#endif

#if defined(__ADSPBLACKFIN__)
#define LCK_INIT_GLOBAL_INTERRUPT_LOCK(precedence) \
    { 0,      \
      (precedence),        \
      0,       \
      11   \
    }
#elif defined(__ADSPTS20x__)
#define LCK_INIT_GLOBAL_INTERRUPT_LOCK(precedence) \
    { 0,      \
      (precedence),        \
      0,       \
      64   \
    }
#elif defined(__ADSPTS101__)
#define LCK_INIT_GLOBAL_INTERRUPT_LOCK(precedence) \
    { 0,      \
      (precedence),        \
      0,       \
      60   \
    }
#elif defined(__ADSP21000__)
#define LCK_INIT_GLOBAL_INTERRUPT_LOCK(precedence) \
    { 0,      \
      (precedence),        \
      0,       \
      32   \
    }
#else
#error Unknown processor family
#endif




#ifdef __cplusplus
}
#endif
#endif
#ifdef __cplusplus
extern "C" {
#endif



#define TMK_MIN_LOCK_PRECEDENCE    LCK_MIN_PRECEDENCE
#define TMK_KERNEL_LOCK_PRECEDENCE 128
#define TMK_MAX_LOCK_PRECEDENCE    LCK_MAX_PRECEDENCE



#if defined(__ADSPBLACKFIN__)
typedef LCK_IMaskUInt TMK_IMaskUInt;
typedef LCK_LockState   TMK_LockState;
#elif defined(__ADSPTS__)
typedef LCK_IMaskUInt TMK_IMaskUInt;
typedef LCK_LockState TMK_LockState;
#elif defined(__ADSP21000__)
typedef LCK_IMaskUInt TMK_IMaskUInt;
typedef LCK_LockState TMK_LockState;
#else
#error Unknown processor family
#endif
typedef enum TMK_HookSelector
{
    TMK_RUNTIMEHOOK,
    TMK_INTERRUPTHOOK,
    TMK_FIRSTTIMEHOOK,
    TMK_KILLTHREADHOOK,
	TMK_NUM_HOOK_FNS
} TMK_HookSelector;




typedef struct TMK_TimeElement {
    struct TMK_TimeElement *pNext;
    struct TMK_TimeElement *pPrev;
    unsigned int            tickNumber;

    void                  (*pfTimeout)(struct TMK_TimeElement *);
} TMK_TimeElement;

typedef struct TMK_DpcElement {
    struct TMK_DpcElement *pNext;

    void                 (*pfInvoke)(struct TMK_DpcElement *);
} TMK_DpcElement;

typedef struct TMK_Thread {

    struct TMK_Thread *pNext;
    struct TMK_Thread *pPrev;
    void              *pStuff;
#if defined(__ADSPTS__)
    unsigned int       priority;
    int                runStatus;
    unsigned int       contextLevel;
    void              *pContextSaveJ;
    void              *pContextSaveK;
#elif defined(__ADSPBLACKFIN__)
    unsigned char      priority;
    char               runStatus;
    unsigned char      contextLevel;
    void              *pContextSave;
    void              *pStackBase;
#elif defined(__ADSP21000__)
    unsigned int       priority;
    int                runStatus;
    unsigned int       contextLevel;
    void              *pContextSave;
#else
#error Unknown processor family
#endif
} TMK_Thread;
typedef struct TMK_ThreadList {
    struct TMK_Thread *pHead;
    struct TMK_Thread *pTail;
} TMK_ThreadList;
typedef LCK_Lock TMK_Lock;



typedef void (*TMK_PFCSwitch)(TMK_Thread *, TMK_Thread *);
typedef void (*TMK_PFDispatch)(void);



unsigned int
TMK_QueryContextRecordSize(void);
void
TMK_InitThread
(
    TMK_Thread  *pThread,
    unsigned int priority,
    void       (*pfRunFunc)(TMK_Thread*),
#if defined(__ADSPTS__)
    void           *pStackJ,
    void           *pStackK,
    void           *pCtxtJ,
    void           *pCtxtK
#elif defined(__ADSPBLACKFIN__)
    void           *pStack,
    void           *pStackBase
#elif defined(__ADSP21000__)
    void           *pStack,
    unsigned int    stackSize,
    void           *pCtxt
#else
#error Unknown processor family
#endif
);
void
TMK_DeInitThread
(
    TMK_Thread *pThread
#if defined(__ADSPTS__)
    ,
    void           **ppCtxtJ,
    void           **ppCtxtK
#elif defined(__ADSPBLACKFIN__)
#elif defined(__ADSP21000__)
    ,
    void           **ppCtxt
#else
#error Unknown processor family
#endif
);
bool
TMK_ChangeThreadPriority
(
    TMK_Thread  *pThread,
    unsigned int priority
);



void
TMK_MakeThreadReady
(
    TMK_Thread *pThread
);
void
TMK_MakeThreadNotReady
(
    TMK_Thread *pThread,
    int newStatus
);
bool
TMK_YieldThread(
    TMK_Thread *pThread
);



TMK_Thread *
TMK_GetCurrentThread(void);
bool
TMK_AtKernelLevel(void);
void
TMK_Reschedule(void);
void
TMK_Block(void);
void
TMK_Run(void);
void
TMK_Stop(void);
void
TMK_SuspendScheduling(void);
void
TMK_ResumeScheduling(void);
bool
TMK_IsSchedulingSuspended(void);
TMK_PFCSwitch
TMK_HookThreadSwitch(TMK_HookSelector which, TMK_PFCSwitch pfHookFn);
TMK_PFDispatch
TMK_HookDispatch(TMK_PFDispatch pfHookFn);



void
TMK_InitTimeElement(
    TMK_TimeElement *pElement,
    void           (*pfTimeout)(struct TMK_TimeElement *)
);
void
TMK_SetTimeout(
    TMK_TimeElement *pElement,
    int timeout
);
int
TMK_CancelTimeout(
    TMK_TimeElement *pElement
);
int
TMK_ResetTimeout(
    TMK_TimeElement *pElement,
    int timeout
);
int
TMK_GetTimeRemaining(
    TMK_TimeElement *pElement
);
#if defined(__ADSPBLACKFIN__)
#pragma regs_clobbered "R0 P1"
#endif
unsigned int
TMK_GetUptime(void);



void
TMK_InitDpcElement(
    TMK_DpcElement *pDpc,
    void          (*pfInvoke)(struct TMK_DpcElement *)
);
#if defined(__ADSPBLACKFIN__)
#pragma regs_clobbered "P1"
#endif
void
TMK_InsertQueueDpc(
    TMK_DpcElement *pDPC
);



void
TMK_InitThreadList(
    TMK_ThreadList *pList
);
void
TMK_AppendThreadToList(
    TMK_ThreadList *pList,
    TMK_Thread     *pThread
);
void
TMK_AddThreadToOrderedList(
    TMK_ThreadList *pList,
    TMK_Thread     *pThread
);
void
TMK_RemoveThreadFromList(
    TMK_Thread     *pThread
);
TMK_Thread *
TMK_GetNextThreadFromList(
    TMK_ThreadList *pList
);
TMK_Thread *
TMK_QueryNextThreadInList(
    TMK_ThreadList *pList
);
int
TMK_QueryThreadlist(
    TMK_ThreadList *pList,
    TMK_Thread     *vpThreads[],
    int arraySize
);
bool
TMK_IsThreadListEmpty(
    TMK_ThreadList *pList
);



#define TMK_InitInterruptLock(pLock, precedence, interruptMask) \
        LCK_InitInterruptLock((pLock), (precedence), (interruptMask))
#define TMK_InitGlobalInterruptLock(pLock, precedence) \
        LCK_InitGlobalInterruptLock((pLock), (precedence))
#define TMK_AcquireGlobalInterruptLock(pLock)  \
        LCK_AcquireGlobalInterruptLock((pLock))
#define TMK_ReleaseGlobalInterruptLock(pLock, state) \
        LCK_ReleaseGlobalInterruptLock((pLock), (state))
#define TMK_AcquireInterruptLock(pLock) \
        LCK_AcquireInterruptLock((pLock))
#define TMK_ReleaseInterruptLock(pLock, state) \
        LCK_ReleaseInterruptLock((pLock), (state))
#define TMK_AcquireInterruptLockFromInterruptLevel(pLock) \
        LCK_AcquireInterruptLockFromInterruptLevel((pLock))
#define TMK_ReleaseInterruptLockFromInterruptLevel(pLock) \
        LCK_ReleaseInterruptLockFromInterruptLevel((pLock))
#define TMK_ChangeInterruptMaskBits(pLock, pState, setBits, clrBits) \
        LCK_ChangeInterruptMaskBits((pLock), (pState), (setBits), (clrBits))
#define TMK_GetInterruptMaskBits(pLock, state) \
        LCK_GetInterruptMaskBits((pLock), (state))



void
TMK_AcquireMasterKernelLock(void);
#if defined(__ADSPBLACKFIN__)
#pragma regs_clobbered "P0 P1 P2 R0 R1 R2 R3 ASTAT RETS"
#endif
void
TMK_ReleaseMasterKernelLock(void);
void
TMK_AcquireMasterKernelLockFromKernelLevel(void);
void
TMK_ReleaseMasterKernelLockFromKernelLevel(void);
void
TMK_ReleaseGlobalInterruptAndMasterKernelLocks(
    TMK_Lock *pLock,
    TMK_LockState state
);



void
TMK_Initialize(void);




#define TMK_GET_ENCLOSING(T, member, ptr) ((T *)(((char*)(ptr)) - offsetof(T, member)))
#define TMK_INIT_GLOBAL_INTERRUPT_LOCK(precedence) \
        LCK_INIT_GLOBAL_INTERRUPT_LOCK(precedence)
#if defined(__ADSPBLACKFIN__)
#define TMK_INIT_RESCHEDULE_INTERRUPT_LOCK(precedence) \
    { 0,         \
      (precedence),           \
      0,          \
      2   \
    }
#elif defined(__ADSPTS20x__)
#define TMK_INIT_RESCHEDULE_INTERRUPT_LOCK(precedence) \
    { 0,         \
      (precedence),           \
      0,          \
      1   \
    }
#elif defined(__ADSPTS101__)
#define TMK_INIT_RESCHEDULE_INTERRUPT_LOCK(precedence) \
    { 0,         \
      (precedence),           \
      0,          \
      3   \
    }
#elif defined(__ADSP21000__)
#ifdef __2106x__
#define TMK_INIT_RESCHEDULE_INTERRUPT_LOCK(precedence) \
    { 0,         \
      (precedence),           \
      0,          \
      2   \
    }
#else
#define TMK_INIT_RESCHEDULE_INTERRUPT_LOCK(precedence) \
    { 0,         \
      (precedence),           \
      0,          \
      3   \
    }
#endif
#else
#error Unknown processor family
#endif




#ifdef __cplusplus
}
#endif
#endif

#ifndef VDK_API_H_
#define VDK_API_H_


#define VDK_API_VERSION_NUMBER 0x05000000
#include <limits.h>
enum DeviceDescriptor   {lastDeviceDescriptor = -1};

#ifdef _MISRA_RULES
#include <misra_types.h>
#pragma diag(push)
#pragma diag(suppress: misra_rule_5_1:"VDK Public APIs have mangled names which may be longer than 31 characters.")
#pragma diag(suppress: misra_rule_5_3:"Type declarations have to be compatible with C++")
#pragma diag(suppress:misra_rule_5_4:"Typedefs need to be compatible with C++ so the identifiers need to appear twice" )
#pragma diag(suppress:misra_rule_5_6:"Typedefs need to be compatible with C++ so the identifiers need to appear twice" )
#pragma diag(suppress:misra_rule_5_7:"HistoryEvent and PayloadDetails have an element called type")
#pragma diag(suppress:misra_rule_6_3:"API types are published and should not change to specify size and sign. This warning only happens misra-strict")
#pragma diag(suppress: misra_rule_8_5:"VDK needs to define some constant variables")
#pragma diag(suppress: misra_rule_18_1:"Some type definitions are not available to users but VDK needs to declare structures to create pointers")
#pragma diag(suppress: misra_rule_18_4:"DispatchUnion must be a union and they are not allowed in MISRA-C")
#pragma diag(suppress: misra_rule_19_4:"NAMESPACE_DECL_ cannot have the format required for macros in MISRA")
#pragma diag(suppress: misra_rule_19_6:"Header needs to undef NAMESPACE_DECL_ macros")
#pragma diag(suppress: misra_rule_19_7:"VDK uses NAMESPACE_DECL_ macro to have the correct API and type names in C and C++")
#pragma diag(suppress: misra_rule_19_13:"NAMESPACE_DECL_ requires the use of the ## operator")
#endif

#ifdef __cplusplus
#define NAMESPACE_(X_)	    VDK::X_
#define NAMESPACE_DECL_(X_)	X_
#else
#define NAMESPACE_(X_)	    VDK_ ## X_
#define NAMESPACE_DECL_(X_)	VDK_ ## X_
#endif
#ifdef __cplusplus
namespace VDK
{
#endif


#ifndef ProcessorSpecificTypes_H_
#define ProcessorSpecificTypes_H_

typedef unsigned int NAMESPACE_DECL_(IMASKStruct);
#define VDK_STACK_ALIGNMENT_ 4
#endif
 	typedef enum ThreadType NAMESPACE_DECL_(ThreadType);
 	typedef enum ThreadID NAMESPACE_DECL_(ThreadID);
	typedef unsigned int NAMESPACE_DECL_(Ticks);
	typedef enum SemaphoreID NAMESPACE_DECL_(SemaphoreID);
	typedef enum PoolID NAMESPACE_DECL_(PoolID);
	typedef enum DeviceFlagID NAMESPACE_DECL_(DeviceFlagID);
	typedef enum IOTemplateID NAMESPACE_DECL_(IOTemplateID);
	typedef enum IOID NAMESPACE_DECL_(IOID);
    typedef enum DeviceDescriptor NAMESPACE_DECL_(DeviceDescriptor);
	typedef enum EventID NAMESPACE_DECL_(EventID);
	typedef enum EventBitID NAMESPACE_DECL_(EventBitID);
	typedef enum HeapID NAMESPACE_DECL_(HeapID);
	typedef enum MessageID NAMESPACE_DECL_(MessageID);
	typedef enum MutexID NAMESPACE_DECL_(MutexID);
    typedef enum FifoID NAMESPACE_DECL_(FifoID);
	typedef enum RoutingNodeID NAMESPACE_DECL_(RoutingNodeID);
	typedef enum MarshalledTypeID NAMESPACE_DECL_(MarshalledTypeID);
	#define INVALID_ID  -1
	typedef bool (*NAMESPACE_DECL_(BootFuncPointers) )( void);

	bool InitBootThreads(void);
	bool InitBootSemaphores(void);
	bool InitBootMemoryPools(void);
	bool InitBootIOObjects(void);
	bool InitBootDeviceFlags(void);
	bool InitRoutingThreads(void);
	bool InitISRMask(void);
	bool SetTimer(void);
	bool InitRoundRobin(void);
#if defined (__ADSPTS__) && !defined (__ADSPTS1XX__)
	bool SetTimer0(void);
#endif

	typedef enum
  	{
	    NAMESPACE_DECL_(kUnknown) = -1,
		NAMESPACE_DECL_(kReady) = 0,
		NAMESPACE_DECL_(kSemaphoreBlocked) = 1,
		NAMESPACE_DECL_(kEventBlocked) = 2,
        NAMESPACE_DECL_(kDeviceFlagBlocked) = 3,
		NAMESPACE_DECL_(kSemaphoreBlockedWithTimeout) = 4,
		NAMESPACE_DECL_(kEventBlockedWithTimeout) = 5,
        NAMESPACE_DECL_(kDeviceFlagBlockedWithTimeout) = 6,
		NAMESPACE_DECL_(kSleeping) = 7,
		NAMESPACE_DECL_(kMessageBlocked) = 8,
		NAMESPACE_DECL_(kMessageBlockedWithTimeout) = 9,
		NAMESPACE_DECL_(kMutexBlocked) = 12,
        NAMESPACE_DECL_(kFifoPendBlocked) = 13,
        NAMESPACE_DECL_(kFifoPendBlockedWithTimeout) = 14,
        NAMESPACE_DECL_(kFifoPostBlocked) = 15,
        NAMESPACE_DECL_(kFifoPostBlockedWithTimeout) = 16
	} NAMESPACE_DECL_(ThreadStatus);
	typedef enum
    	{
		NAMESPACE_DECL_(kUnknownThreadType) =          INT_MIN,
		NAMESPACE_DECL_(kUnknownThread) =              -2147483647,
		NAMESPACE_DECL_(kInvalidThread) =              -2147483646,
		NAMESPACE_DECL_(kThreadCreationFailure) =      -2147483645,
		NAMESPACE_DECL_(kUnknownSemaphore) =           -2147483644,
		NAMESPACE_DECL_(kUnknownEventBit) =            -2147483643,
		NAMESPACE_DECL_(kUnknownEvent) =               -2147483642,
		NAMESPACE_DECL_(kInvalidPriority) =            -2147483641,
		NAMESPACE_DECL_(kInvalidDelay) =               -2147483640,
		NAMESPACE_DECL_(kSemaphoreTimeout) =           -2147483639,
		NAMESPACE_DECL_(kEventTimeout) =               -2147483638,
		NAMESPACE_DECL_(kBlockInInvalidRegion) =       -2147483637,
		NAMESPACE_DECL_(kDbgPossibleBlockInRegion) =   -2147483636,
		NAMESPACE_DECL_(kInvalidPeriod) =              -2147483635,
		NAMESPACE_DECL_(kAlreadyPeriodic) =            -2147483634,
		NAMESPACE_DECL_(kNonperiodicSemaphore) =       -2147483633,
		NAMESPACE_DECL_(kDbgPopUnderflow) =            -2147483632,
		NAMESPACE_DECL_(kBadIOID) =                    -2147483631,
		NAMESPACE_DECL_(kBadDeviceDescriptor) =        -2147483630,
		NAMESPACE_DECL_(kOpenFailure) =                -2147483629,
		NAMESPACE_DECL_(kCloseFailure) =               -2147483628,
		NAMESPACE_DECL_(kReadFailure) =                -2147483627,
		NAMESPACE_DECL_(kWriteFailure)=                -2147483626,
		NAMESPACE_DECL_(kIOCtlFailure) =               -2147483625,
		NAMESPACE_DECL_(kBadIOTemplateID)=             -2147483624,
		NAMESPACE_DECL_(kInvalidDeviceFlag) =          -2147483623,
		NAMESPACE_DECL_(kDeviceTimeout) =              -2147483622,
		NAMESPACE_DECL_(kDeviceFlagCreationFailure) =  -2147483621,
		NAMESPACE_DECL_(kMaxCountExceeded) =           -2147483620,
		NAMESPACE_DECL_(kSemaphoreCreationFailure) =   -2147483619,
		NAMESPACE_DECL_(kSemaphoreDestructionFailure) =-2147483618,
		NAMESPACE_DECL_(kPoolCreationFailure) =        -2147483617,
		NAMESPACE_DECL_(kInvalidBlockPointer) =        -2147483616,
		NAMESPACE_DECL_(kInvalidPoolParms) =           -2147483615,
		NAMESPACE_DECL_(kInvalidPoolID) =              -2147483614,
		NAMESPACE_DECL_(kErrorPoolNotEmpty) =          -2147483613,
		NAMESPACE_DECL_(kErrorMallocBlock) =           -2147483612,
		NAMESPACE_DECL_(kMessageCreationFailure) =     -2147483611,
		NAMESPACE_DECL_(kInvalidMessageID) =           -2147483610,
		NAMESPACE_DECL_(kInvalidMessageOwner) =        -2147483609,
		NAMESPACE_DECL_(kInvalidMessageChannel) =      -2147483608,
		NAMESPACE_DECL_(kInvalidMessageRecipient) =    -2147483607,
		NAMESPACE_DECL_(kMessageTimeout) =             -2147483606,
		NAMESPACE_DECL_(kMessageInQueue) =             -2147483605,
		NAMESPACE_DECL_(kInvalidTimeout) =             -2147483604,
		NAMESPACE_DECL_(kInvalidTargetDSP) =           -2147483603,
		NAMESPACE_DECL_(kIOCreateFailure) =            -2147483602,
		NAMESPACE_DECL_(kHeapInitialisationFailure) =  -2147483601,
		NAMESPACE_DECL_(kInvalidHeapID) =              -2147483600,
		NAMESPACE_DECL_(kNewFailure) =                 -2147483599,
		NAMESPACE_DECL_(kInvalidMarshalledType) =      -2147483598,
		NAMESPACE_DECL_(kUncaughtException) =          -2147483597,
		NAMESPACE_DECL_(kAbort) =                      -2147483596,
		NAMESPACE_DECL_(kInvalidMaskBit) =             -2147483595,
		NAMESPACE_DECL_(kInvalidThreadStatus) =        -2147483594,
		NAMESPACE_DECL_(kThreadStackOverflow) =        -2147483593,
		NAMESPACE_DECL_(kMaxIDExceeded) =              -2147483592,
		NAMESPACE_DECL_(kThreadDestroyedInInvalidRegion)=-2147483591,
		NAMESPACE_DECL_(kNotMutexOwner) =              -2147483590,
		NAMESPACE_DECL_(kMutexNotOwned) =              -2147483589,
		NAMESPACE_DECL_(kMutexCreationFailure) =       -2147483588,
		NAMESPACE_DECL_(kMutexDestructionFailure) =    -2147483587,
		NAMESPACE_DECL_(kMutexSpaceTooSmall) =         -2147483586,
		NAMESPACE_DECL_(kInvalidMutexID) =             -2147483585,
		NAMESPACE_DECL_(kInvalidMutexOwner) =          -2147483584,
		NAMESPACE_DECL_(kAPIUsedfromISR) =             -2147483583,
		NAMESPACE_DECL_(kMaxHistoryEventExceeded) =    -2147483582,
		NAMESPACE_DECL_(kInvalidPointer) =             -2147483581,
        NAMESPACE_DECL_(kFifoCreationFailure) =        -2147483580,
        NAMESPACE_DECL_(kFifoDestructionFailure) =     -2147483579,
        NAMESPACE_DECL_(kInvalidFifoID) =              -2147483578,
        NAMESPACE_DECL_(kPendFifoTimeout) =            -2147483577,
        NAMESPACE_DECL_(kPostFifoTimeout) =            -2147483576,
        NAMESPACE_DECL_(kIncompatibleArguments) =      -2147483575,
		NAMESPACE_DECL_(kSSLInitFailure) =             -2147483566,
        NAMESPACE_DECL_(kUnhandledExceptionError) =    -2147483565,
		NAMESPACE_DECL_(kIntsAreDisabled) =            -100,
		NAMESPACE_DECL_(kRescheduleIntIsMasked) =      -99,
		NAMESPACE_DECL_(kNoError) =                    0,
		NAMESPACE_DECL_(kFirstUserError) =             1,
        NAMESPACE_DECL_(kLastUserError) =              INT_MAX
    } NAMESPACE_DECL_(SystemError);
	typedef enum
    {
	  NAMESPACE_DECL_(kNoPanic)=0,
	  NAMESPACE_DECL_(kThreadError)=1,
	  NAMESPACE_DECL_(kBootError)=2,
	  NAMESPACE_DECL_(kISRError)=3,
	  NAMESPACE_DECL_(kDeprecatedAPI)=4,
	  NAMESPACE_DECL_(kInternalError)=5,
	  NAMESPACE_DECL_(kStackCheckFailure)=6,
      NAMESPACE_DECL_(kUnhandledException)=7
    } NAMESPACE_DECL_(PanicCode);

#if defined (VDK_INSTRUMENTATION_LEVEL_) && (VDK_INSTRUMENTATION_LEVEL_>0)
	typedef enum
    {
		NAMESPACE_DECL_(kFromPopCriticalRegion),
		NAMESPACE_DECL_(kFromPopNestedCriticalRegions),
		NAMESPACE_DECL_(kFromPopUnscheduledRegion),
		NAMESPACE_DECL_(kFromPopNestedUnscheduledRegions)
    } NAMESPACE_DECL_(PopUnderflowError);
#endif
    typedef enum
    {

		NAMESPACE_DECL_(kThreadCreated) =       INT_MIN,
		NAMESPACE_DECL_(kThreadDestroyed)=      -2147483647,
		NAMESPACE_DECL_(kSemaphorePosted)=      -2147483646,
		NAMESPACE_DECL_(kSemaphorePended)=      -2147483645,
		NAMESPACE_DECL_(kEventBitSet)=          -2147483644,
		NAMESPACE_DECL_(kEventBitCleared)=      -2147483643,
		NAMESPACE_DECL_(kEventPended)=          -2147483642,
		NAMESPACE_DECL_(kDeviceFlagPended)=     -2147483641,
		NAMESPACE_DECL_(kDeviceFlagPosted)=     -2147483640,
		NAMESPACE_DECL_(kDeviceActivated)=      -2147483639,
		NAMESPACE_DECL_(kThreadTimedOut)=       -2147483638,
		NAMESPACE_DECL_(kThreadStatusChange)=   -2147483637,
		NAMESPACE_DECL_(kThreadSwitched)=       -2147483636,
		NAMESPACE_DECL_(kMaxStackUsed)=         -2147483635,
		NAMESPACE_DECL_(kPoolCreated)=          -2147483634,
		NAMESPACE_DECL_(kPoolDestroyed)=        -2147483633,
		NAMESPACE_DECL_(kDeviceFlagCreated)=    -2147483632,
		NAMESPACE_DECL_(kDeviceFlagDestroyed)=  -2147483631,
		NAMESPACE_DECL_(kMessagePosted)=        -2147483630,
		NAMESPACE_DECL_(kMessagePended)=        -2147483629,
		NAMESPACE_DECL_(kSemaphoreCreated)=     -2147483628,
		NAMESPACE_DECL_(kSemaphoreDestroyed)=   -2147483627,
		NAMESPACE_DECL_(kMessageCreated)=       -2147483626,
		NAMESPACE_DECL_(kMessageDestroyed)=     -2147483625,
		NAMESPACE_DECL_(kMessageTakenFromQueue)=-2147483624,
		NAMESPACE_DECL_(kThreadResourcesFreed)= -2147483623,
		NAMESPACE_DECL_(kThreadPriorityChanged)=-2147483622,
		NAMESPACE_DECL_(kMutexCreated)=         -2147483621,
		NAMESPACE_DECL_(kMutexDestroyed)=       -2147483620,
		NAMESPACE_DECL_(kMutexAcquired)=        -2147483619,
		NAMESPACE_DECL_(kMutexReleased)=        -2147483618,
        NAMESPACE_DECL_(kFifoCreated)=          -2147483617,
        NAMESPACE_DECL_(kFifoDestroyed)=        -2147483616,
        NAMESPACE_DECL_(kFifoPended)=           -2147483615,
        NAMESPACE_DECL_(kFifoPosted)=           -2147483614,
		NAMESPACE_DECL_(kUserEvent)=            1
    } NAMESPACE_DECL_(HistoryEnum);
	typedef unsigned int NAMESPACE_DECL_(Bitfield);
	typedef struct NAMESPACE_DECL_(EventData)
	{
		bool			            matchAll;
		unsigned int	values;
		unsigned int	mask;
	} NAMESPACE_DECL_(EventData);
	typedef enum
	{
		NAMESPACE_DECL_(kBlockedOnFifoPost),
		NAMESPACE_DECL_(kBlockedOnFifoPend)
	} NAMESPACE_DECL_(FifoBlockingDirection);



	typedef struct BootIOObjectInfo
	{
		 NAMESPACE_(IOTemplateID) 	m_ioTemplateID;
		 NAMESPACE_(IOID)       m_ioDeviceID;
		 long                   m_instanceNum;
	}NAMESPACE_DECL_(BootIOObjectInfo);


	struct NAMESPACE_DECL_(ThreadTemplate);
	typedef struct BootThreadInfo
	{
		 struct NAMESPACE_(ThreadTemplate*) m_templatePtr;
		 long                   m_instanceNum;
	}NAMESPACE_DECL_(BootThreadInfo);
	typedef enum
	{
		NAMESPACE_DECL_(kUnknownFamily),
		NAMESPACE_DECL_(kSHARC),
		NAMESPACE_DECL_(kTSXXX),
		NAMESPACE_DECL_(kBLACKFIN)
	} NAMESPACE_DECL_(DSP_Family);
	typedef enum
	{
        NAMESPACE_DECL_(k21060) = 1,
        NAMESPACE_DECL_(k21061) = 2,
        NAMESPACE_DECL_(k21062) = 3,
        NAMESPACE_DECL_(k21065) = 4,
        NAMESPACE_DECL_(k21160) = 5,
        NAMESPACE_DECL_(k21161) = 6,
        NAMESPACE_DECL_(k21261) = 7,
        NAMESPACE_DECL_(k21262) = 8,
        NAMESPACE_DECL_(k21266) = 9,
        NAMESPACE_DECL_(k21267) = 10,
        NAMESPACE_DECL_(k21362) = 11,
        NAMESPACE_DECL_(k21363) = 12,
        NAMESPACE_DECL_(k21364) = 13,
        NAMESPACE_DECL_(k21365) = 14,
        NAMESPACE_DECL_(k21366) = 15,
        NAMESPACE_DECL_(k21367) = 16,
        NAMESPACE_DECL_(k21368) = 17,
        NAMESPACE_DECL_(k21369) = 18,
        NAMESPACE_DECL_(k21371) = 19,
        NAMESPACE_DECL_(k21375) = 20,
        NAMESPACE_DECL_(k21462) = 21,
        NAMESPACE_DECL_(k21465) = 22,
        NAMESPACE_DECL_(k21467) = 23,
        NAMESPACE_DECL_(k21469) = 24,
        NAMESPACE_DECL_(k21471) = 26,
        NAMESPACE_DECL_(k21472) = 27,
        NAMESPACE_DECL_(k21475) = 30,
        NAMESPACE_DECL_(k21478) = 33,
        NAMESPACE_DECL_(k21479) = 34,
        NAMESPACE_DECL_(k21481) = 36,
        NAMESPACE_DECL_(k21482) = 37,
        NAMESPACE_DECL_(k21483) = 38,
        NAMESPACE_DECL_(k21485) = 40,
        NAMESPACE_DECL_(k21486) = 41,
        NAMESPACE_DECL_(k21487) = 42,
        NAMESPACE_DECL_(k21488) = 43,
        NAMESPACE_DECL_(k21489) = 44,
        NAMESPACE_DECL_(kBF512) = 4097,
        NAMESPACE_DECL_(kBF514) = 4098,
        NAMESPACE_DECL_(kBF516) = 4099,
        NAMESPACE_DECL_(kBF518) = 4100,
        NAMESPACE_DECL_(kBF522) = 4101,
        NAMESPACE_DECL_(kBF523) = 4102,
        NAMESPACE_DECL_(kBF524) = 4103,
        NAMESPACE_DECL_(kBF525) = 4104,
        NAMESPACE_DECL_(kBF526) = 4105,
        NAMESPACE_DECL_(kBF527) = 4106,
        NAMESPACE_DECL_(kBF531) = 4107,
        NAMESPACE_DECL_(kBF532) = 4108,
        NAMESPACE_DECL_(kBF533) = 4109,
        NAMESPACE_DECL_(kBF534) = 4110,
        NAMESPACE_DECL_(kBF535) = 4111,
        NAMESPACE_DECL_(kBF536) = 4112,
        NAMESPACE_DECL_(kBF537) = 4113,
        NAMESPACE_DECL_(kBF538) = 4114,
        NAMESPACE_DECL_(kBF539) = 4115,
        NAMESPACE_DECL_(kBF542) = 4117,
        NAMESPACE_DECL_(kBF544) = 4118,
        NAMESPACE_DECL_(kBF547) = 4119,
        NAMESPACE_DECL_(kBF548) = 4120,
        NAMESPACE_DECL_(kBF549) = 4121,
        NAMESPACE_DECL_(kBF542M)= 4122,
        NAMESPACE_DECL_(kBF544M)= 4123,
        NAMESPACE_DECL_(kBF547M)= 4124,
        NAMESPACE_DECL_(kBF548M)= 4125,
        NAMESPACE_DECL_(kBF549M)= 4126,
        NAMESPACE_DECL_(kBF561) = 4127,
        NAMESPACE_DECL_(kBF504) = 4128,
        NAMESPACE_DECL_(kBF504F)= 4129,
        NAMESPACE_DECL_(kBF506F)= 4130,
		NAMESPACE_DECL_(kBF592A)= 4131,
		NAMESPACE_DECL_(kTS101) = 8193,
		NAMESPACE_DECL_(kTS201) = 8194,
		NAMESPACE_DECL_(kTS202) = 8195,
		NAMESPACE_DECL_(kTS203) = 8196
	} NAMESPACE_DECL_(DSP_Product);
	typedef struct NAMESPACE_DECL_(VersionStruct)
	{
		int								mAPIVersion;
		NAMESPACE_(DSP_Family)			mFamily;
		NAMESPACE_(DSP_Product)			mProduct;
		long							mBuildNumber;
	} NAMESPACE_DECL_(VersionStruct);

#define INT_BITS_ (sizeof(int) * (unsigned int) CHAR_BIT)
	typedef enum
	{
		NAMESPACE_DECL_(kMinPriority)  = 1U,
		NAMESPACE_DECL_(kPriority1)    = INT_BITS_ - 2U ,
		NAMESPACE_DECL_(kPriority2)    = INT_BITS_ - 3U ,
		NAMESPACE_DECL_(kPriority3)    = INT_BITS_ - 4U ,
		NAMESPACE_DECL_(kPriority4)    = INT_BITS_ - 5U ,
		NAMESPACE_DECL_(kPriority5)    = INT_BITS_ - 6U ,
		NAMESPACE_DECL_(kPriority6)    = INT_BITS_ - 7U ,
		NAMESPACE_DECL_(kPriority7)    = INT_BITS_ - 8U ,
		NAMESPACE_DECL_(kPriority8)    = INT_BITS_ - 9U ,
		NAMESPACE_DECL_(kPriority9)    = INT_BITS_ - 10U,
		NAMESPACE_DECL_(kPriority10)   = INT_BITS_ - 11U,
		NAMESPACE_DECL_(kPriority11)   = INT_BITS_ - 12U,
		NAMESPACE_DECL_(kPriority12)   = INT_BITS_ - 13U,
		NAMESPACE_DECL_(kPriority13)   = INT_BITS_ - 14U,
		NAMESPACE_DECL_(kPriority14)   = INT_BITS_ - 15U,
#if UINT_MAX > 65535U
		NAMESPACE_DECL_(kPriority15)   = INT_BITS_ - 16U,
		NAMESPACE_DECL_(kPriority16)   = INT_BITS_ - 17U,
		NAMESPACE_DECL_(kPriority17)   = INT_BITS_ - 18U,
		NAMESPACE_DECL_(kPriority18)   = INT_BITS_ - 19U,
		NAMESPACE_DECL_(kPriority19)   = INT_BITS_ - 20U,
		NAMESPACE_DECL_(kPriority20)   = INT_BITS_ - 21U,
		NAMESPACE_DECL_(kPriority21)   = INT_BITS_ - 22U,
		NAMESPACE_DECL_(kPriority22)   = INT_BITS_ - 23U,
		NAMESPACE_DECL_(kPriority23)   = INT_BITS_ - 24U,
		NAMESPACE_DECL_(kPriority24)   = INT_BITS_ - 25U,
		NAMESPACE_DECL_(kPriority25)   = INT_BITS_ - 26U,
		NAMESPACE_DECL_(kPriority26)   = INT_BITS_ - 27U,
		NAMESPACE_DECL_(kPriority27)   = INT_BITS_ - 28U,
		NAMESPACE_DECL_(kPriority28)   = INT_BITS_ - 29U,
		NAMESPACE_DECL_(kPriority29)   = INT_BITS_ - 30U,
		NAMESPACE_DECL_(kPriority30)   = INT_BITS_ - 31U,
#endif
		NAMESPACE_DECL_(kMaxPriority)  = NAMESPACE_DECL_(kPriority1)
	} NAMESPACE_DECL_(Priority);
	typedef enum
	{
		NAMESPACE_DECL_(kMsgWaitForAll)= 1Ul << 15,
		NAMESPACE_DECL_(kMsgChannel1 ) = 1Ul << 14,
		NAMESPACE_DECL_(kMsgChannel2 ) = 1Ul << 13,
		NAMESPACE_DECL_(kMsgChannel3 ) = 1Ul << 12,
		NAMESPACE_DECL_(kMsgChannel4 ) = 1Ul << 11,
		NAMESPACE_DECL_(kMsgChannel5 ) = 1Ul << 10,
		NAMESPACE_DECL_(kMsgChannel6 ) = 1Ul << 9,
		NAMESPACE_DECL_(kMsgChannel7 ) = 1Ul << 8,
		NAMESPACE_DECL_(kMsgChannel8 ) = 1Ul << 7,
		NAMESPACE_DECL_(kMsgChannel9 ) = 1Ul << 6,
		NAMESPACE_DECL_(kMsgChannel10) = 1Ul << 5,
		NAMESPACE_DECL_(kMsgChannel11) = 1Ul << 4,
		NAMESPACE_DECL_(kMsgChannel12) = 1Ul << 3,
		NAMESPACE_DECL_(kMsgChannel13) = 1Ul << 2,
		NAMESPACE_DECL_(kMsgChannel14) = 1Ul << 1,
		NAMESPACE_DECL_(kMsgChannel15) = 1Ul << 0,
        NAMESPACE_DECL_(kAnyMsgChannel) = NAMESPACE_DECL_(kMsgChannel1 )
                                        | NAMESPACE_DECL_(kMsgChannel2 )
                                        | NAMESPACE_DECL_(kMsgChannel3 )
                                        | NAMESPACE_DECL_(kMsgChannel4 )
                                        | NAMESPACE_DECL_(kMsgChannel5 )
                                        | NAMESPACE_DECL_(kMsgChannel6 )
                                        | NAMESPACE_DECL_(kMsgChannel7 )
                                        | NAMESPACE_DECL_(kMsgChannel8 )
                                        | NAMESPACE_DECL_(kMsgChannel9 )
                                        | NAMESPACE_DECL_(kMsgChannel10 )
                                        | NAMESPACE_DECL_(kMsgChannel11 )
                                        | NAMESPACE_DECL_(kMsgChannel12 )
                                        | NAMESPACE_DECL_(kMsgChannel13 )
                                        | NAMESPACE_DECL_(kMsgChannel14 )
                                        | NAMESPACE_DECL_(kMsgChannel15 )
	} NAMESPACE_DECL_(MsgChannel);
#ifdef __cplusplus
    static const unsigned int kNoTimeoutError = (unsigned int)INT_MIN;
    static const unsigned int kDoNotWait = UINT_MAX;
#else
    #define VDK_kNoTimeoutError ( (unsigned int) INT_MIN )
    #define VDK_kDoNotWait  (UINT_MAX)
#endif

    void
    NAMESPACE_DECL_(Initialize)( void );

    void
    NAMESPACE_DECL_(Run)(void);

    void
    NAMESPACE_DECL_(PushCriticalRegion)( void );

    void
    NAMESPACE_DECL_(PopCriticalRegion)( void );

    void
    NAMESPACE_DECL_(PopNestedCriticalRegions)( void );

    void
    NAMESPACE_DECL_(PushUnscheduledRegion)( void );

    void
    NAMESPACE_DECL_(PopUnscheduledRegion)( void );

  	void
	NAMESPACE_DECL_(PopNestedUnscheduledRegions)( void );

   	NAMESPACE_(ThreadID)
	NAMESPACE_DECL_(CreateThread)( NAMESPACE_(ThreadType) inType );

	typedef struct NAMESPACE_DECL_(ThreadCreationBlock)
	{
		NAMESPACE_(ThreadType)	template_id;
		NAMESPACE_(ThreadID) 	thread_id;
		unsigned int            thread_stack_size;
		NAMESPACE_(Priority) 	thread_priority;
		void                    *user_data_ptr;
		struct NAMESPACE_(ThreadTemplate)	*pTemplate;
#ifndef __ADSPTS__

        unsigned int            *stack_pointer;
#endif
	} NAMESPACE_DECL_(ThreadCreationBlock);
#ifndef __ADSPTS__

    typedef enum NAMESPACE_DECL_(TCBBitfield)
    {
        NAMESPACE_DECL_(kSetThreadTemplateID)       = 1 << 0,
        NAMESPACE_DECL_(kSetThreadStackSize)        = 1 << 1,
        NAMESPACE_DECL_(kSetThreadPriority)         = 1 << 2,
        NAMESPACE_DECL_(kSetUserDataPointer)        = 1 << 3,
        NAMESPACE_DECL_(kSetThreadTemplatePointer)  = 1 << 4,
        NAMESPACE_DECL_(kSetThreadStackPointer)     = 1 << 5
    } NAMESPACE_DECL_(TCBBitfield);
   	NAMESPACE_(ThreadID)
	NAMESPACE_DECL_(CreateThreadEx2)( NAMESPACE_(ThreadCreationBlock)* inOutTCB, int fieldsRequired );
    unsigned int
    NAMESPACE_DECL_(GetContextRecordSize)( void );
#endif
   	NAMESPACE_(ThreadID)
	NAMESPACE_DECL_(CreateThreadEx)( NAMESPACE_(ThreadCreationBlock)* inOutTCB );

    void
    NAMESPACE_DECL_(DestroyThread)(NAMESPACE_(ThreadID) inThreadID, bool inDestroyNow );

	void
	NAMESPACE_DECL_(FreeDestroyedThreads)( void );

    NAMESPACE_(ThreadID)
    NAMESPACE_DECL_(GetThreadID)( void );

    NAMESPACE_ (ThreadType)
    NAMESPACE_DECL_(GetThreadType)( const NAMESPACE_(ThreadID) inThreadID );

    NAMESPACE_(ThreadStatus)
    NAMESPACE_DECL_(GetThreadStatus)( const NAMESPACE_(ThreadID) inThreadID );

    void**
    NAMESPACE_DECL_(GetThreadHandle)( void );

	int
	NAMESPACE_DECL_(GetAllThreads)( NAMESPACE_(ThreadID) outThreadIDArray[],
								    int inArraySize );

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetThreadBlockingID)( const NAMESPACE_(ThreadID) inThreadID,
										  int *outBlockingID );


	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetThreadTemplateName)( const NAMESPACE_(ThreadID) inThreadID,
											char 	**outName );


	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetThreadStackDetails)( const NAMESPACE_(ThreadID) inThreadID,
											unsigned int 	*outStackSize,
											void 			**outStackAddress );

#ifdef __ADSPTS__

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetThreadStack2Details)( const NAMESPACE_(ThreadID) inThreadID,
											 unsigned int 	*outStackSize,
											 void 			**outStackAddress );
#endif

#if defined (VDK_INSTRUMENTATION_LEVEL_) && (VDK_INSTRUMENTATION_LEVEL_==2)


    NAMESPACE_(SystemError)
    NAMESPACE_DECL_(GetNumTimesRun)( const NAMESPACE_(ThreadID) inThreadID,
									 unsigned int *outRunCount );
#ifdef __ADSP21000__

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetSharcThreadCycleData)( const NAMESPACE_(ThreadID) inThreadID,
											  unsigned int outCreationTime[2],
											  unsigned int outStartTime[2],
											  unsigned int outLastTime[2],
											  unsigned int outTotalTime[2] );
#else

    NAMESPACE_(SystemError)
    NAMESPACE_DECL_(GetThreadCycleData)( const NAMESPACE_(ThreadID) inThreadID,
										 unsigned long long int *outCreationTime,
										 unsigned long long int *outStartTime,
										 unsigned long long int *outLastTime,
										 unsigned long long int *outTotalTime );
#endif

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetThreadTickData)( const NAMESPACE_(ThreadID) inThreadID,
										NAMESPACE_(Ticks) *outCreationTime,
										NAMESPACE_(Ticks) *outStartTime,
										NAMESPACE_(Ticks) *outLastTime,
										NAMESPACE_(Ticks) *outTotalTime);
#endif

	NAMESPACE_(VersionStruct)
    NAMESPACE_DECL_(GetVersion)( void );

    NAMESPACE_(Priority)
    NAMESPACE_DECL_(GetPriority)( const NAMESPACE_(ThreadID) inThreadID );

    void
    NAMESPACE_DECL_(SetPriority)( const NAMESPACE_(ThreadID) inThreadID,
                                  const NAMESPACE_(Priority) inPriority );

    void
    NAMESPACE_DECL_(ResetPriority)( const NAMESPACE_(ThreadID) inThreadID );

    void
    NAMESPACE_DECL_(Yield)( void );

    void
    NAMESPACE_DECL_(Sleep)( NAMESPACE_(Ticks) inSleepTicks );




#pragma linkage_name _TMK_GetUptime
  	NAMESPACE_(Ticks)
	NAMESPACE_DECL_(GetUptime)( void );

    void
    NAMESPACE_DECL_(SetClockFrequency)( unsigned int inFrequency);


    void
    NAMESPACE_DECL_(SetClockFrequencyKHz)( float inFrequency);

    unsigned int
    NAMESPACE_DECL_(GetClockFrequency)( void );

    float
    NAMESPACE_DECL_(GetClockFrequencyKHz)( void );

    void
    NAMESPACE_DECL_(SetTickPeriod)( float inPeriod);

    float
    NAMESPACE_DECL_(GetTickPeriod)( void );



    typedef enum NAMESPACE_DECL_(DispatchID)
    {
        NAMESPACE_DECL_(kIO_Init),
        NAMESPACE_DECL_(kIO_Activate),
        NAMESPACE_DECL_(kIO_Open),
        NAMESPACE_DECL_(kIO_Close),
        NAMESPACE_DECL_(kIO_SyncRead),
        NAMESPACE_DECL_(kIO_SyncWrite),
        NAMESPACE_DECL_(kIO_IOCtl)
    }NAMESPACE_DECL_(DispatchID);
    typedef union NAMESPACE_DECL_(DispatchUnion)
    {
        struct
        {
            void        **dataH;
            char        *flags;
        } OpenClose_t;
        struct
        {
            void                **dataH;
            NAMESPACE_(Ticks)   timeout;
            unsigned int        dataSize;
            char                *data;
        } ReadWrite_t;
        struct
        {
            void        **dataH;
            void        *command;
            char        *parameters;
        } IOCtl_t;
		struct
		{
			void        *pInitInfo;
		} Init_t;
    } NAMESPACE_DECL_(DispatchUnion);

    NAMESPACE_(DeviceDescriptor)
    NAMESPACE_DECL_(OpenDevice)( NAMESPACE_(IOID)	inIDNum,
                                 			char        *inFlags );

    void
    NAMESPACE_DECL_(CloseDevice)( NAMESPACE_(DeviceDescriptor)    inDD );

    unsigned int
    NAMESPACE_DECL_(SyncRead)(  NAMESPACE_(DeviceDescriptor)    inDD,
                                char                            *outBuffer,
                                const unsigned int              inSize,
                                NAMESPACE_(Ticks)               inTimeout   );

    unsigned int
    NAMESPACE_DECL_(SyncWrite)( NAMESPACE_(DeviceDescriptor)    inDD,
                                char                            *inBuffer,
                                const unsigned int              inSize,
                                NAMESPACE_(Ticks)               inTimeout   );

    int
    NAMESPACE_DECL_(DeviceIOCtl)(   NAMESPACE_(DeviceDescriptor)    inDD,
                                    void                            *inCommand,
                                    char                            *inParameters );

	NAMESPACE_(DeviceFlagID)
	NAMESPACE_DECL_(CreateDeviceFlag)(void);

	void
	NAMESPACE_DECL_(DestroyDeviceFlag)(NAMESPACE_(DeviceFlagID) inFlag);


    bool
    NAMESPACE_DECL_(PendDeviceFlag)(    NAMESPACE_(DeviceFlagID)	inFlag,
                                        NAMESPACE_(Ticks)   inTimeout );

    void
    NAMESPACE_DECL_(PostDeviceFlag)(    NAMESPACE_(DeviceFlagID) 	inFlag );

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetDevFlagPendingThreads)( const NAMESPACE_(DeviceFlagID) inDevFlagID,
											   int *outNumThreads,
											   NAMESPACE_(ThreadID) outThreadArray[],
											   int inArraySize);

	int
	NAMESPACE_DECL_(GetAllDeviceFlags)( NAMESPACE_(DeviceFlagID) outDevFlagIDArray[],
										int inArraySize );

    NAMESPACE_(IOID)
    NAMESPACE_DECL_(CreateIOObject)(NAMESPACE_(IOTemplateID) inTemplateID,
									void *pInitInfo);
	void
	NAMESPACE_DECL_(DestroyIOObject)(const NAMESPACE_(IOID) inID );


	NAMESPACE_(MessageID)
	NAMESPACE_DECL_(CreateMessage)( int inPayloadType,
									unsigned int inPayloadSize,
									void *inPayloadAddr);

	void
	NAMESPACE_DECL_(DestroyMessage)(NAMESPACE_(MessageID) inID);

	void
	NAMESPACE_DECL_(DestroyMessageAndFreePayload)(NAMESPACE_(MessageID) inID);

	void
	NAMESPACE_DECL_(FreeMessagePayload)(NAMESPACE_(MessageID) inID);

	void
	NAMESPACE_DECL_(PostMessage)(NAMESPACE_(ThreadID) inRecipient,
									NAMESPACE_(MessageID) inMessageID,
									NAMESPACE_(MsgChannel) inChannel);

	void
	NAMESPACE_DECL_(ForwardMessage)(NAMESPACE_(ThreadID) inRecipient,
									NAMESPACE_(MessageID) inMessageID,
									NAMESPACE_(MsgChannel) inChannel,
									NAMESPACE_(ThreadID) inPseudoSender);

	NAMESPACE_(MessageID)
	NAMESPACE_DECL_(PendMessage)(unsigned int inMsgChannelMask,
									NAMESPACE_(Ticks) inTimeout);

	bool
	NAMESPACE_DECL_(MessageAvailable)(unsigned int inMsgPriorityMask);
	void
	NAMESPACE_DECL_(GetMessagePayload)(NAMESPACE_(MessageID) inMessageID,
									   int *pOutPayloadType,
									   unsigned int *pOutPayloadSize,
									   void **ppOutPayloadAddr);
	void
	NAMESPACE_DECL_(SetMessagePayload)(NAMESPACE_(MessageID) inMessageID,
									   int inPayloadType,
									   unsigned int inPayloadSize,
									   void *inPayloadAddr);
	void
	NAMESPACE_DECL_(GetMessageReceiveInfo)(NAMESPACE_(MessageID)  inMessageID,
										   NAMESPACE_(MsgChannel) *pOutChannel,
										   NAMESPACE_(ThreadID)   *pOutSender);

	int
	NAMESPACE_DECL_(GetAllMessages)( NAMESPACE_(MessageID) outMessageIDArray[],
									 int inArraySize );

	typedef struct NAMESPACE_DECL_(PayloadDetails)
	{
		int type;
		unsigned int size;
		void *addr;
	} NAMESPACE_DECL_(PayloadDetails);
	typedef struct NAMESPACE_DECL_(MessageDetails)
	{
		NAMESPACE_(MsgChannel) channel;
		NAMESPACE_(ThreadID)   sender;
		NAMESPACE_(ThreadID)   target;
	} NAMESPACE_DECL_(MessageDetails);

	typedef enum NAMESPACE_DECL_(MarshallingCode)
	{
		TRANSMIT_AND_RELEASE,
		ALLOCATE_AND_RECEIVE,
		ALLOCATE,
		RELEASE
	} NAMESPACE_DECL_(MarshallingCode);
	struct NAMESPACE_DECL_(IOAbstractBase);
	struct NAMESPACE_DECL_(DeviceControlBlock);
	union NAMESPACE_DECL_(DispatchUnion);
	typedef void* (*NAMESPACE_DECL_(PFDispatchFunction))(struct NAMESPACE_(IOAbstractBase) *pThis,
														 enum NAMESPACE_(DispatchID) inCode,
														 union NAMESPACE_(DispatchUnion) *inUnion);
	typedef struct NAMESPACE_DECL_(DeviceInfoBlock)
	{
		NAMESPACE_(DeviceDescriptor) dd;
		NAMESPACE_(PFDispatchFunction) pfDispatchFunction;
		struct NAMESPACE_(IOAbstractBase) *pDevObj;
		struct NAMESPACE_(DeviceControlBlock) *pDcb;
	} NAMESPACE_DECL_(DeviceInfoBlock);
	typedef struct NAMESPACE_DECL_(MsgWireFormat)
	{
		unsigned int header;
		NAMESPACE_(PayloadDetails) payload;
	} NAMESPACE_DECL_(MsgWireFormat);
	typedef int (*NAMESPACE_DECL_(PFMarshaller))(NAMESPACE_(MarshallingCode) code,
								 NAMESPACE_(MsgWireFormat) *inOutMsgPacket,
								 NAMESPACE_(DeviceInfoBlock) *pDev,
								 unsigned int inArea,
								 NAMESPACE_(Ticks) inTimeout);

	typedef struct NAMESPACE_DECL_(MarshallingEntry)
	{
		NAMESPACE_(PFMarshaller) pfMarshaller;
		unsigned int area;
	} NAMESPACE_DECL_(MarshallingEntry);
	typedef enum NAMESPACE_DECL_(RoutingDirection)
	{
		kINCOMING,
		kOUTGOING
	} NAMESPACE_DECL_(RoutingDirection);
#define MARSHALLINGINDEX(x) (-(x) - 1)
#define ISMARSHALLEDTYPE(x) ((x) < 0)
	struct NAMESPACE_DECL_(IOAbstractBase);
	union NAMESPACE_DECL_(DispatchUnion);
	void
	NAMESPACE_DECL_(GetMessageDetails)(NAMESPACE_(MessageID)  inMessageID,
									   NAMESPACE_(MessageDetails) *pOutMessageDetails,
									   NAMESPACE_(PayloadDetails) *pOutPayloadDetails);

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetMessageStatusInfo)( NAMESPACE_(MessageID) inMessageID,
								NAMESPACE_(MessageDetails) *outMessageDetails,
								NAMESPACE_(PayloadDetails) *outPayloadDetails );
	int
	NAMESPACE_DECL_(PoolMarshaller) (NAMESPACE_(MarshallingCode) code,
									 NAMESPACE_(MsgWireFormat) *pMsgPacket,
									 NAMESPACE_(DeviceInfoBlock) *pDev,
									 unsigned int inArea,
									 NAMESPACE_(Ticks) inTimeout);
	int
	NAMESPACE_DECL_(EmptyPoolMarshaller) (NAMESPACE_(MarshallingCode) code,
										  NAMESPACE_(MsgWireFormat) *pMsgPacket,
										  NAMESPACE_(DeviceInfoBlock) *pDev,
										  unsigned int inArea,
										  NAMESPACE_(Ticks) inTimeout);
	int
	NAMESPACE_DECL_(HeapMarshaller) (NAMESPACE_(MarshallingCode) code,
									 NAMESPACE_(MsgWireFormat) *pMsgPacket,
									 NAMESPACE_(DeviceInfoBlock) *pDev,
									 unsigned int heapID,
									 NAMESPACE_(Ticks) inTimeout);
	int
	NAMESPACE_DECL_(EmptyHeapMarshaller) (NAMESPACE_(MarshallingCode) code,
										  NAMESPACE_(MsgWireFormat) *pMsgPacket,
										  NAMESPACE_(DeviceInfoBlock) *pDev,
										  unsigned int heapID,
										  NAMESPACE_(Ticks) inTimeout);
#if defined(__ADSPTS__) || defined(__2106x__) || defined(__2116x__)
	int
	NAMESPACE_DECL_(ClusterBusMarshaller) (NAMESPACE_(MarshallingCode) code,
										   NAMESPACE_(MsgWireFormat) *pMsgPacket,
										   NAMESPACE_(DeviceInfoBlock) *pDev,
										   unsigned int heapID,
										   NAMESPACE_(Ticks) inTimeout);
#endif
	void
	NAMESPACE_DECL_(InstallMessageControlSemaphore)(NAMESPACE_(SemaphoreID) inSemaphore);
	unsigned int
	NAMESPACE_DECL_(GetHeapIndex)(NAMESPACE_(HeapID) inHeapID);
#ifdef __ADSPTS__
#define INIT_THREADTEMPLATE_(name,priority,stacksize,stack2size,createfunction,contextheap, stackheap, context2heap, stack2heap,threadheap, messagesallowed) \
	{ (name), (contextheap), (stackheap), (context2heap), (stack2heap), (threadheap), \
	(priority),(stacksize),(stack2size),(createfunction), (messagesallowed) }
#define INIT_RTHREAD_(name,priority,stacksize,stack2size,createfunction,contextheap, stackheap, context2heap, stack2heap,threadheap, messagesallowed,id, device, args, direction) \
	{ \
	  INIT_THREADTEMPLATE_((name),(priority),(stacksize),(stack2size),(createfunction),(contextheap), (stackheap), (context2heap), (stack2heap),(threadheap), (messagesallowed)) \
	, (id), (device), (args), (direction) \
	}

#elif defined (__ADSPBLACKFIN__)
#define INIT_THREADTEMPLATE_(name,priority,stacksize,createfunction,stackheap, threadheap, messagesallowed) \
	{ (name), (stackheap), (threadheap), \
	(priority), (stacksize), (createfunction), (messagesallowed) }
#define INIT_RTHREAD_(name,priority,stacksize,createfunction,stackheap, threadheap, messagesallowed,id, device, args, direction) \
	{ \
	INIT_THREADTEMPLATE_((name),(priority),(stacksize),(createfunction),(stackheap), (threadheap), (messagesallowed)) \
	, (id), (device), (args), (direction) \
	}
#else
#define INIT_THREADTEMPLATE_(name,priority,stacksize,createfunction,contextheap, stackheap,threadheap, messagesallowed) \
	{ (name), (contextheap), (stackheap), (threadheap), \
	(priority),(stacksize),(createfunction),(messagesallowed) }
#define INIT_RTHREAD_(name, priority,stacksize,createfunction,contextheap, stackheap,threadheap, messagesallowed, id, device, args, direction) \
	{ \
	INIT_THREADTEMPLATE_((name), (priority),(stacksize),(createfunction),(contextheap), (stackheap),(threadheap), (messagesallowed)) \
	, (id), (device), (args), (direction) \
	}
#endif

    NAMESPACE_(SemaphoreID)
    NAMESPACE_DECL_(CreateSemaphore)( unsigned int inInitialValue ,
								      unsigned int inMaxCount ,
								      NAMESPACE_(Ticks) inInitialDelay ,
								      NAMESPACE_(Ticks) inPeriod );
    void
    NAMESPACE_DECL_(DestroySemaphore)( const NAMESPACE_(SemaphoreID) inSemaphoreID);

    bool
    NAMESPACE_DECL_(PendSemaphore)( NAMESPACE_(SemaphoreID) inSemaphoreID,
                                    NAMESPACE_(Ticks) inTimeout );

    unsigned int
    NAMESPACE_DECL_(GetSemaphoreValue)( NAMESPACE_(SemaphoreID) inSemaphoreID );

    void
    NAMESPACE_DECL_(PostSemaphore)( NAMESPACE_(SemaphoreID) inSemID );

    void
	NAMESPACE_DECL_(MakePeriodic)( NAMESPACE_(SemaphoreID) inSemID,
	                               NAMESPACE_(Ticks) inDelay,
	                               NAMESPACE_(Ticks) inPeriod );

    void
	NAMESPACE_DECL_(RemovePeriodic)( NAMESPACE_(SemaphoreID) inSemID );

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetSemaphorePendingThreads)( NAMESPACE_(SemaphoreID) inSemID,
											int *outNumThreads,
											NAMESPACE_(ThreadID) outThreadArray[],
											int inArraySize);

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetSemaphoreDetails)( const NAMESPACE_(SemaphoreID) inSemID,
										  NAMESPACE_(Ticks) *outPeriod,
										  unsigned int *outMaxCount );

	int
	NAMESPACE_DECL_(GetAllSemaphores)( NAMESPACE_(SemaphoreID) outSemaphoreIDArray[],
									   int inArraySize );


    void
    NAMESPACE_DECL_(SetEventBit)( NAMESPACE_(EventBitID) inEventBitID );

    void
    NAMESPACE_DECL_(ClearEventBit)( NAMESPACE_(EventBitID) inEventBitID );

    bool
    NAMESPACE_DECL_(GetEventBitValue)( NAMESPACE_(EventBitID) inEventBitID );

    bool
    NAMESPACE_DECL_(PendEvent)( NAMESPACE_(EventID) inEventID,
                                const NAMESPACE_(Ticks) inTimeout );

    bool
    NAMESPACE_DECL_(GetEventValue)( NAMESPACE_(EventID) inEventID );

    NAMESPACE_(EventData)
    NAMESPACE_DECL_(GetEventData)( NAMESPACE_(EventID) inEventID );

    void
    NAMESPACE_DECL_(LoadEvent)( NAMESPACE_(EventID) inEventID,
                                const NAMESPACE_(EventData) inEventData );

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetEventPendingThreads)( const NAMESPACE_(EventID)inEventID,
											 int *outNumThreads,
											 NAMESPACE_(ThreadID) outThreadArray[],
											 int inArraySize );


	NAMESPACE_(MutexID)
	NAMESPACE_DECL_(CreateMutex)(void);
    void
    NAMESPACE_DECL_(DestroyMutex)( const NAMESPACE_(MutexID) inMutexID);
    void
    NAMESPACE_DECL_(AcquireMutex)( const NAMESPACE_(MutexID) inMutexID);
    void
    NAMESPACE_DECL_(ReleaseMutex)( const NAMESPACE_(MutexID) inMutexID);


	NAMESPACE_(FifoID)
	NAMESPACE_DECL_(CreateFifo)(unsigned int inSize,
                                void *pInBuffer,
                                void (*pfInBufferCleanup)(void*));
    void
    NAMESPACE_DECL_(DestroyFifo)( NAMESPACE_(FifoID) inFifoID);
    bool
    NAMESPACE_DECL_(C_ISR_PostFifo)(NAMESPACE_(FifoID) 	inFifoID,
                                    void 	*pInData);
    bool
    NAMESPACE_DECL_(PostFifo)( NAMESPACE_(FifoID) 	inFifoID,
                                void 	*pInData,
                                NAMESPACE_(Ticks) 	inTimeout );
    bool
    NAMESPACE_DECL_(PendFifo)(NAMESPACE_(FifoID) 	inFifoID,
                                void 	**pOutData,
                                NAMESPACE_(Ticks) 	inTimeout );
    NAMESPACE_(SystemError)
    NAMESPACE_DECL_(GetFifoDetails)( NAMESPACE_(FifoID) 	fifo,
                                            unsigned int 	*pOutFifoSize,
                                            unsigned int 	*pOutNumFreeSlots,
                                            void 		    **pOutBuffer);


	void
	NAMESPACE_DECL_(LogHistoryEvent)(NAMESPACE_(HistoryEnum) inEnum,
															int inValue);


#if defined (VDK_INSTRUMENTATION_LEVEL_) && (VDK_INSTRUMENTATION_LEVEL_==2)

	typedef struct NAMESPACE_DECL_(HistoryEvent)
    {
		NAMESPACE_(Ticks)      	time;
		NAMESPACE_(ThreadID)   	threadID;
        NAMESPACE_(HistoryEnum) type;
        int             		value;
    } NAMESPACE_DECL_(HistoryEvent);
	typedef void (*NAMESPACE_DECL_(HistoryLogging))( NAMESPACE_(Ticks),
											const NAMESPACE_(HistoryEnum),
											const int,
											const NAMESPACE_(ThreadID) );

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetHistoryEvent)( unsigned int inHistEventNum,
									  NAMESPACE_(HistoryEvent) *outHistoryEvent );

	unsigned int
	NAMESPACE_DECL_(GetCurrentHistoryEventNum)( void );

	unsigned int
	NAMESPACE_DECL_(GetHistoryBufferSize)( void );

	void
	NAMESPACE_DECL_(ReplaceHistorySubroutine)( NAMESPACE_(HistoryLogging) newRoutine);
#endif


#ifdef __cplusplus
    extern "C" void VDK_CThread_Error(VDK::ThreadID inThreadID);
#else
    void VDK_CThread_Error(VDK_ThreadID inThreadID);
#endif

    int
    NAMESPACE_DECL_(DispatchThreadError)( NAMESPACE_(SystemError) inErrorID, const int inErrorValue );

    void
    NAMESPACE_DECL_(SetThreadError)( NAMESPACE_(SystemError) inErrorID, const int inErrorValue );

    void
    NAMESPACE_DECL_(ClearThreadError)( void );

    NAMESPACE_(SystemError)
    NAMESPACE_DECL_(GetLastThreadError)( void );

    int
    NAMESPACE_DECL_(GetLastThreadErrorValue)( void );


   NAMESPACE_(IMASKStruct)
   NAMESPACE_DECL_(GetInterruptMask)( void );
#if defined(__2116x__) || defined(__2126x__) || defined(__2136x__) || defined(__2137x__) || defined (__214xx__)
  void
  NAMESPACE_DECL_(GetInterruptMaskEx) (NAMESPACE_(IMASKStruct)* outValue1, NAMESPACE_(IMASKStruct)* outValue2);
#endif

   void
   NAMESPACE_DECL_(SetInterruptMaskBits)( const NAMESPACE_(IMASKStruct) inValue );
#if defined(__2116x__) || defined(__2126x__) || defined(__2136x__) || defined(__2137x__) || defined (__214xx__)
   void
   NAMESPACE_DECL_(SetInterruptMaskBitsEx)( const NAMESPACE_(IMASKStruct) inValue1, const NAMESPACE_(IMASKStruct) inValue2 );
#endif

   void
   NAMESPACE_DECL_(ClearInterruptMaskBits)( const NAMESPACE_(IMASKStruct) inValue );
#if defined(__2116x__) || defined(__2126x__) || defined(__2136x__) || defined(__2137x__) || defined (__214xx__)
   void
   NAMESPACE_DECL_(ClearInterruptMaskBitsEx)( const NAMESPACE_(IMASKStruct) inValue1, const NAMESPACE_(IMASKStruct) inValue2 );
#endif

	NAMESPACE_(PoolID)
	NAMESPACE_DECL_(CreatePool) (const unsigned int inBlockSz,const unsigned int inNumBlocks,const bool inLazyCreate);

	NAMESPACE_(PoolID)
	NAMESPACE_DECL_(CreatePoolEx) (const unsigned int inBlockSz,const unsigned int inNumBlocks,const bool inLazyCreate,int inWhichPool);

	void
    NAMESPACE_DECL_(DestroyPool) (const NAMESPACE_(PoolID) inPoolID);

	void *
	NAMESPACE_DECL_(MallocBlock) (const NAMESPACE_(PoolID) inPoolID);


	void
	NAMESPACE_DECL_(FreeBlock) (const NAMESPACE_(PoolID) inPoolID, void* inBlkPtr);

	void
	NAMESPACE_DECL_(LocateAndFreeBlock) (void *inBlkPtr);

	unsigned int
	NAMESPACE_DECL_(GetNumFreeBlocks) (const NAMESPACE_(PoolID) inPoolID);


	unsigned int
	NAMESPACE_DECL_(GetNumAllocatedBlocks) (const NAMESPACE_(PoolID) inPoolID);

	NAMESPACE_(SystemError)
	NAMESPACE_DECL_(GetPoolDetails)( const NAMESPACE_(PoolID) inPoolID,
									 unsigned int *outNumBlocks,
									 void **outMemoryAddress );

	int
	NAMESPACE_DECL_(GetAllMemoryPools)( NAMESPACE_(PoolID) outPoolIDArray[],
										int inArraySize );

	unsigned int
	NAMESPACE_DECL_(GetBlockSize) (const NAMESPACE_(PoolID) inPoolID);
	unsigned int
	NAMESPACE_DECL_(GetThreadStackUsage) (const NAMESPACE_(ThreadID) inThreadID);
#ifdef __ADSPTS__
	unsigned int
	NAMESPACE_DECL_(GetThreadStack2Usage) (const NAMESPACE_(ThreadID) inThreadID);
#endif
	void
	NAMESPACE_DECL_(InstrumentStack) (void);

#ifdef __cplusplus
	static const int kTLSUnallocated = INT_MIN;
#else
	#define VDK_kTLSUnallocated INT_MIN
#endif
	bool
	NAMESPACE_DECL_(AllocateThreadSlot) (int *ioSlotNum);
	bool
	NAMESPACE_DECL_(AllocateThreadSlotEx) (int *ioSlotNum, void (*pfCleanup)(void *));
	bool
	NAMESPACE_DECL_(SetThreadSlotValue) (int inSlotNum, void *inValue);
	void*
	NAMESPACE_DECL_(GetThreadSlotValue) (int inSlotNum);
	bool
	NAMESPACE_DECL_(FreeThreadSlot) (int inSlotNum);
#ifdef __ADSPBLACKFIN__
#define ___vdkclobber__ "P1 R0"
#define ___vdkclobber_call__ "P1 R0"
#elif defined(__ADSP21000__)
#define ___vdkclobber__ ""
#define ___vdkclobber_call__ "i12"
#else
#define ___vdkclobber__ ""
#endif
#if defined(__ADSPBLACKFIN__) || defined(__ADSP21000__)
#pragma regs_clobbered ___vdkclobber_call__
	bool
	NAMESPACE_DECL_(IsInRegion)(void);
#endif
	bool
	NAMESPACE_DECL_(IsRunning)(void);
#pragma regs_clobbered ___vdkclobber__
	void
	NAMESPACE_DECL_(C_ISR_ActivateDevice)(NAMESPACE_(IOID) inID);
#pragma regs_clobbered ___vdkclobber__
	void
	NAMESPACE_DECL_(C_ISR_PostSemaphore)( NAMESPACE_(SemaphoreID) inSemID );
#pragma regs_clobbered ___vdkclobber__
	void
	NAMESPACE_DECL_(C_ISR_SetEventBit)( NAMESPACE_(EventBitID) inEventBitID );
#pragma regs_clobbered ___vdkclobber__
	void
	NAMESPACE_DECL_(C_ISR_ClearEventBit)( NAMESPACE_(EventBitID) inEventBitID );
#pragma regs_clobbered ___vdkclobber__
#ifdef __cplusplus
extern "C"
#endif
    void
    KernelPanic(NAMESPACE_DECL_(PanicCode) inCode,
                NAMESPACE_DECL_(SystemError) inError,
                const int inValue);
#if defined(__ADSPBLACKFIN__)
#pragma regs_clobbered ___vdkclobber__
#ifdef __cplusplus
extern "C"
#endif
    void
    ExceptionPanic(NAMESPACE_DECL_(PanicCode) inCode,
                NAMESPACE_DECL_(SystemError) inError,
                const int inValue);
#ifdef __cplusplus
extern "C"
#endif
    void
    InterruptPanic(NAMESPACE_DECL_(PanicCode) inCode,
                NAMESPACE_DECL_(SystemError) inError,
                const int inValue);
#endif

#ifdef __cplusplus
	extern const unsigned int NAMESPACE_DECL_(kMaxNumThreads);
	extern const unsigned int NAMESPACE_DECL_(kMaxNumActiveMemoryPools);
	extern const unsigned int NAMESPACE_DECL_(kMaxNumActiveSemaphores);
	extern const unsigned int NAMESPACE_DECL_(kMaxNumActiveDevFlags);
	extern const unsigned int NAMESPACE_DECL_(kMaxNumActiveMessages);
	extern const unsigned int NAMESPACE_DECL_(kMaxNumIOObjects);
#endif
#ifdef __cplusplus
}
#endif

#undef NAMESPACE_
#undef NAMESPACE_DECL_
#ifdef _MISRA_RULES
#pragma diag(pop)
#endif
#endif

#ifndef __IDELEMENT__
#define __IDELEMENT__
namespace VDK
{
	class IDElement
	{
		protected:
			unsigned int				m_ID;
	};
template <class IDType>
	class IDElementTemplate:public IDElement {
		public:
	        inline IDType& ID()
	    		{ return *(reinterpret_cast <IDType *> (&m_ID)); }

	        inline const IDType& ID() const
	    		{ return *(reinterpret_cast <IDType *> (&m_ID)); }
	};
}
#endif
namespace VDK{
    class Thread;
    extern HeapID g_SemaphoreHeap;
    class Semaphore;

    struct SemaphoreInfo {
	public:

	   SemaphoreID m_ID;
	   unsigned int m_InitialValue;
	   unsigned int m_MaxCount;
	   Ticks m_InitialDelay;
	   Ticks m_Period;
    } ;

}
#endif

#ifndef __EVENT_H__
#define __EVENT_H__




#ifndef VDK_THREAD_H_
#define VDK_THREAD_H_



#ifndef   VDK_HISTORY_H_
#define   VDK_HISTORY_H_





	typedef struct HistoryStruct
    {
		int		m_Time;
		int		m_ThreadID;
        int		m_Type;
        int		m_Value;
    } HistoryStruct;
	typedef struct HistoryBuffer
    {
		unsigned int   	m_NumEvents;
        unsigned int	m_CurrentEvent;
		HistoryStruct	*m_Events;
    } HistoryBuffer;

#ifdef __cplusplus


#if (VDK_INSTRUMENTATION_LEVEL_==2)
extern "C" void VDK_History(const VDK::HistoryEnum, const int, const VDK::ThreadID);
#define HISTORY_(event_, value_, threadid_) VDK_History(event_, value_, threadid_)
#else
#define HISTORY_(event_, value_, threadid_) do {   } while(0)
#endif
#endif
#endif

#ifndef DEVICE_CONTROL_BLOCK_H_
#define DEVICE_CONTROL_BLOCK_H_

namespace VDK
{

	class DeviceControlBlock
	{
	public:

		DeviceControlBlock()
	    {
		    m_DD_DataPtr = 0;
	    }

	protected:
		void	    *m_DD_DataPtr;
        IOID    m_DeviceID;
	};
}
#endif

#ifndef MESSAGEQUEUE_H
#define MESSAGEQUEUE_H

#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#ifndef __PRIORITYLISTELEMENT__
#define __PRIORITYLISTELEMENT__

#ifndef VDK_LIST_ELEMENT_H_
#define VDK_LIST_ELEMENT_H_



namespace VDK
{

    template <class PointerType, class CastType = PointerType>
    class ListElement
    {
    public:

        ListElement()
        {
            m_NextP = static_cast<PointerType*>(this);
            m_PrevP = static_cast<PointerType*>(this);
        }

        inline PointerType*     Next()
                                    { return m_NextP; }

        inline PointerType*     Prev()
                                    { return m_PrevP; }


        void    InsertAfter(PointerType *inListElement)
                {
                    static_cast<CastType*>(inListElement)->m_NextP = m_NextP;
                    static_cast<CastType*>(inListElement)->m_PrevP = static_cast<PointerType*>(this);
                    static_cast<CastType*>(m_NextP)->m_PrevP = inListElement;
                    m_NextP = inListElement;
                }
        bool IsInList()
	        { return (m_NextP != static_cast<PointerType*>(this)); }

    protected:
        PointerType     *m_NextP;
        PointerType     *m_PrevP;
    };
}
#endif
namespace VDK
{


	class PriorityListElement;
    class PriorityListElementMgr : public VDK::ListElement<VDK::PriorityListElementMgr>
    {
    };
    class PriorityListElement : public PriorityListElementMgr
    {
        public:
            inline VDK::Priority& Priority()
             { return m_Priority; }

            inline const VDK::Priority& Priority() const
             { return m_Priority; }
        private:
            VDK::Priority    m_Priority;
    };
}
#endif


#include <new>
namespace VDK
{
	extern PoolID g_MessagePoolID ;

	class Message : public IDElementTemplate<MessageID>, public PriorityListElement
	{
		public:
			Message(MessageID 	inMsgID,
					int			inPayloadType,
					int 		inPayloadSize,
					void 	   *inPayloadAddr):	m_PayloadP(inPayloadAddr),
												m_PayloadType(inPayloadType),
												m_NumElements(inPayloadSize)
												{ 	m_ID = inMsgID;
													m_Sender = static_cast<VDK::ThreadID>(0);
													m_Owner  = static_cast<VDK::ThreadID>(0);
													m_Target = static_cast<VDK::ThreadID>(0);
												}

		private:

			int					m_PayloadType;
			void				*m_PayloadP;
			unsigned int		m_NumElements;
			VDK::ThreadID		m_Sender;
			VDK::ThreadID		m_Owner;
			VDK::ThreadID		m_Target;
	};
}
#endif

#ifndef QUEUE_H
#define QUEUE_H

#ifndef __QUEUEMGR__
#define __QUEUEMGR__



#ifndef __PRIORITYLISTMGR__
#define __PRIORITYLISTMGR__



namespace VDK
{



class PriorityListMgr
{
    public:
        PriorityListElement*  	GetNext()
                        {
                            if (ElementsPresent())
                                return static_cast<PriorityListElement*>(m_LE.Next());
                            return 0;
                        }

        PriorityListElement*  	GetNextUnchecked()
                        {
                                return static_cast<PriorityListElement*>(m_LE.Next());
                        }

        void            Insert( PriorityListElement *inPtr )
                        {


                            (m_LE.Prev())->InsertAfter(inPtr);
                        }
        bool            ElementsPresent()
                        {
                            return ( (static_cast<PriorityListElement *>(m_LE.Next())) != (&m_LE) );
                        }
        bool            MultipleElementsPresent()
                        {
                            return (m_LE.Next() != m_LE.Prev());
                        }
    protected:

        PriorityListElementMgr    m_LE;
};
}
#endif

#ifndef _BITOPS_H_
#define _BITOPS_H_
#if defined(__ADSPTS__)
#include <builtins.h>
#elif defined(__ADSP21000__)
#elif !defined(__ADSPBLACKFIN__)
#error Unknown processor family
#endif
namespace VDK {
    enum { kNoneSet = -1 };
inline bool IsBitSet(unsigned field, int bit)
{
    return 0 != ((field) & (1 << (bit)));
}
inline bool IsBitClr(unsigned field, int bit)
{
    return 0 == ((field) & (1 << (bit)));
}

#if defined(__ADSPBLACKFIN__)
inline int FindFirstSet(unsigned field)
{
    return 30 - __builtin_norm_fr1x32(field);
}
#elif defined(__ADSPTS__)
inline int FindFirstSet(unsigned field)
{
    return 30 + __builtin_exp(field);
}
#elif defined(__ADSP21000__)
inline int FindFirstSet(unsigned field)
{
    int ret_val;

    asm("%0 = LEFTZ %1;"
	: "=d" (ret_val) : "d" (field));
    return (31 - ret_val);
}
#endif
}
#endif
namespace VDK
{
    class QueueMgr
    {

	public:

		QueueMgr()
		{
			m_IsElementPresentAtPriority = 0;
		}



		unsigned		PrioritiesWithElements() const
							{ return m_IsElementPresentAtPriority; }
	protected:





        PriorityListElement*     GetNextElement(PriorityListMgr inReadyElements[])
		{
			Priority priority = static_cast<Priority>(FindFirstSet(m_IsElementPresentAtPriority));

			return inReadyElements[priority].GetNextUnchecked();
		}


        void            Remove(PriorityListMgr inOutReadyElements[], PriorityListElement* inElementP);


        void            Insert(PriorityListMgr inOutReadyElements[], PriorityListElement* inElementP);

        static bool     MoveToEnd(PriorityListMgr inOutReadyElements[], PriorityListElement* inElementP);

        unsigned int        	m_IsElementPresentAtPriority;

    };
}
#endif
namespace VDK
{
	template <class T, int tableSize>
	class Queue : public QueueMgr
	{
		public:
	        T*   		   GetNextElement()
	        			   	{ return static_cast<T*>(VDK::QueueMgr::GetNextElement(m_ReadyElements)); }
	        T*   		   GetNextElementAtPriority(Priority priority)
	        			   	{ return static_cast<T*>(m_ReadyElements[priority].GetNext()); }
	        void           Remove(T* theElement)
						   	{ VDK::QueueMgr::Remove(m_ReadyElements, static_cast<T*>(theElement)); }
	        void           Insert(T* theElement)
						   	{ VDK::QueueMgr::Insert(m_ReadyElements, static_cast<T*>(theElement)); }
	        bool           MoveToEnd(T* theElement)
						   	{ return VDK::QueueMgr::MoveToEnd(m_ReadyElements, static_cast<T*>(theElement)); }
	        bool           MultipleElementsPresent(const VDK::Priority inPriority)
						   	{ return m_ReadyElements[inPriority].MultipleElementsPresent(); }
	    protected:
			VDK::PriorityListMgr    m_ReadyElements[tableSize];
	};
}
#endif
namespace VDK
{
        class MessageQueue : public Queue<Message, 15>
	{
		public:
			MessageQueue()
				{
					m_MsgChannelMask=0;
					m_WaitForMsgOnAllChannels = false;
				}
		    ~MessageQueue();
	        const unsigned&            MsgChannelMask() const
	                                            { return m_MsgChannelMask; }
	        unsigned&                  MsgChannelMask()
	                                            { return m_MsgChannelMask; }
	        const bool&                     WaitForMsgOnAllChannels() const
	                                            { return m_WaitForMsgOnAllChannels; }
	        bool&                           WaitForMsgOnAllChannels()
	                                            { return m_WaitForMsgOnAllChannels; }
			bool IsWaitConditionMet()
				{
					unsigned theMaskedQueue = PrioritiesWithElements() & m_MsgChannelMask;
					return m_WaitForMsgOnAllChannels ? (theMaskedQueue == m_MsgChannelMask) : (theMaskedQueue != 0);
				}
		private:
			unsigned				m_MsgChannelMask;
			bool			    		m_WaitForMsgOnAllChannels;
	};
typedef MessageQueue *MessageQueuePtr;
}
#endif
#ifndef _VDK_ABS_DEVICE_
#define _VDK_ABS_DEVICE_


#ifndef __IDTABLE__
#define __IDTABLE__
#include <string.h>
#include <limits.h>



#ifdef __cplusplus
extern "C" void KernelPanic(VDK::PanicCode, VDK::SystemError , const int);
#else
void KernelPanic(VDK_PanicCode, VDK_SystemError , const int);
#endif
namespace VDK
{
	struct IDTableElement
	{
		IDElement		    *m_ObjectPtr;
		int					m_IndexCount;
	};



    class IDTableMgr
    {
	    public:

		    static int    GetNextObjectID(IDTableElement *pIDArray, int arraySize);


	        static void   AddObject(IDElement* inObjectPtr, int inID, IDTableElement *pIDArray)
			{
				pIDArray[Index_From_ObjectID(inID)].m_ObjectPtr = inObjectPtr;
			}

			static int	GetAllObjectIDs( IDTableElement *pIDTable,
										 int			tableSize,
										 int			outArray[],
										 int			arraySize );


	        static void   RemoveObject( const int inObjectID, IDTableElement *pIDArray );


	        static IDElement*  GetObjectPtr( const int inObjectID, IDTableElement *pIDArray, int arraySize )
			{

				int index = Index_From_ObjectID(inObjectID);
#if (VDK_INSTRUMENTATION_LEVEL_>0)
				int object_count = Count_From_ObjectID(inObjectID);

				if ((index >= arraySize) || (pIDArray[index].m_IndexCount != object_count))
					return static_cast<IDElement*>(0);
#endif
				return pIDArray[index].m_ObjectPtr;
			}

		protected:

	    private:
	        IDTableMgr();
	        enum { kIndexBits = 9 };
	        enum { kNodeBits  = 5 };
	        enum { kIndexMask = ~ (-1 << kIndexBits) };
	        enum { kNodeMask  = ~ (-1 << kNodeBits) };
	        enum { kCountShift = ( kIndexBits + kNodeBits) };
	    public:

	        static int Index_From_ObjectID(const int inObjectID)
				{ return inObjectID & static_cast<int>(kIndexMask); }


	        static int Node_From_ObjectID(const int inObjectID)
				{ return (static_cast<unsigned int>(inObjectID) >> kIndexBits) & static_cast<int>(kNodeMask); }


	        static int Count_From_ObjectID(const int inObjectID)
				{ return (static_cast<unsigned int>(inObjectID) >> (kIndexBits + kNodeBits)); }
			static int Count_For_Index(int i, IDTableElement *pIDArray)
				{ return pIDArray[i].m_IndexCount << kCountShift; }

			static int ObjectID_From_Index( int index, IDTableElement *pIDArray )
			{
#if (VDK_INSTRUMENTATION_LEVEL_>0)
				return (index | (pIDArray[index].m_IndexCount << kCountShift));
#else
				return index;
#endif
			}
	};


	template <class T, class Tid> class IDTable
	{
		public:
	        Tid				GetNextObjectID() const
								{ return static_cast<Tid>(IDTableMgr::GetNextObjectID(m_IDTable, m_TableSize)); }
	        void            AddObject(T* inObjectP)
								{ IDTableMgr::AddObject(static_cast<T*>(inObjectP), static_cast<int>(inObjectP->ID()), m_IDTable); }
	        void            RemoveObject( const Tid inTid )
								{ IDTableMgr::RemoveObject(static_cast<Tid>(inTid), m_IDTable); }
	        T*				GetObjectPtr( const Tid inTid )
								{ return static_cast<T*>(IDTableMgr::GetObjectPtr(static_cast<Tid>(inTid), m_IDTable, m_TableSize)); }
			int             Count_For_Index(int i)
				                { return IDTableMgr::Count_For_Index(i, m_IDTable); }
            int             GetAllObjectIDs(Tid outArray[], int inArraySize)
				                { return IDTableMgr::GetAllObjectIDs(m_IDTable,
                                                                    m_TableSize,
                                                                    reinterpret_cast<int*>(outArray),
                                                                    inArraySize ); }
			IDTableElement		*m_IDTable;
			int					m_TableSize;
	};

}
#endif
namespace VDK
{




	class IOAbstractBase  : public IDElementTemplate<IOID>
	{
		public:




		virtual void* DispatchFunction(DispatchID inDispatchID,DispatchUnion &inDispatchUnion) = 0;
	};




	typedef struct IODeviceTemplate
	{
		IOAbstractBase* (*CreateFuncP)(void);
	} IODeviceTemplate;
}
#endif

#ifndef HEAP_H_
#define HEAP_H_
#ifdef __ADSPBLACKFIN__
#include <stdlib.h>
#endif
namespace VDK{
#ifdef  __ADSP21000__
typedef char* UserID;
#else
typedef unsigned int UserID;
#endif
    struct HeapInfo {
	public:
	   UserID m_ID;
	   unsigned int m_Index;
    } ;
extern HeapInfo g_Heaps[];

}
#endif

namespace VDK
{
    class DebugInfo;
	class Thread;
	struct ThreadTemplate;



    class Thread
        : public VDK::IDElementTemplate<ThreadID>, public TMK_Thread, public TMK_TimeElement

    {

    friend void DestroyThread( const ThreadID inThreadID, bool inDestroyNow );
    friend bool C_ISR_PostFifo(FifoID 	inFifoID, void 	        *pInData );
    friend bool PostFifo(FifoID 	inFifoID, void 	*pInData, Ticks 	inTimeout );
    friend bool PendFifo(FifoID 	inFifoID, void	**pOutData, Ticks  	inTimeout );
    public:
	void * operator new(size_t allocate_size,  ThreadType templateID);
	void * operator new(size_t allocate_size,  ThreadCreationBlock &tcb);
	void * operator new(size_t allocate_size);
	void * operator new(size_t allocate_size,const _STD nothrow_t) {
		return ::new (_STD nothrow) char[allocate_size];
	}
	inline void operator delete(void * ptr) { ::delete ptr;}
	inline void operator delete(void * ptr, ThreadType templateID) { ::delete ptr;}
	inline void operator delete(void * ptr, ThreadCreationBlock &tcb) { ::delete ptr;}
	inline void operator delete(void * ptr, const _STD nothrow_t) { ::delete ptr;}

    	typedef ::VDK::ThreadCreationBlock ThreadCreationBlock;

        typedef VDK::Thread* (*CreateFunctionP)(ThreadCreationBlock&);


        Thread(ThreadCreationBlock		&t);


        virtual ~Thread();


        virtual void Run() = 0;


        virtual int ErrorHandler();

	private:
		enum { kMaxNumDataSlots = 8 };
	public:


        unsigned int                    StackSize() const
                                            { return m_StackSize; }
        unsigned int*                   Stack() const
                                            { return m_StackP; }
        unsigned int*                   StackBase() const
                                            { return m_StackP - (m_StackSize - 1); }
#ifdef __ADSPTS__
        unsigned int                    Stack2Size() const
                                            { return m_StackSize2; }
        unsigned int*                   Stack2() const
                                            { return m_StackP2; }
#endif
        void**             				DataPtr()
                                            { return &m_DataPtr; }
		bool                            StackGuardWordChanged();


    private:
        enum { kNumDCBs = 8 };
        unsigned int            	m_StackSize;
        unsigned int            	*m_StackP;
#ifdef __ADSPTS__
        unsigned int            	m_StackSize2;
        unsigned int            	*m_StackP2;
#endif
        VDK::DebugInfo     			*m_DebugInfoP;
        unsigned int               m_DCBNotUsed;
        VDK::DeviceControlBlock  	m_DCBs[kNumDCBs];
	VDK::SystemError 			m_LastErrorType;
	int							m_LastErrorValue;
	void						*m_SlotValue[kMaxNumDataSlots];
        VDK::MessageQueuePtr           m_MessageQueuePtr;
        ThreadTemplate*              	m_TemplatePtr;
        VDK::Priority				m_InitialPriority;
        int                     	m_BlockedOnIndex;
        bool                    	m_TimeoutOccurred;
        bool                        m_ShouldDispatchError;
#ifndef __ADSPTS__
        bool                        m_UserAllocatedStack;
#endif

		static unsigned int         c_UnusedSlots;
		static void               (*c_CleanupFns[kMaxNumDataSlots]) (void *);
	protected:
		void						*m_DataPtr;




		void                        *m_APIData;
		static bool s_didConstructOK;
};


        struct ThreadTemplate
    {
		char*                           name;

#ifndef __ADSPBLACKFIN__

		HeapID              context1Heap;
#endif
		HeapID                          stack1Heap;
#ifdef __ADSPTS__
		HeapID                          context2Heap;
		HeapID                          stack2Heap;
#endif
		HeapID                          threadStructHeap;
		VDK::Priority                   priority;
		unsigned int                    stackSize;
#ifdef __ADSPTS__
		unsigned int                    stackSize2;
#endif
		VDK::Thread::CreateFunctionP    createFunction;
		bool                            messagesAllowed;
#ifdef __ADSPBLACKFIN__
		unsigned int                    pad;
#endif
	};
	struct IdleThreadInfo
    {
		unsigned int			stackSize;
#ifdef __ADSPTS__
		unsigned int			stackSize2;
#endif
		HeapID				heap;
    };
}
#endif
namespace VDK
{
    class Event : public IDElementTemplate<EventID>
    {
	friend bool PendEvent( const EventID inEventID, const Ticks inTimeout );
	friend 	SystemError GetEventPendingThreads( const EventID	inEventID,
												int				*outNumThreads,
												ThreadID		outThreadArray[],
												int				inArraySize );
        Event(Event&);
    public:


		Event(EventID inID, bool inAllBitsMatch,
					unsigned int inMask, unsigned int inVector);


    private:
        bool          		m_Value;
        TMK_ThreadList		m_PendingThreads;
        VDK::EventData		m_EventData;
    };
    extern volatile unsigned int     g_EventHasReadyThreads;
    extern VDK::Event       g_Events[];
    extern unsigned int	    kNumEvents;
}
#endif

#ifndef EVENTBIT_H_
#define EVENTBIT_H_

namespace VDK
{
    extern volatile unsigned int     g_EventBitState;
    extern volatile unsigned int     g_EventBitNeedsRecalculate;
    extern volatile unsigned int     g_EventNeedsRecalculate;
    extern unsigned int     kNumEventBits;
    class EventBit
    {
    public:

    private:

        unsigned int   m_DependentEvents;
    };





    extern VDK::EventBit    g_EventBits[];

}
#endif
#ifndef _VDK_INTVECTOR_H_
#define _VDK_INTVECTOR_H_
#ifdef __ECC__
#include <sys/exception.h>
enum {
seg_EVT_NMI=ik_nmi,
seg_EVT_IVHW=ik_hardware_err,
seg_EVT_IVG7=ik_ivg7,
seg_EVT_IVTMR=ik_timer,
seg_EVT_IVG8=ik_ivg8,
seg_EVT_IVG9=ik_ivg9,
seg_EVT_IVG10=ik_ivg10,
seg_EVT_IVG11=ik_ivg11,
seg_EVT_IVG12=ik_ivg12,
seg_EVT_IVG13=ik_ivg13
};
#define INT_CPP_ROUT(ServiceRoutine) \
EX_INTERRUPT_HANDLER(ServiceRoutine);
#define INT_C_ROUT(ServiceRoutine) \
extern "C" {EX_INTERRUPT_HANDLER(ServiceRoutine);}
#define INT_ASM_ROUT(ServiceRoutine) \
extern "asm" {EX_INTERRUPT_HANDLER(ServiceRoutine);}
#define INTVECTOR(SegIntVector, ServiceRoutine) \
{ register_handler_ex((interrupt_kind)SegIntVector,ServiceRoutine,EX_INT_DISABLE); }
#define INTVECTOR_C(SegIntVector, ServiceRoutine) \
INTVECTOR(SegIntVector, ServiceRoutine)
#define INTVECTOR_CPP(SegIntVector, ServiceRoutine) \
INTVECTOR(SegIntVector, ServiceRoutine)
#endif
#endif

#ifndef _VDK_MEM_POOL_H_
#define _VDK_MEM_POOL_H_


namespace VDK
{





class MemoryPool : public IDElementTemplate<PoolID>
{
friend SystemError GetPoolDetails( const PoolID inPoolID,
								   unsigned int *outNumBlocks,
								   void			**outMemoryAddress );
friend int GetAllMessages( MessageID	outMessageIDArray[],
						   int			inArraySize );
public:



struct block
{
	void* next;
};
	 MemoryPool(PoolID id) : m_BlkTop(0),m_NumFreeBlks(0),m_PoolStart(0),
	 							m_BlkCreatCount(0),m_TotalNumBlks(0), m_WhichHeap(0)
	 {
		ID() = id;
	 }
	~MemoryPool();

private:
	  void*               m_BlkTop;
	  void*               m_PoolStart;

	  unsigned int        m_BlkSize;
	  unsigned int        m_NumFreeBlks;
	  unsigned int        m_BlkCreatCount;
	  unsigned int        m_TotalNumBlks;
          int 		      m_WhichHeap;
};
      typedef struct BootPoolInfo
      {
              unsigned int inPoolID;
              unsigned int inBlockSize;
              unsigned int inNumBlocks;
              unsigned int inLazyCreate;
              int inWhichHeap;
      }BootPoolInfo;
}
#endif

#ifndef __MEMORYPOOLTABLE__
#define __MEMORYPOOLTABLE__



namespace VDK
{
    typedef IDTable<VDK::MemoryPool,VDK::PoolID> MemoryPoolTable;
    extern MemoryPoolTable g_MemoryPoolTable;
}
#endif

#ifndef __THREADTABLE__
#define __THREADTABLE__


namespace VDK {
    typedef IDTable < Thread, ThreadID > ThreadTable;
    extern ThreadTable g_ThreadTable;
}
#endif

#ifndef _VDK_DEVICE_FLG_
#define _VDK_DEVICE_FLG_



namespace VDK
{
extern HeapID g_DeviceFlagHeap;
class DeviceFlag;

}
#endif

#ifndef _DEVICE_FLAG_TABLE_
#define _DEVICE_FLAG_TABLE_



namespace VDK
{
    typedef IDTable<VDK::DeviceFlag,VDK::DeviceFlagID> DeviceFlagTable;
    extern DeviceFlagTable g_DeviceFlagTable;
}
#endif

#ifndef __SEMAPHORETABLE__
#define __SEMAPHORETABLE__



namespace VDK
{
    typedef IDTable<Semaphore,SemaphoreID> SemaphoreTable;
    extern VDK::SemaphoreTable g_SemaphoreTable;
}
#endif
#ifndef _VDK_ABS_DEVICE_
#define _VDK_ABS_DEVICE_


namespace VDK
{




	class IOAbstractBase  : public IDElementTemplate<IOID>
	{
		public:




		virtual void* DispatchFunction(DispatchID inDispatchID,DispatchUnion &inDispatchUnion) = 0;
	};




	typedef struct IODeviceTemplate
	{
		IOAbstractBase* (*CreateFuncP)(void);
	} IODeviceTemplate;
}
#endif
#ifndef _IO_DEVICE_TABLE_
#define _IO_DEVICE_TABLE_

#ifndef _VDK_ABS_DEVICE_
#define _VDK_ABS_DEVICE_


namespace VDK
{




	class IOAbstractBase  : public IDElementTemplate<IOID>
	{
		public:




		virtual void* DispatchFunction(DispatchID inDispatchID,DispatchUnion &inDispatchUnion) = 0;
	};




	typedef struct IODeviceTemplate
	{
		IOAbstractBase* (*CreateFuncP)(void);
	} IODeviceTemplate;
}
#endif
namespace VDK
{
    typedef IDTable<VDK::IOAbstractBase,VDK::IOID> IODeviceTable;
    extern IODeviceTable g_IOdevTable;
}
#endif
#ifndef _VDK_DRIVERS_
#define _VDK_DRIVERS_


#include <new>
namespace VDK
{


class DeviceDriver : public IOAbstractBase, public TMK_DpcElement
{
public:
        DeviceDriver();
	void * operator new(size_t allocate_size,  HeapID heap);
	void * operator new(size_t allocate_size);
	void * operator new(size_t allocate_size, const _STD nothrow_t) {return ::new char[allocate_size];}
	inline void operator delete(void * ptr) { ::delete ptr;}
	inline void operator delete(void * ptr,HeapID heap) { ::delete ptr;}
	inline void operator delete(void * ptr,const _STD nothrow_t) { ::delete ptr;}
 protected:

        static void Invoke(TMK_DpcElement *pSelf);

};
}
#endif
#ifndef __IDE_TYPEDEF_H__
#define __IDE_TYPEDEF_H__






#ifndef __VDK_ASM_OFFSETS_H_
#define __VDK_ASM_OFFSETS_H_
#define VDK_MUTEX_SIZE (20U)
#define VDK_MUTEX_LEN (5U)
#define __VDK_SIZEOF_IDElement_ (4)

#endif
typedef VDK::MemoryPool				IDE_MemoryPool;
typedef VDK::Thread 				IDE_Thread;
typedef VDK::Semaphore 				IDE_Semaphore;
typedef VDK::Message 				IDE_Message;
typedef VDK::DeviceFlag 			IDE_DeviceFlag;
typedef VDK::IDElement				IDE_Element;
typedef VDK::MsgChannel				IDE_MsgChannel;
typedef VDK::ThreadStatus			IDE_ThreadStatus;
typedef VDK::Priority				IDE_Priority;


IDE_Thread*  			IDE_ThreadPtr;
IDE_Semaphore*			IDE_SemaphorePtr;
IDE_Message*			IDE_MessagePtr;
IDE_Element* 			IDE_IDElementPtr;
IDE_MemoryPool*			IDE_MemoryPoolPtr;
IDE_DeviceFlag* 		IDE_DeviceFlagPtr;
IDE_MsgChannel*			IDE_MsgChannelPtr;
IDE_ThreadStatus*		IDE_ThreadStatusPtr;
IDE_Priority*			IDE_PriorityPtr;


typedef VDK::SemaphoreID 	IDE_SemaphoreID;
typedef VDK::EventID	 	IDE_EventID;
typedef VDK::EventBitID	 	IDE_EventBitID;
typedef VDK::DeviceFlagID 	IDE_DeviceFlagID;
typedef VDK::PoolID 		IDE_MemoryPoolID;
typedef VDK::ThreadID 		IDE_ThreadID;
IDE_SemaphoreID*		IDE_SemaphoreIDPtr;
IDE_EventID*			IDE_EventIDPtr;
IDE_EventBitID*			IDE_EventBitIDPtr;
IDE_DeviceFlagID*		IDE_DeviceFlagIDPtr;
IDE_MemoryPoolID*		IDE_MemoryPoolIDPtr;
IDE_ThreadID*			IDE_ThreadIDPtr;







namespace VDK
{
int g_Sem_ThreadBaseOffset =  __VDK_SIZEOF_IDElement_;
}

#endif


#endif /* VDK_INTERNALS_H_*/
