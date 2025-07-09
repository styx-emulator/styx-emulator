/* generated from FatalError.xml schema 1 */
#ifndef _ADI_FATAL_ERROR_CODES_H
#define _ADI_FATAL_ERROR_CODES_H

#ifdef _LANGUAGE_C
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_1:"Header uses long macro names")
#endif

/* General codes: code representing the tool reporting the error. Prefixed with _AFE_G_ and used as 1st paramater to adi_fatal_error() and adi_fatal_exception() */

#define _AFE_G_NoError (0x0)
#define _AFE_G_LibraryError (0x7)
#define _AFE_G_RunTimeError (0x8)
#define _AFE_G_UnhandledException (0x9)
#define _AFE_G_UserError (0xffffffff)

/* Specific codes: code representing the specific details of the error. Prefixed with _AFE_S_ and used as 2nd paramater to adi_fatal_error() and adi_fatal_exception() */


/* Specific list 0x0, vdk="no" */
#define _AFE_S_NoError (0x0)

/* Specific list 0x2, vdk="no" */
#define _AFE_S_TLSSlotAllocFailed (0x1)
#define _AFE_S_InsufficientHeapForLibrary (0x2)
#define _AFE_S_IONotAllowed (0x3)
#define _AFE_S_ProfBadExeName (0x4)
#define _AFE_S_HeapUnknown (0x101)
#define _AFE_S_HeapFailed (0x102)
#define _AFE_S_HeapAllocationOfZero (0x103)
#define _AFE_S_HeapNullPointer (0x104)
#define _AFE_S_HeapInvalidAddress (0x105)
#define _AFE_S_HeapBlockIsCorrupt (0x106)
#define _AFE_S_HeapReallocOfZero (0x107)
#define _AFE_S_HeapFunctionMismatch (0x108)
#define _AFE_S_HeapUnfreedBlock (0x109)
#define _AFE_S_HeapWrongHeap (0x10a)
#define _AFE_S_HeapAllocationTooLarge (0x10b)
#define _AFE_S_HeapInvalidInput (0x10c)
#define _AFE_S_HeapInternalError (0x10d)
#define _AFE_S_HeapInInterrupt (0x10e)
#define _AFE_S_HeapMissingOutput (0x10f)
#define _AFE_S_HeapInsufficientSpace (0x110)
#define _AFE_S_HeapCantOpenDump (0x111)
#define _AFE_S_HeapCantOpenTrace (0x112)
#define _AFE_S_HeapInvalidHeapID (0x113)
#define _AFE_S_InstrprofIOFail (0x201)
#define _AFE_S_PGOHWFailedOutput (0x301)
#define _AFE_S_PGOHWDataCorrupted (0x302)

/* Specific list 0x3, vdk="no" */
#define _AFE_S_CPLBMissAllLocked (0x1)
#define _AFE_S_CPLBMissWithoutReplacement (0x2)
#define _AFE_S_CPLBProtectionViolation (0x3)
#define _AFE_S_CPLBAddressIsMisalignedForCPLBSize (0x4)
#define _AFE_S_L1CodeCacheEnabledWhenL1UsedForCode (0x5)
#define _AFE_S_L1DataACacheEnabledWhenUsedForData (0x6)
#define _AFE_S_L1DataBCacheEnabledWhenUsedForData (0x7)
#define _AFE_S_TooManyLockedDataCPLB (0x8)
#define _AFE_S_TooManyLockedInstructionCPLB (0x9)
#define _AFE_S_CPLBDoubleHit (0xA)

/* Specific list 0x4, vdk="no" */
#define _AFE_S_TraceBufferFull (0x11)
#define _AFE_S_UndefinedInstruction (0x21)
#define _AFE_S_IllegalInstructionCombination (0x22)
#define _AFE_S_DataAccessCPLBProtection (0x23)
#define _AFE_S_DataMisalignedAccessViolation (0x24)
#define _AFE_S_UnrecoverableEvent (0x25)
#define _AFE_S_DataCPLBMiss (0x26)
#define _AFE_S_DataCPLBMultipleHits (0x27)
#define _AFE_S_EmulationWatchpoint (0x28)
#define _AFE_S_InstructionFetchMisaligned (0x2A)
#define _AFE_S_InstructionFetchViolation (0x2B)
#define _AFE_S_InstructionCPLBMiss (0x2C)
#define _AFE_S_InstructionCPLBMultipleHits (0x2D)
#define _AFE_S_SupervisorResource (0x2E)

/* Specific list 0xffffffff, vdk="no" */
#define _AFE_S_NoError (0x0)
#define _AFE_S_FirstUserError (0x1)
#define _AFE_S_LastUserError (0xffffffff)

#ifdef _LANGUAGE_C
#pragma diag(pop)
#endif

#endif /* _ADI_FATAL_ERROR_CODES_H */
