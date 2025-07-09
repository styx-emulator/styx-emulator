/* Copyright (C) 2011 Analog Devices, Inc. All Rights Reserved.
**
** Support for avoidance of silicon anomaly 05-00-0312:
** SYNC operations must be non-interruptible.
**
** This header defines macros for use in assembly language,
** to make code which must use SYNC operations easier to
** read.
*/

#ifndef _DEF_05000312_H
#define _DEF_05000312_H

#if !defined(_LANGUAGE_C)

#include <sys/platform.h>

#if defined(__WORKAROUND_SYNC_LOOP_ANOM_312)

// Anomaly 05-00-0312 requires CSYNC operations to be non-interruptible,
// so define some macros to turn off interrupts temporarily. Since the
// assembler will warn about this anomaly applying, also turn off the
// assembler's warning for these specific cases.

#define WA_312_CLI(_r)  CLI _r;
#define WA_312_STI(_r)  STI _r;
#define WA_312_PRESYNC  .MESSAGE/SUPPRESS 5515 FOR 1 LINES;
#define WA_312_CSYNC    CSYNC
#define WA_312_SSYNC    SSYNC

#else

// If Anomaly 05-00-0312 does not apply to the current build, then
// define the CLI/STI macros to do nothing, and for the SYNC macros
// to just be the instruction (the assembler warning is allowed, but
// should not be triggered).

#define WA_312_CLI(_r)
#define WA_312_STI(_r)
#define WA_312_PRESYNC
#define WA_312_CSYNC  CSYNC
#define WA_312_SSYNC  SSYNC

#endif


#endif /* _LANGUAGE_C */
#endif /* !_DEF_05000312_H */
