#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* pcio.h */
#endif
/************************************************************************
 *
 * pcio.h
 *
 * (c) Copyright 2002-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef _PCIO_H
#define _PCIO_H

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#endif /* _MISRA_RULES */


#define PCI_WRITE_REQUEST   1
#define PCI_READ_REQUEST    2
#define PCI_RESET_DRIVER_REQUEST 3
#define PCI_PRINTF_REQUEST  4
#define PCI_EXIT_REQUEST    5
#define PCI_F115            6
#define PCI_F97             7
#define PCI_OPEN_REQUEST    8
#define PCI_CLOSE_REQUEST   9

#define PCI_NEW_EXIT_REQUEST 10

#define PCI_CHECKSUM_REQUEST 11
#define PCI_ARGS_REQUEST    12
#define PCI_BREAKPOINT_REQUEST 13
#define PCI_SEEK_REQUEST    14
#define PCI_DSP_EXIT_REQUEST 15

#define PCI_MAX_ARGS        40

#define PCI_MAX_STRLEN      16
#define PCI_MAX_STRLEN_LOG  4

typedef struct {
  int cmd;               /* + 0x00 */
  unsigned char *buffer; /* + 0x04 */
  int count;             /* + 0x08 */
  char *filename;        /* + 0x0C */
  int mode;              /* + 0x10 */
  char *string;          /* + 0x14 */
  int fileid;            /* + 0x18 */
  int result;            /* + 0x1C */
  int eof;               /* + 0x20 */
  int argc;              /* + 0x24 */
  int argv;              /* + 0x28 */
  int strarg;            /* + 0x2C */
} PciIoCB;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _PCIO_H */
