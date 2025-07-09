/************************************************************************
 *
 * device.h
 *
 * (c) Copyright 2000-2005 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3522 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* device.h */
#endif

#ifndef _DEVICE_H
#define _DEVICE_H

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#endif /* _MISRA_RULES */

#ifndef MAXDEV
# define MAXDEV 10
#endif

#ifndef MAXFD
# define MAXFD  25
#endif

#if defined(__ADSPBLACKFIN__)
#define FILEIO 0
#define PRIMIO 1
#define PCI_IO 2
#define CSIMIO 3
#else
#define PRIMIO 0
#define FILEIO 1
#define PCI_IO 2
#define CSIMIO 3
#endif

#define _DEV_IS_THREADSAFE 0x80000000

enum { dev_not_claimed = -1 };

/* Device Entry Structure. Each device will have one assoc.'d with it */
struct DevEntry{
  int   DeviceID;
  void  *data;

  int   (*init)(struct DevEntry *dev);
  int   (*open)(const char *name, int mode);
  int   (*close)(int fd);
  int   (*write)(int fd, unsigned char *buf, int size);
  int   (*read)(int fd, unsigned char *buf, int size);
  long  (*seek)(int fd, long offset, int whence);
  int   stdinfd;
  int   stdoutfd;
  int   stderrfd;
};


typedef struct DevEntry DevEntry;
typedef struct DevEntry *DevEntry_t;

/* structure containing a pointer to a Device Entry Struct and a file des. */
typedef struct sDevTab{
  int           DevFileDes;
  int           DeviceID;
} sDevTab;


#ifdef __cplusplus
extern "C" {
#endif

/* addition of customised device drivers */
#pragma misra_func(io)
int add_devtab_entry(DevEntry_t entry);

#ifdef __cplusplus
}
#endif


#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _DEVICE_H */
