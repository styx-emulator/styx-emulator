/************************************************************************
 *
 * device_int.h
 *
 * (c) Copyright 2000-2009 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3522 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* device_int.h */
#endif

#ifndef _DEVICE_INT_H
#define _DEVICE_INT_H

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _MISRA_RULES */


#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ADSPBLACKFIN__)
#define _dev_open  dev_open
#define _dev_close dev_close
#define _dev_write dev_write
#define _dev_read  dev_read
#define _dev_seek  dev_seek
#define _dev_dup   dev_dup
#endif


#pragma misra_func(io)
int
_dev_open(int _dev, char *_buf, int _mode);

/* flags for _dev_open mode */

#if defined(__ADSPBLACKFIN__)
  enum {
    _dev_rdonly   = 0x0000,
    _dev_wronly   = 0x0001,
    _dev_rdwr     = 0x0002,
    _dev_append   = 0x0008,
    _dev_create   = 0x0100,
    _dev_truncate = 0x0200,
    _dev_text     = 0x4000,
    _dev_binary   = 0x8000
  };
#else
  enum {
    _dev_openr    = 0x0001,
    _dev_openw    = 0x0002,
    _dev_append   = 0x0004,
    _dev_truncate = 0x0008,
    _dev_create   = 0x0010,
    _dev_binary   = 0x0020
  };
#endif

#pragma misra_func(io)
int
_dev_close(int _fd);

#pragma misra_func(io)
int
_dev_write(int _fd, void *_buf, int _size);

#pragma misra_func(io)
int
_dev_read(int _fd, void *_buf, int _size);

#pragma misra_func(io)
long
_dev_seek(int _fd, long _offset, int _whence);

#pragma misra_func(io)
int
_dev_dup(int _fd);

extern int __default_io_device;
#pragma misra_func(io)
int get_default_io_device(void);
#pragma misra_func(io)
void set_default_io_device(int _newval);

#ifdef __cplusplus
  } /* extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _DEVICE_INT_H */
