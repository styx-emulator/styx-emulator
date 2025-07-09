// new.h standard header
#if defined (_ADI_COMPILER)
/************************************************************************
 *
 * new.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 * (c) Copyright 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * $Revision: 3522 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* new.h */
#endif
#endif /* _ADI_COMPILER */

#ifndef _NEW_H_
#define _NEW_H_
#include <new>

 #if _HAS_NAMESPACE
using std::bad_alloc;
using std::new_handler;
using std::nothrow;
using std::nothrow_t;
using std::set_new_handler;
 #endif /* _HAS_NAMESPACE */

#endif /* _NEW_ */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
