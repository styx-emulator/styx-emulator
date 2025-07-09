/****************************************************************************
 *
 * xsyslock.h : $Revision: 1.13.2.7 $
 *
 * Locking facilities that are used in public header files.
 * Do not use these in application code.
 *
 * (c) Copyright 2009-2010 Analog Devices, Inc.  All rights reserved.
 *
 ****************************************************************************/

#ifndef _XSYSLOCK
#define _XSYSLOCK

#include <yvals.h>
#include <sys/adi_rtl_sync.h>

enum { _LOCK_STREAM = 0, _LOCK_MALLOC = 1, _LOCK_LOCALE = 2 };

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_1:"Inline functions don't need prototypes")
#pragma diag(suppress:misra_rule_8_5:"Allow inline function definitions")
#pragma diag(suppress:misra_rule_19_4:"Allow non-MISRA compliant substituion text")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function-like macros")
#endif /* _MISRA_RULES */

#if _MULTI_THREAD

_EXTERN_C

extern adi_rtl_mutex _Files_mutex;

void __check_and_acquire_mutex(adi_rtl_mutex *mutex, bool io);

#pragma inline
#pragma always_inline
static void
_Locksyslock(int lockno)
{
  if (lockno == _LOCK_STREAM) {
    __check_and_acquire_mutex(&_Files_mutex, true);
  } else {
    adi_rtl_lock_globals();
  }
}

#pragma inline
#pragma always_inline
static void
_Unlocksyslock(int lockno)
{
  if (lockno == _LOCK_STREAM) {
    adi_rtl_release_mutex(&_Files_mutex);
  } else {
    adi_rtl_unlock_globals();
  }
}

_END_EXTERN_C

#else /* _MULTI_THREAD */

#define _Locksyslock(x)	((void)0)
#define _Unlocksyslock(x)	((void)0)

#endif /* _MULTI_THREAD */


#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */


#if defined(__cplusplus)

_STD_BEGIN

		// BLOCK-LOCAL LOCKS
class _Lockit
	{	// lock while object in existence -- MUST NEST
public:

#if !_MULTI_THREAD
	#pragma always_inline
	_Lockit()
		{	// do nothing
		}

	#pragma always_inline
	explicit _Lockit(int)
		{	// do nothing
		}

   #pragma always_inline
	~_Lockit()
		{	// do nothing
		}
#else /* !_MULTI_THREAD */
	#pragma always_inline
	explicit _Lockit()
		: _Locktype(_LOCK_MALLOC)
		{	// set default lock
		_Locksyslock(_Locktype);
		}

	#pragma always_inline
	explicit _Lockit(int _Type)
		: _Locktype(_Type)
		{	// set the lock
		_Locksyslock(_Locktype);
		}

	#pragma always_inline
	~_Lockit()
		{	// clear the lock
		_Unlocksyslock(_Locktype);
		}

private:
	int _Locktype;
#endif /* !_MULTI_THREAD */

public:
	_Lockit(const _Lockit&);			// not defined
	_Lockit& operator=(const _Lockit&);	// not defined
	};


class _Mutex
	{
#if _MULTI_THREAD
 #if _IOSTREAM_OP_LOCKS

	// stream-specific locks
public:
	#pragma always_inline
	_Mutex() : _Mtx(ADI_RTL_INVALID_MUTEX) {}

	#pragma always_inline
	~_Mutex()
		{
		if (_Mtx != ADI_RTL_INVALID_MUTEX)
			adi_rtl_deinit_mutex(&_Mtx);
		}

	#pragma always_inline
	void _Lock() { __check_and_acquire_mutex(&_Mtx, false); }

	#pragma always_inline
	void _Unlock() { adi_rtl_release_mutex(&_Mtx); }

private:
	_Mutex(const _Mutex&);				// not defined
	_Mutex& operator=(const _Mutex&);	// not defined
	adi_rtl_mutex _Mtx;

 #else /* _IOSTREAM_OP_LOCKS */

	// global stream lock
public:
	#pragma always_inline
	void _Lock() { _Locksyslock(_LOCK_STREAM); }

	#pragma always_inline
	void _Unlock() { _Unlocksyslock(_LOCK_STREAM); }

 #endif /* _IOSTREAM_OP_LOCKS */

#else /* _MULTI_THREAD */

	// single-threaded: do nothing
public:
	#pragma always_inline
	void _Lock() {}

	#pragma always_inline
	void _Unlock() {}

#endif /* _MULTI_THREAD */
	};

_STD_END

#endif  /* defined(_cplusplus) */

#endif /* _XSYSLOCK */
