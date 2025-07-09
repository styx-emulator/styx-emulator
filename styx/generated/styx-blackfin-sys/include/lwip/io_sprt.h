//##############################################################
//#
//# IO_SPRT.H - IO Support functions for the ADSP-2153x family
//#
//# ADSP-21535 Embedded Web Server Project
//#
//# (c) ANALOG DEVICES 2002
//#     eDSP Division
//#     Stefan Hacker
//#     23-DEC-2002
//#
//# History
//#     23-DEC-2002 HS  initial version
//#     29-DEC-2002 HS  verified all inline functions
//#     16-APR-2003 HS  release 1.0
//#

#ifndef __io_sprt_h__
#define __io_sprt_h__

#include <ccblkfn.h>
// *(unsigned char*)addr = (unsigned)value;
inline void _outp(unsigned int addr, unsigned char value)
{
	unsigned char volatile *paddr = (unsigned char volatile *)addr;

	*paddr = value;
	csync();

	/*
    asm("B[%0] = %1; CSYNC;"
        :
        : "p" (addr), "D" (value)
        : );
	*/
}

// *(unsigned short*)addr = (unsigned)value;
inline void _outpw(unsigned int addr, unsigned short value)
{
	unsigned short volatile *paddr = (unsigned short volatile *)addr;

	*paddr = value;
	csync();

	/*
    asm("W[%0] = %1; CSYNC;"
        :
        : "p" (addr), "H" (value)
        :);
		*/
}

// *(unsigned int*)addr = (unsigned)value;
inline void _outpd(unsigned int addr, unsigned int value)
{
	unsigned int volatile *paddr = (unsigned int volatile *)addr;

	*paddr = value;
	csync();
	/*
    asm("[%0] = %1; CSYNC;"
        :
        : "p" (addr), "D" (value)
        :);
		*/
}

// returns (*(unsigned char*) addr);
inline char _inp(unsigned int addr)
{
    volatile unsigned char rval;
	unsigned char volatile *paddr = (unsigned char volatile *)addr;
	rval = *paddr;

	return rval;

	/*
	unsigned char rval;
    asm("%0 = B [%1] (Z);"
        : "=D" (rval)
        : "p" (addr)
        :);
    return rval;
	*/
}

// returns (*(unsigned short*) addr);
inline short _inpw(unsigned int addr)
{
    volatile unsigned short rval;
	unsigned short volatile *paddr = (unsigned short volatile *)addr;
	rval = *paddr;

	return rval;
	/*
    unsigned short rval;
    asm("%0 = W [%1];"
        : "=H" (rval)
        : "p" (addr)
        :);
    return rval;
	*/
}

// returns (*(unsigned int*) addr);
inline int _inpd(unsigned int addr)
{
    volatile int rval;
	unsigned int volatile *paddr = (unsigned int volatile *)addr;
	rval = *paddr;

	return rval;

	/*
    unsigned int rval;
    asm("%0 = [%1];"
        : "=D" (rval)
        : "p" (addr)
        :);
    return rval;
	*/
}

// *(unsigned int*)addr = (unsigned)value;
inline void _ch_clk(unsigned int addr, unsigned int value)
{
	unsigned int volatile *paddr = (unsigned int volatile *)addr;

	*paddr = value;
	ssync();

	/*
    asm("[%0] = %1; SSYNC; nop; nop; nop;"
        :
        : "p" (addr), "D" (value)
        :);
        */
}
#endif // __io_sprt_h__
