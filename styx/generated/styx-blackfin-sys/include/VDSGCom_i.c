

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 6.00.0361 */
/* at Fri Jan 06 14:55:33 2006
 */
/* Compiler settings for .\VDSGCom.idl:
    Oicf, W1, Zp8, env=Win32 (32b run)
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data
    VC __declspec() decoration level:
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
//@@MIDL_FILE_HEADING(  )

#if !defined(_M_IA64) && !defined(_M_AMD64)


#pragma warning( disable: 4049 )  /* more than 64k source lines */


#ifdef __cplusplus
extern "C"{
#endif


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IVDSGPrinter,0xD3A87A3B,0xA8A3,0x4b78,0xAB,0xC5,0x18,0x63,0x3E,0x3C,0x29,0x3C);


MIDL_DEFINE_GUID(IID, IID_IVDSGDocument,0x45C49022,0x10F5,0x4c8e,0x87,0xAD,0x9F,0x55,0x35,0xEB,0x2B,0x02);


MIDL_DEFINE_GUID(IID, IID_IVDSGApp,0x3DCA6F43,0x2407,0x44cf,0xA0,0x48,0xCA,0xBD,0x9F,0x04,0x21,0x51);


MIDL_DEFINE_GUID(IID, IID_IVDSG,0x0BEB4437,0xB750,0x4D48,0xB8,0x9B,0x37,0x96,0x7E,0x46,0x14,0xD8);


MIDL_DEFINE_GUID(IID, LIBID_VDSGComLib,0x6F7D00BB,0xB534,0x48AB,0xAE,0xE2,0xC2,0xC6,0x10,0x73,0xE7,0x65);


MIDL_DEFINE_GUID(CLSID, CLSID_VDSG,0xAFCA1AA5,0xB871,0x45C9,0x83,0xCC,0x66,0xB1,0x67,0xC1,0x00,0x70);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



#endif /* !defined(_M_IA64) && !defined(_M_AMD64)*/
