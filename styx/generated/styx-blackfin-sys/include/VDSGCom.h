

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


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

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __VDSGCom_h__
#define __VDSGCom_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */

#ifndef __IVDSGPrinter_FWD_DEFINED__
#define __IVDSGPrinter_FWD_DEFINED__
typedef interface IVDSGPrinter IVDSGPrinter;
#endif 	/* __IVDSGPrinter_FWD_DEFINED__ */


#ifndef __IVDSGDocument_FWD_DEFINED__
#define __IVDSGDocument_FWD_DEFINED__
typedef interface IVDSGDocument IVDSGDocument;
#endif 	/* __IVDSGDocument_FWD_DEFINED__ */


#ifndef __IVDSGApp_FWD_DEFINED__
#define __IVDSGApp_FWD_DEFINED__
typedef interface IVDSGApp IVDSGApp;
#endif 	/* __IVDSGApp_FWD_DEFINED__ */


#ifndef __IVDSG_FWD_DEFINED__
#define __IVDSG_FWD_DEFINED__
typedef interface IVDSG IVDSG;
#endif 	/* __IVDSG_FWD_DEFINED__ */


#ifndef __VDSG_FWD_DEFINED__
#define __VDSG_FWD_DEFINED__

#ifdef __cplusplus
typedef class VDSG VDSG;
#else
typedef struct VDSG VDSG;
#endif /* __cplusplus */

#endif 	/* __VDSG_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif

void * __RPC_USER MIDL_user_allocate(size_t);
void __RPC_USER MIDL_user_free( void * );

#ifndef __IVDSGPrinter_INTERFACE_DEFINED__
#define __IVDSGPrinter_INTERFACE_DEFINED__

/* interface IVDSGPrinter */
/* [unique][helpstring][nonextensible][uuid][object] */


EXTERN_C const IID IID_IVDSGPrinter;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("D3A87A3B-A8A3-4b78-ABC5-18633E3C293C")
    IVDSGPrinter : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetText(
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [out] */ BSTR *pStrText) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetText(
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strText) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetCData(
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [out] */ BSTR *pStrText) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetCData(
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strText) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetAttribute(
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strName,
            /* [out] */ BSTR *pStrValue) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetAttribute(
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strName,
            /* [in] */ BSTR strValue) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetNameAndValue(
            /* [in] */ IXMLDOMAttribute *pAttrNode,
            /* [out] */ BSTR *strName,
            /* [out] */ BSTR *strValue) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetEntity(
            /* [in] */ LPCTSTR szName,
            /* [in] */ LPCTSTR szValue) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetEntity(
            /* [in] */ LPCTSTR szName,
            /* [out] */ LPTSTR *pszValue) = 0;

        virtual HRESULT STDMETHODCALLTYPE RemoveEntity(
            /* [in] */ LPCTSTR szName) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetEntityReplacement(
            /* [in] */ LPCTSTR szInput,
            /* [out] */ LPTSTR *szOutput) = 0;

        virtual HRESULT STDMETHODCALLTYPE ReleaseEntityReplacement(
            /* [in] */ LPCTSTR szInput) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetCommentWidth(
            /* [out] */ int *pOldWidth) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetCommentWidth(
            /* [in] */ int NewWidth) = 0;

        virtual HRESULT STDMETHODCALLTYPE IncrCommentWidth(
            /* [in] */ int delta) = 0;

        virtual HRESULT STDMETHODCALLTYPE DecrCommentWidth(
            /* [in] */ int delta) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetIndent(
            /* [out] */ int *pOldIndent) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetIndent(
            /* [in] */ int NewIndent) = 0;

        virtual HRESULT STDMETHODCALLTYPE IncrIndent(
            /* [in] */ int delta) = 0;

        virtual HRESULT STDMETHODCALLTYPE DecrIndent(
            /* [in] */ int delta) = 0;

        virtual HRESULT STDMETHODCALLTYPE UnIndent( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE RestoreIndent( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE ResetIndent( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE Write(
            /* [in] */ LPCTSTR szText) = 0;

        virtual HRESULT STDMETHODCALLTYPE StartLine(
            /* [in] */ LPCTSTR szText) = 0;

        virtual HRESULT STDMETHODCALLTYPE EndLine(
            /* [in] */ LPCTSTR szText) = 0;

        virtual HRESULT STDMETHODCALLTYPE WriteLine(
            /* [in] */ LPCTSTR szText) = 0;

        virtual HRESULT STDMETHODCALLTYPE WriteCommentLine(
            /* [in] */ LPCTSTR szText) = 0;

        virtual HRESULT STDMETHODCALLTYPE WriteCommentBanner(
            /* [in] */ LPCTSTR szUID,
            /* [in] */ LPCTSTR szText) = 0;

        virtual HRESULT STDMETHODCALLTYPE printVdsgText(
            /* [in] */ IXMLDOMText *pTextNode) = 0;

        virtual HRESULT STDMETHODCALLTYPE printVdsgCData(
            /* [in] */ IXMLDOMCDATASection *pCDataNode) = 0;

        virtual HRESULT STDMETHODCALLTYPE printVdsgVdsgTag(
            /* [in] */ IXMLDOMElement *pElemNode) = 0;

        virtual HRESULT STDMETHODCALLTYPE printVdsgFileTag(
            /* [in] */ IXMLDOMElement *pElemNode) = 0;

        virtual HRESULT STDMETHODCALLTYPE printVdsgUserTag(
            /* [in] */ IXMLDOMElement *pElemNode) = 0;

        virtual HRESULT STDMETHODCALLTYPE printChildren(
            /* [in] */ IXMLDOMElement *pElemNode) = 0;

        virtual HRESULT STDMETHODCALLTYPE HasUserCode(
            LPCTSTR szUID) = 0;

        virtual HRESULT STDMETHODCALLTYPE DeleteUserCode(
            LPCTSTR szUID) = 0;

    };

#else 	/* C style interface */

    typedef struct IVDSGPrinterVtbl
    {
        BEGIN_INTERFACE

        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
            IVDSGPrinter * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
            IVDSGPrinter * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
            IVDSGPrinter * This);

        HRESULT ( STDMETHODCALLTYPE *GetText )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [out] */ BSTR *pStrText);

        HRESULT ( STDMETHODCALLTYPE *SetText )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strText);

        HRESULT ( STDMETHODCALLTYPE *GetCData )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [out] */ BSTR *pStrText);

        HRESULT ( STDMETHODCALLTYPE *SetCData )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strText);

        HRESULT ( STDMETHODCALLTYPE *GetAttribute )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strName,
            /* [out] */ BSTR *pStrValue);

        HRESULT ( STDMETHODCALLTYPE *SetAttribute )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode,
            /* [in] */ BSTR strName,
            /* [in] */ BSTR strValue);

        HRESULT ( STDMETHODCALLTYPE *GetNameAndValue )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMAttribute *pAttrNode,
            /* [out] */ BSTR *strName,
            /* [out] */ BSTR *strValue);

        HRESULT ( STDMETHODCALLTYPE *SetEntity )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szName,
            /* [in] */ LPCTSTR szValue);

        HRESULT ( STDMETHODCALLTYPE *GetEntity )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szName,
            /* [out] */ LPTSTR *pszValue);

        HRESULT ( STDMETHODCALLTYPE *RemoveEntity )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szName);

        HRESULT ( STDMETHODCALLTYPE *GetEntityReplacement )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szInput,
            /* [out] */ LPTSTR *szOutput);

        HRESULT ( STDMETHODCALLTYPE *ReleaseEntityReplacement )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szInput);

        HRESULT ( STDMETHODCALLTYPE *GetCommentWidth )(
            IVDSGPrinter * This,
            /* [out] */ int *pOldWidth);

        HRESULT ( STDMETHODCALLTYPE *SetCommentWidth )(
            IVDSGPrinter * This,
            /* [in] */ int NewWidth);

        HRESULT ( STDMETHODCALLTYPE *IncrCommentWidth )(
            IVDSGPrinter * This,
            /* [in] */ int delta);

        HRESULT ( STDMETHODCALLTYPE *DecrCommentWidth )(
            IVDSGPrinter * This,
            /* [in] */ int delta);

        HRESULT ( STDMETHODCALLTYPE *GetIndent )(
            IVDSGPrinter * This,
            /* [out] */ int *pOldIndent);

        HRESULT ( STDMETHODCALLTYPE *SetIndent )(
            IVDSGPrinter * This,
            /* [in] */ int NewIndent);

        HRESULT ( STDMETHODCALLTYPE *IncrIndent )(
            IVDSGPrinter * This,
            /* [in] */ int delta);

        HRESULT ( STDMETHODCALLTYPE *DecrIndent )(
            IVDSGPrinter * This,
            /* [in] */ int delta);

        HRESULT ( STDMETHODCALLTYPE *UnIndent )(
            IVDSGPrinter * This);

        HRESULT ( STDMETHODCALLTYPE *RestoreIndent )(
            IVDSGPrinter * This);

        HRESULT ( STDMETHODCALLTYPE *ResetIndent )(
            IVDSGPrinter * This);

        HRESULT ( STDMETHODCALLTYPE *Write )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szText);

        HRESULT ( STDMETHODCALLTYPE *StartLine )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szText);

        HRESULT ( STDMETHODCALLTYPE *EndLine )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szText);

        HRESULT ( STDMETHODCALLTYPE *WriteLine )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szText);

        HRESULT ( STDMETHODCALLTYPE *WriteCommentLine )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szText);

        HRESULT ( STDMETHODCALLTYPE *WriteCommentBanner )(
            IVDSGPrinter * This,
            /* [in] */ LPCTSTR szUID,
            /* [in] */ LPCTSTR szText);

        HRESULT ( STDMETHODCALLTYPE *printVdsgText )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMText *pTextNode);

        HRESULT ( STDMETHODCALLTYPE *printVdsgCData )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMCDATASection *pCDataNode);

        HRESULT ( STDMETHODCALLTYPE *printVdsgVdsgTag )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode);

        HRESULT ( STDMETHODCALLTYPE *printVdsgFileTag )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode);

        HRESULT ( STDMETHODCALLTYPE *printVdsgUserTag )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode);

        HRESULT ( STDMETHODCALLTYPE *printChildren )(
            IVDSGPrinter * This,
            /* [in] */ IXMLDOMElement *pElemNode);

        HRESULT ( STDMETHODCALLTYPE *HasUserCode )(
            IVDSGPrinter * This,
            LPCTSTR szUID);

        HRESULT ( STDMETHODCALLTYPE *DeleteUserCode )(
            IVDSGPrinter * This,
            LPCTSTR szUID);

        END_INTERFACE
    } IVDSGPrinterVtbl;

    interface IVDSGPrinter
    {
        CONST_VTBL struct IVDSGPrinterVtbl *lpVtbl;
    };



#ifdef COBJMACROS


#define IVDSGPrinter_QueryInterface(This,riid,ppvObject)	\
    (This)->lpVtbl -> QueryInterface(This,riid,ppvObject)

#define IVDSGPrinter_AddRef(This)	\
    (This)->lpVtbl -> AddRef(This)

#define IVDSGPrinter_Release(This)	\
    (This)->lpVtbl -> Release(This)


#define IVDSGPrinter_GetText(This,pElemNode,pStrText)	\
    (This)->lpVtbl -> GetText(This,pElemNode,pStrText)

#define IVDSGPrinter_SetText(This,pElemNode,strText)	\
    (This)->lpVtbl -> SetText(This,pElemNode,strText)

#define IVDSGPrinter_GetCData(This,pElemNode,pStrText)	\
    (This)->lpVtbl -> GetCData(This,pElemNode,pStrText)

#define IVDSGPrinter_SetCData(This,pElemNode,strText)	\
    (This)->lpVtbl -> SetCData(This,pElemNode,strText)

#define IVDSGPrinter_GetAttribute(This,pElemNode,strName,pStrValue)	\
    (This)->lpVtbl -> GetAttribute(This,pElemNode,strName,pStrValue)

#define IVDSGPrinter_SetAttribute(This,pElemNode,strName,strValue)	\
    (This)->lpVtbl -> SetAttribute(This,pElemNode,strName,strValue)

#define IVDSGPrinter_GetNameAndValue(This,pAttrNode,strName,strValue)	\
    (This)->lpVtbl -> GetNameAndValue(This,pAttrNode,strName,strValue)

#define IVDSGPrinter_SetEntity(This,szName,szValue)	\
    (This)->lpVtbl -> SetEntity(This,szName,szValue)

#define IVDSGPrinter_GetEntity(This,szName,pszValue)	\
    (This)->lpVtbl -> GetEntity(This,szName,pszValue)

#define IVDSGPrinter_RemoveEntity(This,szName)	\
    (This)->lpVtbl -> RemoveEntity(This,szName)

#define IVDSGPrinter_GetEntityReplacement(This,szInput,szOutput)	\
    (This)->lpVtbl -> GetEntityReplacement(This,szInput,szOutput)

#define IVDSGPrinter_ReleaseEntityReplacement(This,szInput)	\
    (This)->lpVtbl -> ReleaseEntityReplacement(This,szInput)

#define IVDSGPrinter_GetCommentWidth(This,pOldWidth)	\
    (This)->lpVtbl -> GetCommentWidth(This,pOldWidth)

#define IVDSGPrinter_SetCommentWidth(This,NewWidth)	\
    (This)->lpVtbl -> SetCommentWidth(This,NewWidth)

#define IVDSGPrinter_IncrCommentWidth(This,delta)	\
    (This)->lpVtbl -> IncrCommentWidth(This,delta)

#define IVDSGPrinter_DecrCommentWidth(This,delta)	\
    (This)->lpVtbl -> DecrCommentWidth(This,delta)

#define IVDSGPrinter_GetIndent(This,pOldIndent)	\
    (This)->lpVtbl -> GetIndent(This,pOldIndent)

#define IVDSGPrinter_SetIndent(This,NewIndent)	\
    (This)->lpVtbl -> SetIndent(This,NewIndent)

#define IVDSGPrinter_IncrIndent(This,delta)	\
    (This)->lpVtbl -> IncrIndent(This,delta)

#define IVDSGPrinter_DecrIndent(This,delta)	\
    (This)->lpVtbl -> DecrIndent(This,delta)

#define IVDSGPrinter_UnIndent(This)	\
    (This)->lpVtbl -> UnIndent(This)

#define IVDSGPrinter_RestoreIndent(This)	\
    (This)->lpVtbl -> RestoreIndent(This)

#define IVDSGPrinter_ResetIndent(This)	\
    (This)->lpVtbl -> ResetIndent(This)

#define IVDSGPrinter_Write(This,szText)	\
    (This)->lpVtbl -> Write(This,szText)

#define IVDSGPrinter_StartLine(This,szText)	\
    (This)->lpVtbl -> StartLine(This,szText)

#define IVDSGPrinter_EndLine(This,szText)	\
    (This)->lpVtbl -> EndLine(This,szText)

#define IVDSGPrinter_WriteLine(This,szText)	\
    (This)->lpVtbl -> WriteLine(This,szText)

#define IVDSGPrinter_WriteCommentLine(This,szText)	\
    (This)->lpVtbl -> WriteCommentLine(This,szText)

#define IVDSGPrinter_WriteCommentBanner(This,szUID,szText)	\
    (This)->lpVtbl -> WriteCommentBanner(This,szUID,szText)

#define IVDSGPrinter_printVdsgText(This,pTextNode)	\
    (This)->lpVtbl -> printVdsgText(This,pTextNode)

#define IVDSGPrinter_printVdsgCData(This,pCDataNode)	\
    (This)->lpVtbl -> printVdsgCData(This,pCDataNode)

#define IVDSGPrinter_printVdsgVdsgTag(This,pElemNode)	\
    (This)->lpVtbl -> printVdsgVdsgTag(This,pElemNode)

#define IVDSGPrinter_printVdsgFileTag(This,pElemNode)	\
    (This)->lpVtbl -> printVdsgFileTag(This,pElemNode)

#define IVDSGPrinter_printVdsgUserTag(This,pElemNode)	\
    (This)->lpVtbl -> printVdsgUserTag(This,pElemNode)

#define IVDSGPrinter_printChildren(This,pElemNode)	\
    (This)->lpVtbl -> printChildren(This,pElemNode)

#define IVDSGPrinter_HasUserCode(This,szUID)	\
    (This)->lpVtbl -> HasUserCode(This,szUID)

#define IVDSGPrinter_DeleteUserCode(This,szUID)	\
    (This)->lpVtbl -> DeleteUserCode(This,szUID)

#endif /* COBJMACROS */


#endif 	/* C style interface */



HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetText_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode,
    /* [out] */ BSTR *pStrText);


void __RPC_STUB IVDSGPrinter_GetText_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_SetText_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode,
    /* [in] */ BSTR strText);


void __RPC_STUB IVDSGPrinter_SetText_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetCData_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode,
    /* [out] */ BSTR *pStrText);


void __RPC_STUB IVDSGPrinter_GetCData_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_SetCData_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode,
    /* [in] */ BSTR strText);


void __RPC_STUB IVDSGPrinter_SetCData_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetAttribute_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode,
    /* [in] */ BSTR strName,
    /* [out] */ BSTR *pStrValue);


void __RPC_STUB IVDSGPrinter_GetAttribute_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_SetAttribute_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode,
    /* [in] */ BSTR strName,
    /* [in] */ BSTR strValue);


void __RPC_STUB IVDSGPrinter_SetAttribute_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetNameAndValue_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMAttribute *pAttrNode,
    /* [out] */ BSTR *strName,
    /* [out] */ BSTR *strValue);


void __RPC_STUB IVDSGPrinter_GetNameAndValue_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_SetEntity_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szName,
    /* [in] */ LPCTSTR szValue);


void __RPC_STUB IVDSGPrinter_SetEntity_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetEntity_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szName,
    /* [out] */ LPTSTR *pszValue);


void __RPC_STUB IVDSGPrinter_GetEntity_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_RemoveEntity_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szName);


void __RPC_STUB IVDSGPrinter_RemoveEntity_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetEntityReplacement_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szInput,
    /* [out] */ LPTSTR *szOutput);


void __RPC_STUB IVDSGPrinter_GetEntityReplacement_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_ReleaseEntityReplacement_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szInput);


void __RPC_STUB IVDSGPrinter_ReleaseEntityReplacement_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetCommentWidth_Proxy(
    IVDSGPrinter * This,
    /* [out] */ int *pOldWidth);


void __RPC_STUB IVDSGPrinter_GetCommentWidth_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_SetCommentWidth_Proxy(
    IVDSGPrinter * This,
    /* [in] */ int NewWidth);


void __RPC_STUB IVDSGPrinter_SetCommentWidth_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_IncrCommentWidth_Proxy(
    IVDSGPrinter * This,
    /* [in] */ int delta);


void __RPC_STUB IVDSGPrinter_IncrCommentWidth_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_DecrCommentWidth_Proxy(
    IVDSGPrinter * This,
    /* [in] */ int delta);


void __RPC_STUB IVDSGPrinter_DecrCommentWidth_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_GetIndent_Proxy(
    IVDSGPrinter * This,
    /* [out] */ int *pOldIndent);


void __RPC_STUB IVDSGPrinter_GetIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_SetIndent_Proxy(
    IVDSGPrinter * This,
    /* [in] */ int NewIndent);


void __RPC_STUB IVDSGPrinter_SetIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_IncrIndent_Proxy(
    IVDSGPrinter * This,
    /* [in] */ int delta);


void __RPC_STUB IVDSGPrinter_IncrIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_DecrIndent_Proxy(
    IVDSGPrinter * This,
    /* [in] */ int delta);


void __RPC_STUB IVDSGPrinter_DecrIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_UnIndent_Proxy(
    IVDSGPrinter * This);


void __RPC_STUB IVDSGPrinter_UnIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_RestoreIndent_Proxy(
    IVDSGPrinter * This);


void __RPC_STUB IVDSGPrinter_RestoreIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_ResetIndent_Proxy(
    IVDSGPrinter * This);


void __RPC_STUB IVDSGPrinter_ResetIndent_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_Write_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szText);


void __RPC_STUB IVDSGPrinter_Write_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_StartLine_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szText);


void __RPC_STUB IVDSGPrinter_StartLine_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_EndLine_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szText);


void __RPC_STUB IVDSGPrinter_EndLine_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_WriteLine_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szText);


void __RPC_STUB IVDSGPrinter_WriteLine_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_WriteCommentLine_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szText);


void __RPC_STUB IVDSGPrinter_WriteCommentLine_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_WriteCommentBanner_Proxy(
    IVDSGPrinter * This,
    /* [in] */ LPCTSTR szUID,
    /* [in] */ LPCTSTR szText);


void __RPC_STUB IVDSGPrinter_WriteCommentBanner_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_printVdsgText_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMText *pTextNode);


void __RPC_STUB IVDSGPrinter_printVdsgText_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_printVdsgCData_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMCDATASection *pCDataNode);


void __RPC_STUB IVDSGPrinter_printVdsgCData_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_printVdsgVdsgTag_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode);


void __RPC_STUB IVDSGPrinter_printVdsgVdsgTag_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_printVdsgFileTag_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode);


void __RPC_STUB IVDSGPrinter_printVdsgFileTag_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_printVdsgUserTag_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode);


void __RPC_STUB IVDSGPrinter_printVdsgUserTag_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_printChildren_Proxy(
    IVDSGPrinter * This,
    /* [in] */ IXMLDOMElement *pElemNode);


void __RPC_STUB IVDSGPrinter_printChildren_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_HasUserCode_Proxy(
    IVDSGPrinter * This,
    LPCTSTR szUID);


void __RPC_STUB IVDSGPrinter_HasUserCode_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


HRESULT STDMETHODCALLTYPE IVDSGPrinter_DeleteUserCode_Proxy(
    IVDSGPrinter * This,
    LPCTSTR szUID);


void __RPC_STUB IVDSGPrinter_DeleteUserCode_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);



#endif 	/* __IVDSGPrinter_INTERFACE_DEFINED__ */


#ifndef __IVDSGDocument_INTERFACE_DEFINED__
#define __IVDSGDocument_INTERFACE_DEFINED__

/* interface IVDSGDocument */
/* [unique][helpstring][nonextensible][dual][uuid][object] */


EXTERN_C const IID IID_IVDSGDocument;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("45C49022-10F5-4c8e-87AD-9F5535EB2B02")
    IVDSGDocument : public IDispatch
    {
    public:
        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE Load(
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE LoadXml(
            /* [in] */ BSTR document) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE Save(
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][propput][id] */ HRESULT STDMETHODCALLTYPE put_Check(
            /* [in] */ VARIANT_BOOL value) = 0;

        virtual /* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE get_DOMDocument(
            /* [retval][out] */ IXMLDOMDocument **ppDoc) = 0;

        virtual /* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE get_VDSGRoot(
            /* [retval][out] */ IXMLDOMElement **ppRoot) = 0;

        virtual /* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE get_PathName(
            /* [retval][out] */ BSTR *pPath) = 0;

        virtual /* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE get_FileCount(
            /* [retval][out] */ long *pNumFiles) = 0;

        virtual /* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE get_FileElement(
            /* [in] */ long index,
            /* [retval][out] */ IXMLDOMElement **ppElem) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE FindPrefixedNode(
            /* [in] */ IXMLDOMNodeList *pNodeList,
            /* [in] */ BSTR prefix,
            /* [in] */ BSTR name,
            /* [out] */ IXMLDOMNode **ppNode,
            /* [out] */ long *pPos) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE FindNode(
            /* [in] */ IXMLDOMNodeList *pNodeList,
            /* [in] */ BSTR name,
            /* [out] */ IXMLDOMNode **ppNode,
            /* [out] */ long *pPos) = 0;

    };

#else 	/* C style interface */

    typedef struct IVDSGDocumentVtbl
    {
        BEGIN_INTERFACE

        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
            IVDSGDocument * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
            IVDSGDocument * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
            IVDSGDocument * This);

        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )(
            IVDSGDocument * This,
            /* [out] */ UINT *pctinfo);

        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )(
            IVDSGDocument * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);

        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )(
            IVDSGDocument * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )(
            IVDSGDocument * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *Load )(
            IVDSGDocument * This,
            /* [in] */ BSTR path);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *LoadXml )(
            IVDSGDocument * This,
            /* [in] */ BSTR document);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *Save )(
            IVDSGDocument * This,
            /* [in] */ BSTR path);

        /* [helpstring][propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Check )(
            IVDSGDocument * This,
            /* [in] */ VARIANT_BOOL value);

        /* [helpstring][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_DOMDocument )(
            IVDSGDocument * This,
            /* [retval][out] */ IXMLDOMDocument **ppDoc);

        /* [helpstring][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_VDSGRoot )(
            IVDSGDocument * This,
            /* [retval][out] */ IXMLDOMElement **ppRoot);

        /* [helpstring][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_PathName )(
            IVDSGDocument * This,
            /* [retval][out] */ BSTR *pPath);

        /* [helpstring][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_FileCount )(
            IVDSGDocument * This,
            /* [retval][out] */ long *pNumFiles);

        /* [helpstring][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_FileElement )(
            IVDSGDocument * This,
            /* [in] */ long index,
            /* [retval][out] */ IXMLDOMElement **ppElem);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *FindPrefixedNode )(
            IVDSGDocument * This,
            /* [in] */ IXMLDOMNodeList *pNodeList,
            /* [in] */ BSTR prefix,
            /* [in] */ BSTR name,
            /* [out] */ IXMLDOMNode **ppNode,
            /* [out] */ long *pPos);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *FindNode )(
            IVDSGDocument * This,
            /* [in] */ IXMLDOMNodeList *pNodeList,
            /* [in] */ BSTR name,
            /* [out] */ IXMLDOMNode **ppNode,
            /* [out] */ long *pPos);

        END_INTERFACE
    } IVDSGDocumentVtbl;

    interface IVDSGDocument
    {
        CONST_VTBL struct IVDSGDocumentVtbl *lpVtbl;
    };



#ifdef COBJMACROS


#define IVDSGDocument_QueryInterface(This,riid,ppvObject)	\
    (This)->lpVtbl -> QueryInterface(This,riid,ppvObject)

#define IVDSGDocument_AddRef(This)	\
    (This)->lpVtbl -> AddRef(This)

#define IVDSGDocument_Release(This)	\
    (This)->lpVtbl -> Release(This)


#define IVDSGDocument_GetTypeInfoCount(This,pctinfo)	\
    (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo)

#define IVDSGDocument_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo)

#define IVDSGDocument_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)

#define IVDSGDocument_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)


#define IVDSGDocument_Load(This,path)	\
    (This)->lpVtbl -> Load(This,path)

#define IVDSGDocument_LoadXml(This,document)	\
    (This)->lpVtbl -> LoadXml(This,document)

#define IVDSGDocument_Save(This,path)	\
    (This)->lpVtbl -> Save(This,path)

#define IVDSGDocument_put_Check(This,value)	\
    (This)->lpVtbl -> put_Check(This,value)

#define IVDSGDocument_get_DOMDocument(This,ppDoc)	\
    (This)->lpVtbl -> get_DOMDocument(This,ppDoc)

#define IVDSGDocument_get_VDSGRoot(This,ppRoot)	\
    (This)->lpVtbl -> get_VDSGRoot(This,ppRoot)

#define IVDSGDocument_get_PathName(This,pPath)	\
    (This)->lpVtbl -> get_PathName(This,pPath)

#define IVDSGDocument_get_FileCount(This,pNumFiles)	\
    (This)->lpVtbl -> get_FileCount(This,pNumFiles)

#define IVDSGDocument_get_FileElement(This,index,ppElem)	\
    (This)->lpVtbl -> get_FileElement(This,index,ppElem)

#define IVDSGDocument_FindPrefixedNode(This,pNodeList,prefix,name,ppNode,pPos)	\
    (This)->lpVtbl -> FindPrefixedNode(This,pNodeList,prefix,name,ppNode,pPos)

#define IVDSGDocument_FindNode(This,pNodeList,name,ppNode,pPos)	\
    (This)->lpVtbl -> FindNode(This,pNodeList,name,ppNode,pPos)

#endif /* COBJMACROS */


#endif 	/* C style interface */



/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_Load_Proxy(
    IVDSGDocument * This,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGDocument_Load_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_LoadXml_Proxy(
    IVDSGDocument * This,
    /* [in] */ BSTR document);


void __RPC_STUB IVDSGDocument_LoadXml_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_Save_Proxy(
    IVDSGDocument * This,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGDocument_Save_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propput][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_put_Check_Proxy(
    IVDSGDocument * This,
    /* [in] */ VARIANT_BOOL value);


void __RPC_STUB IVDSGDocument_put_Check_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_get_DOMDocument_Proxy(
    IVDSGDocument * This,
    /* [retval][out] */ IXMLDOMDocument **ppDoc);


void __RPC_STUB IVDSGDocument_get_DOMDocument_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_get_VDSGRoot_Proxy(
    IVDSGDocument * This,
    /* [retval][out] */ IXMLDOMElement **ppRoot);


void __RPC_STUB IVDSGDocument_get_VDSGRoot_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_get_PathName_Proxy(
    IVDSGDocument * This,
    /* [retval][out] */ BSTR *pPath);


void __RPC_STUB IVDSGDocument_get_PathName_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_get_FileCount_Proxy(
    IVDSGDocument * This,
    /* [retval][out] */ long *pNumFiles);


void __RPC_STUB IVDSGDocument_get_FileCount_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_get_FileElement_Proxy(
    IVDSGDocument * This,
    /* [in] */ long index,
    /* [retval][out] */ IXMLDOMElement **ppElem);


void __RPC_STUB IVDSGDocument_get_FileElement_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_FindPrefixedNode_Proxy(
    IVDSGDocument * This,
    /* [in] */ IXMLDOMNodeList *pNodeList,
    /* [in] */ BSTR prefix,
    /* [in] */ BSTR name,
    /* [out] */ IXMLDOMNode **ppNode,
    /* [out] */ long *pPos);


void __RPC_STUB IVDSGDocument_FindPrefixedNode_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGDocument_FindNode_Proxy(
    IVDSGDocument * This,
    /* [in] */ IXMLDOMNodeList *pNodeList,
    /* [in] */ BSTR name,
    /* [out] */ IXMLDOMNode **ppNode,
    /* [out] */ long *pPos);


void __RPC_STUB IVDSGDocument_FindNode_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);



#endif 	/* __IVDSGDocument_INTERFACE_DEFINED__ */


#ifndef __IVDSGApp_INTERFACE_DEFINED__
#define __IVDSGApp_INTERFACE_DEFINED__

/* interface IVDSGApp */
/* [unique][helpstring][nonextensible][dual][uuid][object] */


EXTERN_C const IID IID_IVDSGApp;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("3DCA6F43-2407-44cf-A048-CABD9F042151")
    IVDSGApp : public IDispatch
    {
    public:
        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE LoadTemplateDoc(
            /* [out] */ IVDSGDocument **ppDoc,
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE LoadTemplateStr(
            /* [out] */ IVDSGDocument **ppDoc,
            /* [in] */ BSTR document) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE SaveTemplateDoc(
            /* [in] */ IVDSGDocument *pDoc,
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE LoadXmlDoc(
            /* [out] */ IXMLDOMDocument **ppDoc,
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE LoadXmlStr(
            /* [out] */ IXMLDOMDocument **ppDoc,
            /* [in] */ BSTR document) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE SaveXmlDoc(
            /* [in] */ IXMLDOMDocument *pDoc,
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE AttachPrinter(
            /* [in] */ IDispatch *pAppPrinter) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE DetachPrinter(
            /* [in] */ IDispatch *pAppPrinter) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE PrintElement(
            /* [in] */ IXMLDOMElement *pElem) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE PrintFileElement(
            /* [in] */ IXMLDOMElement *pElem,
            /* [in] */ BSTR path) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE PrintFile(
            /* [in] */ BSTR path) = 0;

    };

#else 	/* C style interface */

    typedef struct IVDSGAppVtbl
    {
        BEGIN_INTERFACE

        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
            IVDSGApp * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
            IVDSGApp * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
            IVDSGApp * This);

        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )(
            IVDSGApp * This,
            /* [out] */ UINT *pctinfo);

        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )(
            IVDSGApp * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);

        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )(
            IVDSGApp * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )(
            IVDSGApp * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *LoadTemplateDoc )(
            IVDSGApp * This,
            /* [out] */ IVDSGDocument **ppDoc,
            /* [in] */ BSTR path);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *LoadTemplateStr )(
            IVDSGApp * This,
            /* [out] */ IVDSGDocument **ppDoc,
            /* [in] */ BSTR document);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *SaveTemplateDoc )(
            IVDSGApp * This,
            /* [in] */ IVDSGDocument *pDoc,
            /* [in] */ BSTR path);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *LoadXmlDoc )(
            IVDSGApp * This,
            /* [out] */ IXMLDOMDocument **ppDoc,
            /* [in] */ BSTR path);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *LoadXmlStr )(
            IVDSGApp * This,
            /* [out] */ IXMLDOMDocument **ppDoc,
            /* [in] */ BSTR document);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *SaveXmlDoc )(
            IVDSGApp * This,
            /* [in] */ IXMLDOMDocument *pDoc,
            /* [in] */ BSTR path);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *AttachPrinter )(
            IVDSGApp * This,
            /* [in] */ IDispatch *pAppPrinter);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *DetachPrinter )(
            IVDSGApp * This,
            /* [in] */ IDispatch *pAppPrinter);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *PrintElement )(
            IVDSGApp * This,
            /* [in] */ IXMLDOMElement *pElem);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *PrintFileElement )(
            IVDSGApp * This,
            /* [in] */ IXMLDOMElement *pElem,
            /* [in] */ BSTR path);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *PrintFile )(
            IVDSGApp * This,
            /* [in] */ BSTR path);

        END_INTERFACE
    } IVDSGAppVtbl;

    interface IVDSGApp
    {
        CONST_VTBL struct IVDSGAppVtbl *lpVtbl;
    };



#ifdef COBJMACROS


#define IVDSGApp_QueryInterface(This,riid,ppvObject)	\
    (This)->lpVtbl -> QueryInterface(This,riid,ppvObject)

#define IVDSGApp_AddRef(This)	\
    (This)->lpVtbl -> AddRef(This)

#define IVDSGApp_Release(This)	\
    (This)->lpVtbl -> Release(This)


#define IVDSGApp_GetTypeInfoCount(This,pctinfo)	\
    (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo)

#define IVDSGApp_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo)

#define IVDSGApp_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)

#define IVDSGApp_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)


#define IVDSGApp_LoadTemplateDoc(This,ppDoc,path)	\
    (This)->lpVtbl -> LoadTemplateDoc(This,ppDoc,path)

#define IVDSGApp_LoadTemplateStr(This,ppDoc,document)	\
    (This)->lpVtbl -> LoadTemplateStr(This,ppDoc,document)

#define IVDSGApp_SaveTemplateDoc(This,pDoc,path)	\
    (This)->lpVtbl -> SaveTemplateDoc(This,pDoc,path)

#define IVDSGApp_LoadXmlDoc(This,ppDoc,path)	\
    (This)->lpVtbl -> LoadXmlDoc(This,ppDoc,path)

#define IVDSGApp_LoadXmlStr(This,ppDoc,document)	\
    (This)->lpVtbl -> LoadXmlStr(This,ppDoc,document)

#define IVDSGApp_SaveXmlDoc(This,pDoc,path)	\
    (This)->lpVtbl -> SaveXmlDoc(This,pDoc,path)

#define IVDSGApp_AttachPrinter(This,pAppPrinter)	\
    (This)->lpVtbl -> AttachPrinter(This,pAppPrinter)

#define IVDSGApp_DetachPrinter(This,pAppPrinter)	\
    (This)->lpVtbl -> DetachPrinter(This,pAppPrinter)

#define IVDSGApp_PrintElement(This,pElem)	\
    (This)->lpVtbl -> PrintElement(This,pElem)

#define IVDSGApp_PrintFileElement(This,pElem,path)	\
    (This)->lpVtbl -> PrintFileElement(This,pElem,path)

#define IVDSGApp_PrintFile(This,path)	\
    (This)->lpVtbl -> PrintFile(This,path)

#endif /* COBJMACROS */


#endif 	/* C style interface */



/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_LoadTemplateDoc_Proxy(
    IVDSGApp * This,
    /* [out] */ IVDSGDocument **ppDoc,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGApp_LoadTemplateDoc_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_LoadTemplateStr_Proxy(
    IVDSGApp * This,
    /* [out] */ IVDSGDocument **ppDoc,
    /* [in] */ BSTR document);


void __RPC_STUB IVDSGApp_LoadTemplateStr_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_SaveTemplateDoc_Proxy(
    IVDSGApp * This,
    /* [in] */ IVDSGDocument *pDoc,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGApp_SaveTemplateDoc_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_LoadXmlDoc_Proxy(
    IVDSGApp * This,
    /* [out] */ IXMLDOMDocument **ppDoc,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGApp_LoadXmlDoc_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_LoadXmlStr_Proxy(
    IVDSGApp * This,
    /* [out] */ IXMLDOMDocument **ppDoc,
    /* [in] */ BSTR document);


void __RPC_STUB IVDSGApp_LoadXmlStr_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_SaveXmlDoc_Proxy(
    IVDSGApp * This,
    /* [in] */ IXMLDOMDocument *pDoc,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGApp_SaveXmlDoc_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_AttachPrinter_Proxy(
    IVDSGApp * This,
    /* [in] */ IDispatch *pAppPrinter);


void __RPC_STUB IVDSGApp_AttachPrinter_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_DetachPrinter_Proxy(
    IVDSGApp * This,
    /* [in] */ IDispatch *pAppPrinter);


void __RPC_STUB IVDSGApp_DetachPrinter_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_PrintElement_Proxy(
    IVDSGApp * This,
    /* [in] */ IXMLDOMElement *pElem);


void __RPC_STUB IVDSGApp_PrintElement_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_PrintFileElement_Proxy(
    IVDSGApp * This,
    /* [in] */ IXMLDOMElement *pElem,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGApp_PrintFileElement_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSGApp_PrintFile_Proxy(
    IVDSGApp * This,
    /* [in] */ BSTR path);


void __RPC_STUB IVDSGApp_PrintFile_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);



#endif 	/* __IVDSGApp_INTERFACE_DEFINED__ */


#ifndef __IVDSG_INTERFACE_DEFINED__
#define __IVDSG_INTERFACE_DEFINED__

/* interface IVDSG */
/* [unique][helpstring][nonextensible][dual][uuid][object] */


EXTERN_C const IID IID_IVDSG;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("0BEB4437-B750-4D48-B89B-37967E4614D8")
    IVDSG : public IDispatch
    {
    public:
        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE Application(
            /* [out] */ IVDSGApp **ppApp) = 0;

        virtual /* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE get_ErrorMsg(
            /* [retval][out] */ BSTR *pMsg) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE GetVersion(
            /* [out] */ long *pVerNum,
            /* [out] */ long *pRelNum,
            /* [out] */ long *pUpdateNum,
            /* [out] */ long *pBuildNum) = 0;

    };

#else 	/* C style interface */

    typedef struct IVDSGVtbl
    {
        BEGIN_INTERFACE

        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
            IVDSG * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
            IVDSG * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
            IVDSG * This);

        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )(
            IVDSG * This,
            /* [out] */ UINT *pctinfo);

        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )(
            IVDSG * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);

        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )(
            IVDSG * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )(
            IVDSG * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *Application )(
            IVDSG * This,
            /* [out] */ IVDSGApp **ppApp);

        /* [helpstring][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ErrorMsg )(
            IVDSG * This,
            /* [retval][out] */ BSTR *pMsg);

        /* [helpstring][id] */ HRESULT ( STDMETHODCALLTYPE *GetVersion )(
            IVDSG * This,
            /* [out] */ long *pVerNum,
            /* [out] */ long *pRelNum,
            /* [out] */ long *pUpdateNum,
            /* [out] */ long *pBuildNum);

        END_INTERFACE
    } IVDSGVtbl;

    interface IVDSG
    {
        CONST_VTBL struct IVDSGVtbl *lpVtbl;
    };



#ifdef COBJMACROS


#define IVDSG_QueryInterface(This,riid,ppvObject)	\
    (This)->lpVtbl -> QueryInterface(This,riid,ppvObject)

#define IVDSG_AddRef(This)	\
    (This)->lpVtbl -> AddRef(This)

#define IVDSG_Release(This)	\
    (This)->lpVtbl -> Release(This)


#define IVDSG_GetTypeInfoCount(This,pctinfo)	\
    (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo)

#define IVDSG_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo)

#define IVDSG_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)

#define IVDSG_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)


#define IVDSG_Application(This,ppApp)	\
    (This)->lpVtbl -> Application(This,ppApp)

#define IVDSG_get_ErrorMsg(This,pMsg)	\
    (This)->lpVtbl -> get_ErrorMsg(This,pMsg)

#define IVDSG_GetVersion(This,pVerNum,pRelNum,pUpdateNum,pBuildNum)	\
    (This)->lpVtbl -> GetVersion(This,pVerNum,pRelNum,pUpdateNum,pBuildNum)

#endif /* COBJMACROS */


#endif 	/* C style interface */



/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSG_Application_Proxy(
    IVDSG * This,
    /* [out] */ IVDSGApp **ppApp);


void __RPC_STUB IVDSG_Application_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][propget][id] */ HRESULT STDMETHODCALLTYPE IVDSG_get_ErrorMsg_Proxy(
    IVDSG * This,
    /* [retval][out] */ BSTR *pMsg);


void __RPC_STUB IVDSG_get_ErrorMsg_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [helpstring][id] */ HRESULT STDMETHODCALLTYPE IVDSG_GetVersion_Proxy(
    IVDSG * This,
    /* [out] */ long *pVerNum,
    /* [out] */ long *pRelNum,
    /* [out] */ long *pUpdateNum,
    /* [out] */ long *pBuildNum);


void __RPC_STUB IVDSG_GetVersion_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);



#endif 	/* __IVDSG_INTERFACE_DEFINED__ */



#ifndef __VDSGComLib_LIBRARY_DEFINED__
#define __VDSGComLib_LIBRARY_DEFINED__

/* library VDSGComLib */
/* [helpstring][version][uuid] */


EXTERN_C const IID LIBID_VDSGComLib;

EXTERN_C const CLSID CLSID_VDSG;

#ifdef __cplusplus

class DECLSPEC_UUID("AFCA1AA5-B871-45C9-83CC-66B167C10070")
VDSG;
#endif
#endif /* __VDSGComLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  BSTR_UserSize(     unsigned long *, unsigned long            , BSTR * );
unsigned char * __RPC_USER  BSTR_UserMarshal(  unsigned long *, unsigned char *, BSTR * );
unsigned char * __RPC_USER  BSTR_UserUnmarshal(unsigned long *, unsigned char *, BSTR * );
void                      __RPC_USER  BSTR_UserFree(     unsigned long *, BSTR * );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif
