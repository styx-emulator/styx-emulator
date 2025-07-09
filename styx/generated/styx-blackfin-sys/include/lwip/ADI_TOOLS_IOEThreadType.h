/* =============================================================================
 *
 *  Description: This is a C++ to C Thread Header file for Thread ADI_TOOLS_IOEThreadType
 *
 * -----------------------------------------------------------------------------
 *  Comments:
 *
 * ===========================================================================*/

#ifndef _ADI_TOOLS_IOEThreadType_H_
#define _ADI_TOOLS_IOEThreadType_H_

#include "VDK.h"

#ifdef __ECC__ /* for C/C++ access */
#ifdef __cplusplus
extern "C" void ADI_TOOLS_IOEThreadType_InitFunction(void**, VDK::Thread::ThreadCreationBlock *);
#else
extern "C" void ADI_TOOLS_IOEThreadType_InitFunction(void**, VDK_ThreadCreationBlock *);
#endif
extern "C" void ADI_TOOLS_IOEThreadType_DestroyFunction(void**);
extern "C" int  ADI_TOOLS_IOEThreadType_ErrorFunction(void**);
extern "C" void ADI_TOOLS_IOEThreadType_RunFunction(void**);
#endif /* __ECC__ */

#ifdef __cplusplus
#include <new>

class ADI_TOOLS_IOEThreadType_Wrapper : public VDK::Thread
{
public:
    ADI_TOOLS_IOEThreadType_Wrapper(VDK::ThreadCreationBlock &t)
        : VDK::Thread(t)
    {
      /* Save the user data pointer to m_DataPtr. CVDKOE
         implementation uses this to pass user defiend function
         address and its arguments.
      */
      m_DataPtr = t.user_data_ptr;
      ADI_TOOLS_IOEThreadType_InitFunction(&m_DataPtr, &t);
   }

    ~ADI_TOOLS_IOEThreadType_Wrapper()
    { ADI_TOOLS_IOEThreadType_DestroyFunction(&m_DataPtr); }

    int ErrorHandler()
    {
      return ADI_TOOLS_IOEThreadType_ErrorFunction(&m_DataPtr);
     }

    void Run()
    { ADI_TOOLS_IOEThreadType_RunFunction(&m_DataPtr); }

    static VDK::Thread* Create(VDK::Thread::ThreadCreationBlock &t)
    { return new (t.template_id) ADI_TOOLS_IOEThreadType_Wrapper(t); }
};

#endif /* __cplusplus */
#endif /* _ADI_TOOLS_IOEThreadType_H_ */

/* ========================================================================== */
