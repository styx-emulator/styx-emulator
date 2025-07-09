/******************************************************************************
Copyright (c), 2010 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3682 $
$Date: 2010-11-01 16:56:32 -0400 (Mon, 01 Nov 2010) $

Title: ADI STDIO

Description: This is the primary include file STDIO service.

*****************************************************************************/

#ifndef __ADI_STDIO_H__
#define __ADI_STDIO_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  I N C L U D E S   =============*/

/* System Services include */
#include <services/services.h>
#include <drivers/adi_dev.h>

#if defined(_LANGUAGE_C)
/* PRIMIO includes */
#include <device.h>
#include <device_int.h>
/* adi types are only relevant in C code */
#include <adi_types.h>
#endif

/*==============  D E F I N E S  ===============*/

/* Allow this header file to be used in assembly files */
#if defined(_LANGUAGE_C)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* C-specific definitions  */


/*
**
** Enumerations
**
*/

/*
**  Enumerations of stream types supported by STDIO
*/
typedef enum __AdiStdioStreamType
{

    /* Console Input (stdin) stream         */
    ADI_STDIO_STREAM_STDIN = 0U,
    /* Console Output (stdout) stream       */
    ADI_STDIO_STREAM_STDOUT,
    /* Console Error Output (stderr) stream */
    ADI_STDIO_STREAM_STDERR,
    /* stdin, stdout and stderr streams     */
    ADI_STDIO_STREAM_ALL_CONSOLE_IO

} ADI_STDIO_STREAM_TYPE;

/*
**  Enumerations of device types supported by STDIO
*/
typedef enum __AdiStdioDeviceType
{
    /* Reserved device type                 */
    ADI_STDIO_DEVICE_TYPE_RESERVED1  = 0U,
    /* Reserved device type                 */
    ADI_STDIO_DEVICE_TYPE_RESERVED2,
    /* UART Device type                     */
    ADI_STDIO_DEVICE_TYPE_UART,
    /* Maximum number of device types       */
    ADI_STDIO_DEVICE_TYPE_MAX
} ADI_STDIO_DEVICE_TYPE;



/*
** Enumerations of STDIO Return Codes
*/
typedef enum __AdiStdioResult
{
    /* Generic Success                                */
    ADI_STDIO_RESULT_SUCCESS                        = 0U,
    /* Generic Failure                                */
    ADI_STDIO_RESULT_FAILED                         = 1U,
    /* Service not yet initialized */
    ADI_STDIO_RESULT_SERVICE_NOT_INITIALIZED        = (ADI_STDIO_ENUMERATION_START + 0U),
    /* Service is already initialized */
    ADI_STDIO_RESULT_SERVICE_ALREADY_INITIALIZED    = (ADI_STDIO_ENUMERATION_START + 1U),
    /* Memory passsed for requested devices is not sufficient */
    ADI_STDIO_RESULT_INSUFFICIENT_MEMORY            = (ADI_STDIO_ENUMERATION_START + 2U),
    /* The given device handle is invalid             */
    ADI_STDIO_RESULT_INVALID_HANDLE                 = (ADI_STDIO_ENUMERATION_START + 3U),
    /* Given Device type is invalid                   */
    ADI_STDIO_RESULT_INVALID_DEVICE_TYPE            = (ADI_STDIO_ENUMERATION_START + 4U),
    /* Given Device type is not registered with stdio */
    ADI_STDIO_RESULT_DEVICE_NOT_REGISTERED          = (ADI_STDIO_ENUMERATION_START + 5U),
    /* Failed to redirect the given stream            */
    ADI_STDIO_RESULT_REDIRECT_FAILED                = (ADI_STDIO_ENUMERATION_START + 6U),
    /* Failed to create the seaphore                  */
    ADI_STDIO_RESULT_SEMAPHORE_FAILURE              = (ADI_STDIO_ENUMERATION_START + 7U),
    /* Failed to create the mutex                  */
    ADI_STDIO_RESULT_MUTEX_FAILURE                  = (ADI_STDIO_ENUMERATION_START + 8U),
    /* Failed to add entry into LIBIO device table */
    ADI_STDIO_RESULT_DEVTAB_REGISTER_FAILED         = (ADI_STDIO_ENUMERATION_START + 9U),
    /* Command not supported by the given device     */
    ADI_STDIO_RESULT_COMMAND_NOT_SUPPORTED          = (ADI_STDIO_ENUMERATION_START + 10U),
    /* STDIO device/hardware initialization failed    */
    ADI_STDIO_RESULT_DEVICE_FAILED                  = (ADI_STDIO_ENUMERATION_START + 11U),
    /* Give pointer is invalid or pointing to NULL    */
    ADI_STDIO_RESULT_INVALID_POINTER                = (ADI_STDIO_ENUMERATION_START + 12U),
    /* The given function pointer is invalid or pointing to NULL */
    ADI_STDIO_RESULT_INVALID_FUNCTION_POINTER       = (ADI_STDIO_ENUMERATION_START + 13U),
    /* No more STDIO devices available */
    ADI_STDIO_RESULT_NO_STDIO_DEVICES               = (ADI_STDIO_ENUMERATION_START + 14U),
    /* Invalid stream type or Stream type not supported by the selected device */
    ADI_STDIO_RESULT_STREAM_NOT_SUPPORTED           = (ADI_STDIO_ENUMERATION_START + 15U)
} ADI_STDIO_RESULT;


/*
** Enumerations of Parity types for UART
*/
typedef enum __AdiStdiotParityType
{
    ADI_STDIO_PARITY_TYPE_NONE  = 0U,
    ADI_STDIO_PARITY_TYPE_ODD   = 1U,
    ADI_STDIO_PARITY_TYPE_EVEN  = 2U

} ADI_STDIO_PARITY_TYPE;


/*
** Enumerations of STDIO Return Codes
*/
typedef enum __AdiStdioCommand
{
    /* Enable/Disable Unix mode line breaks. true = Enable, false = Disable */
    ADI_STDIO_COMMAND_ENABLE_UNIX_MODE         = (ADI_STDIO_ENUMERATION_START + 0U),
    /* Enalbe/Disable Charecter echo. true = Enable, false = Disable */
    ADI_STDIO_COMMAND_ENABLE_CHAR_ECHO         = (ADI_STDIO_ENUMERATION_START + 1U),
    /* Get the physical device handle */
    ADI_STDIO_COMMAND_GET_DEVICE_HANDLE        = (ADI_STDIO_ENUMERATION_START + 2U),

    /*
    ** UART related configuration commands
    */

    /* Set Parity type (valid argument is one of the prity type from ADI_STDIO_PARITY_TYPE) */
    ADI_STDIO_COMMAND_SET_UART_PARITY_TYPE     = (ADI_STDIO_ENUMERATION_START + 3U),
    /* Set data word length, valid word lengths are 5, 6, 7, 8 */
    ADI_STDIO_COMMAND_SET_UART_WORD_LENGTH     = (ADI_STDIO_ENUMERATION_START + 4U),
    /* Set number of stop bits, valid values are 1 or 2 */
    ADI_STDIO_COMMAND_SET_UART_NUM_STOP_BITS   = (ADI_STDIO_ENUMERATION_START + 5U),
    /* Set the charecter to be used in autobaud mode, valid values are any charecter */
    ADI_STDIO_COMMAND_SET_UART_AUTO_BAUD_CHAR  = (ADI_STDIO_ENUMERATION_START + 6U),
    /* Enable auto baud detection (no command specific arguments) */
    ADI_STDIO_COMMAND_ENABLE_AUTO_BAUD         = (ADI_STDIO_ENUMERATION_START + 7U),
    /* Set the UART baud rate */
    ADI_STDIO_COMMAND_SET_UART_BAUD_RATE       = (ADI_STDIO_ENUMERATION_START + 8U)

} ADI_STDIO_COMMAND;



/*=============  D A T A    T Y P E S   =============*/

/* Handle to STDIO device device */
typedef void* ADI_STDIO_DEVICE_HANDLE;


/*=======  P U B L I C   P R O T O T Y P E S  ========*/
/*            (globally-scoped functions)             */



/*
**  Function: adi_stdio_Init
**
**      Initalizes the STDIO service
**
**  Parameters:
**      hDeviceMgr        - Handle to Device Manager
**      hDMAMgr           - Handle to DMA Manager
**      hDCBMgr           - Handle to DCB Manager
**      hMemPool          - Handle to the memory pool, if NULL is passed
**                          then memory is allocated from system heap
**      phDefaultDevice   - Pointer to the default STDIO device (JTAG)
**
**  Returns:
**      ADI_STDIO_RESULT_SUCCESS
**          - Successfully redirected stream
**      ADI_STDIO_RESULT_INVALID_HANDLE
**          - One or more of the given handles is invalid
**      ADI_STDIO_RESULT_SERVICE_ALREADY_INITIALIZED
**          - STDIO service is already initialized
**      ADI_STDIO_RESULT_MUTEX_FAILURE
**          - Failed to create the required mutex
*/
ADI_STDIO_RESULT  adi_stdio_Init (
    ADI_DEV_MANAGER_HANDLE    const hDeviceMgr,
    ADI_DMA_MANAGER_HANDLE    const hDMAMgr,
    ADI_DCB_HANDLE            const hDcbMgr,
    ADI_STDIO_DEVICE_HANDLE        *phDefaultDevice
);


/*
**  Function: adi_stdio_Terminate
**
**      Terminates the STDIO service
**
**  Parameters:
**      None
**  Returns:
**      ADI_STDIO_RESULT_SUCCESS
**          - Successfully terminated STDIO service
**      ADI_STDIO_RESULT_SERVICE_NOT_INITIALIZED
**          - STDIO service is not initialialized
*/
ADI_STDIO_RESULT adi_stdio_Terminate (
    void
);


/*
**  Function: adi_stdio_OpenDevice
**
**      Opens the given physical device for STDIO
**
**  Parameters:
**      eDeviceType         - STDIO device type (JTAG/UART/NULL..)
**      nPhysicalDevNum     - Physical device number to open
**      phStdioDevice       - Pointer to STDIO device handle.
**
**  Returns:
**     ADI_STDIO_RESULT_SUCCESS
**         - Successfully opened the given device.
**     ADI_STDIO_RESULT_SERVICE_NOT_INITIALIZED
**         - STDIO service is not yet initialized
**     ADI_STDIO_RESULT_INVALID_HANDLE
**         - Handle to the device device is not valid
**     ADI_STDIO_RESULT_INVALID_FUNCTION_POINTER
**         - Invalid function pointer
**     ADI_STDIO_RESULT_NO_STDIO_DEVICES
**         - No free STDIO devices
**     ADI_STDIO_RESULT_DEVICE_FAILED
**         - Failed to open the given physical device
*/
ADI_STDIO_RESULT  adi_stdio_OpenDevice (
    ADI_STDIO_DEVICE_TYPE        eDeviceType,
    uint32_t                     nPhysicalDevNum,
    ADI_STDIO_DEVICE_HANDLE     *phStdioDevice
);



/*
**  Function: adi_stdio_CloseDevice
**
**      Closes the given physical device
**
**  Parameters:
**
**     hStdioDevice      - Handle to the STDIO device device
**
**  Returns:
**     ADI_STDIO_RESULT_SUCCESS
**         - Successfully closed the given device.
**     ADI_STDIO_RESULT_INVALID_HANDLE
**         - Handle to the device device is not valid
**     ADI_STDIO_RESULT_DEVICE_FAILED
**         - Failed to close the given physical device
*/
ADI_STDIO_RESULT adi_stdio_CloseDevice(
    ADI_STDIO_DEVICE_HANDLE     const hStdioDevice
);


/*
**  Function: adi_stdio_ControlDevice
**
**      Sets/Gets the configuration parameters for given physical device
**
**  Parameters:
**      hStdioDevice      - Handle to the STDIO device device
**      nCommandID          - Command ID which needs to be set/get.
**      pValue              - Pointer that holds the value to be set/get
**
**  Returns:
**     ADI_STDIO_RESULT_SUCCESS
**         - Successfully closed the given device.
**     ADI_STDIO_RESULT_INVALID_HANDLE
**         - Handle to the device device is not valid
**     ADI_STDIO_RESULT_DEVICE_FAILED
**         - Device failed to exicute the given command
**     ADI_STDIO_RESULT_COMMAND_NOT_SUPPORTED
**         - Given command is not supported by the device
*/
ADI_STDIO_RESULT adi_stdio_ControlDevice(
    ADI_STDIO_DEVICE_HANDLE          hStdioDevice,
    uint32_t                         nCommandID,
    void                      *const pValue
);



/*
**  Function: adi_stdio_RedirectStream
**
**      Re-directs selected stream to a STDIO device
**
**  Parameters:
**      hStdioDevice  - Handle to STDIO device to which the
**                        stream to be redirected
**      eStreamType     - Stream type to re-direct
**
**  Returns:
**      ADI_STDIO_RESULT_SUCCESS
**          - Successfully redirected stream
**      ADI_STDIO_RESULT_SERVICE_NOT_INITIALIZED
**          - STDIO service is not yet initialized
**      ADI_STDIO_RESULT_INVALID_HANDLE
**          - Given handle is invalid
**      ADI_STDIO_RESULT_STREAM_NOT_SUPPORTED
**          - Invalid stream type or
**            Stream type not supported by the selected device
**      ADI_STDIO_RESULT_REDIRECT_FAILED
**          - Failed to re-direct stream
**      ADI_STDIO_RESULT_DEVICE_FAILED
**          - STDIO device/hardware initialisation failed
**      ADI_STDIO_RESULT_SEMAPHORE_FAILURE
**          - Failed to create semaphore
**      ADI_STDIO_RESULT_DEVTAB_REGISTER_FAILED
**          - Failed to add entry into LIBIO device table entry
*/
ADI_STDIO_RESULT  adi_stdio_RedirectStream (
    ADI_STDIO_DEVICE_HANDLE     hStdioDevice,
    ADI_STDIO_STREAM_TYPE       eStreamType
);


/*
**  Function: adi_stdio_DisableStream
**
**      Disables selected STDIO stream by redirecting the output to
**      the NULL device
**
**  Parameters:
**      eStreamType - Stream type to disable
**
**  Returns:
**      ADI_STDIO_RESULT_SUCCESS
**          - Successfully disabled stream
**      ADI_STDIO_RESULT_SEMAPHORE_FAILURE
**          - Failed to create semaphore
**      ADI_STDIO_RESULT_DEVTAB_REGISTER_FAILED
**          - Failed to add entry into LIBIO device table entry
**      ADI_STDIO_RESULT_SERVICE_NOT_INITIALIZED
**          - Stdio service not initialized
*/
ADI_STDIO_RESULT  adi_stdio_DisableStream (
    ADI_STDIO_STREAM_TYPE   eStreamType
);

/*
**  Function: adi_stdio_RegisterUART
**
**      Registers the UART device with STDIO service.
**
**      This function needs to be called by the application
**      to use UART as STDIO device. This function primarily
**      helps to avoid UART related functions to be linked
**      when it is not called.
**
**      This function can be called any number of times
**      but should be called atleast once. It can just be
**      called only once irrespective of the number of UARTs
**      are being used.
**
**  Parameters:
**      None
**
**  Returns:
**      None
*/
void adi_stdio_RegisterUART (
    void
);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#else /* not _LANGUAGE_C */

/* Assembler-specific */

#endif /* not _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_STDIO_H__ */
