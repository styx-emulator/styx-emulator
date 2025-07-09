/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided
 * that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __USB_SERIAL_PORT_H__
#define __USB_SERIAL_PORT_H__

typedef struct _usb_serial_port_xfer
{
    uint8_t *buffer; /*!< The buffer of data to be transfer.*/
    size_t size;     /*!< The byte count to be transfer. */
} usb_serial_port_xfer_t;

/*! @brief Error codes for the serial port driver. */
typedef enum _usb_serial_port_status
{
    kStatus_USB_SERIAL_PORT_Success = 0,
    kStatus_USB_SERIAL_PORT_TxBusy = 1,
    kStatus_USB_SERIAL_PORT_RxBusy = 2,
    kStatus_USB_SERIAL_PORT_TxIdle = 3,
    kStatus_USB_SERIAL_PORT_RxIdle = 4,
    kStatus_USB_SERIAL_PORT_TxWatermarkTooLarge = 5,
    kStatus_USB_SERIAL_PORT_RxWatermarkTooLarge = 6,
    kStatus_USB_SERIAL_PORT_kStatus_FlagCannotClearManually = 7,
    kStatus_USB_SERIAL_PORT_Error = 8,
    kStatus_USB_SERIAL_PORT_RxRingBufferOverrun = 9,
    kStatus_USB_SERIAL_PORT_RxHardwareOverrun = 10,
    kStatus_USB_SERIAL_PORT_NoiseError = 11,
    kStatus_USB_SERIAL_PORT_FramingError = 12,
    kStatus_USB_SERIAL_PORT_ParityError = 13,
    kStatus_USB_SERIAL_PORT_BaudrateNotSupport = 14,

    kStatus_USB_SERIAL_PORT_Busy = -2,
    kStatus_USB_SERIAL_PORT_InvalidParameter = -1,
} usb_serial_port_status_t;

/*! @brief serial port configuration structure. */
typedef struct _usb_serial_port_config
{
    uint32_t baudRate_Bps; /*!< LPUART baud rate  */
    uint8_t isMsb;         /*!< Data bits order, LSB (default), MSB */
    uint8_t enableTx;      /*!< Enable TX */
    uint8_t enableRx;      /*!< Enable RX */
} usb_serial_port_config_t;

/*! @brief SERIAL_PORT callback function type */
typedef void (*usb_serial_port_callback_t)(void *handle, status_t status, void *userData);

typedef struct _usb_serial_port_callback_struct
{
    usb_serial_port_callback_t callbackFunction; /*!< The callback function for serial port.*/
    void *callbackParam;                         /*!< The callback parameter for serial port. */
} usb_serial_port_callback_struct_t;

typedef struct _usb_serial_port_handle
{
    void *serialPortHandle;
    void *baseReg;
    usb_serial_port_callback_struct_t callback;
    uint8_t instance;
} usb_serial_port_handle_t;

#define USB_SERIAL_PORT_INSTANCE_COUNT (1U)

/*******************************************************************************
 * API
 ******************************************************************************/
/*The function in this head file is just a wrapper , it will call the serial_port, lpserial_port or lpsci corresponding
 * function.*/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Initializes a SERIAL_PORT instance.
 *
 * This function initializes the SERIAL_PORT module with user-defined settings.
 * This example shows how to set up the serial_port_state_t and the
 * serial_port_config_t parameters and how to call the SERIAL_PORT_Configure function.
 *
 *
 * @param base The SERIAL_PORT base point.
 * @param config The user configuration structure of type usb_serial_port_config_t. The user
 *  populates the members of this structure and passes the pointer of this structure
 *  to this function.
 * @param callback callback structure; See the #usb_serial_port_callback_struct_t.
 * @param sourceClockHz SERIAL_PORT clock source frequency in Hz.
 * @param handle SERIAL_PORT handle pointer.
 * @return 0 succeed; Others failed.
 */
usb_serial_port_status_t USB_SerialPortInit(uint8_t instance,
                                            const usb_serial_port_config_t *config,
                                            usb_serial_port_callback_struct_t *callback,
                                            uint32_t sourceClockHz,
                                            usb_serial_port_handle_t *handle);

/*!
 * @brief Transmits a buffer of data using the interrupt method.
 *
 * This function sends data using an interrupt method. This is a non-blocking function, which
 * returns without waiting for all data to be written to the TX register. When
 * all data is written to the TX register in the ISR, the SERIAL_PORT driver calls the callback
 * function and passes @ref kStatus_SERIAL_PORT_TxIdle as status parameter.
 *
 * @note The kStatus_SERIAL_PORT_TxIdle is passed to the upper layer when all data written
 * to TX register, but does not ensure that all the data sent out. So before disabling the TX,
 * check the kSERIAL_PORT_TransmissionCompleteFlag to ensure that the TX is finished.
 *
 * @param base SERIAL_PORT peripheral base address.
 * @param handle SERIAL_PORT handle pointer.
 * @param xfer SERIAL_PORT transfer structure; See the #serial_port_transfer_t.
 * @retval kStatus_Success Successfully starts the data transmission.
 * @retval kStatus_SERIAL_PORT_TxBusy Previous transmission still not finished, data not all written to TX register yet.
 */
usb_serial_port_status_t USB_SerialPortSend(usb_serial_port_handle_t *handle, usb_serial_port_xfer_t *xfer);

/*!
 * @brief Receives data using IRQ.
 *
 * This function receives data using IRQ. This is a non-blocking function, which returns
 * right away. When all data is received, the receive callback function is called.
 *
 * @param base The SERIAL_PORT base point.
 * @param handle SERIAL_PORT handle.
 * @param xfer SERIAL_PORT transfer structure; See the #usb_serial_port_xfer_t.
 * @return kSERIAL_PORT_Succeed succeed, others failed; See the #usb_serial_port_status_t.
 */
usb_serial_port_status_t USB_SerialPortRecv(usb_serial_port_handle_t *handle,
                                            usb_serial_port_xfer_t *xfer,
                                            size_t *receivedBytes);

/*!
 * @brief Deinitializes an SERIAL_PORT instance.
 *
 * This function gates the SERIAL_PORT module clock and sets all register values to reset values.
 *
 * @param base The SERIAL_PORT base point.
 */
usb_serial_port_status_t USB_SerialPortDeinit(usb_serial_port_handle_t *handle);

/*!
 * @brief SERIAL_PORT IRQ handler function.
 *
 * This function process the SERIAL_PORT transmit and receive IRQ requestion.
 *
 * @param base The SERIAL_PORT base point.
 * @param handle SERIAL_PORT handle pointer.
 */
void USB_SerialPortIRQHandler(usb_serial_port_handle_t *handle);

#if defined(__cplusplus)
}
#endif

#endif /* __USB_SERIAL_PORT_H__*/
