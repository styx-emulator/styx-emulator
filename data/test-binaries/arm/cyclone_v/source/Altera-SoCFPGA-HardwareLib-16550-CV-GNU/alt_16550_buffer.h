/*****************************************************************************
*
* Copyright 2013 Altera Corporation. All Rights Reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software without
* specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*****************************************************************************/

/*
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-GNU/alt_16550_buffer.h#1 $
 */

#ifndef ___ALT_16550_BUFFER_H___
#define ___ALT_16550_BUFFER_H___

#include "alt_16550_uart.h"
#include "alt_interrupt.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
 * This preprocessor definition determines the size of the system memory used
 * to buffer data coming in from the UART FIFO. This buffer constantly reads
 * data out of the UART FIFO into a circular buffer, which can then be read
 * back to the caller as a buffer or a buffer with a new line character. This
 * allows users to process UART data as a statement instead of raw data.
 *
 * To specify another RX system buffer size, define
 * ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE in your Makefile to be another
 * size.
 */
#ifndef ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE
#define ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE 4096
#endif

/*!
 * This preprocessor definition determines the size of the system memory used
 * to buffer data going out to the UART FIFO. This buffer constantly writes
 * data into of the UART FIFO from a circular buffer.
 *
 * To specify another RX system buffer size, define
 * ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE in your Makefile to be another
 * size.
 */
#ifndef ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE
#define ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE 4096
#endif

/*!
 * This preprocessor definition causes extra synchronizations to be used when
 * running on SMP systems.
 *
 * To enable SMP synchronizations, define ALT_16550_BUFFER_ENABLE_SMP=1 in your
 * Makefile.
 */
#ifndef ALT_16550_BUFFER_ENABLE_SMP
#define ALT_16550_BUFFER_ENABLE_SMP 0
#endif

/*!
 * This structure is used to represent a UART buffer system.
 */
typedef struct ALT_16550_BUFFER_s
{
    ALT_16550_HANDLE_t * handle; /*!< The UART handle to associate with. */
    volatile ALT_STATUS_CODE status; /*!< Interrupt status to be reported back to
                                          usermode. */

    uint32_t fifo_size_rx;       /*!< Cache for the UART RX FIFO size. */
    uint32_t fifo_size_tx;       /*!< Cache for the UART TX FIFO size. */

#if ALT_16550_BUFFER_ENABLE_SMP
    volatile bool isr_rx;        /*!< RX specific synchronization for SMP systems. */
    volatile bool isr_tx;        /*!< TX specific synchronization for SMP systems. */
#endif

    /*! RX circular buffer memory. */
    char     rx_buffer[ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE];
    uint16_t rx_start;           /*!< RX data start position in the RX circular buffer. */
    uint16_t rx_level;           /*!< RX data item count in the RX circular buffer. */
    uint16_t rx_nl_count;        /*!< Newline ('\n') count in the RX circular buffer. */

    /*! TX circular buffer memory. */
    char     tx_buffer[ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE];
    uint16_t tx_start;           /*!< TX data start position in the TX circular buffer. */
    uint16_t tx_level;           /*!< TX data item count in the TXcircular buffer. */

    bool echo_enable;            /*!< Instructs the buffer to echo back characters read. */
    bool echo_inject_lf;         /*!< Instructs the buffer to echo an additional
                                      newline ('\n') when a carriage return is
                                      encountered. */
    char echo_char;              /*!< The character to echo. NULL specifies
                                      that the character read should be echoed.
                                      Otherwise the character specified will be
                                      echoed. */

}
ALT_16550_BUFFER_t;

/*! Definitions of status codes returned by the UART Buffer. */

/*! Overrun Error detected in the RX FIFO. */
#define ALT_E_UART_OE     (-1000)

/*! Parity error detected in the RX FIFO. */
#define ALT_E_UART_PE     (-1001)

/*! Framing Error detected in the RX FIFO. */
#define ALT_E_UART_FE     (-1002)

/*! Receiver FIFO Error detected in the RX FIFO. */
#define ALT_E_UART_RFE    (-1003)

/*!
 * Initializes the buffer for use. This should be done after the interrupt
 * system and UART in use has been initialized.
 *
 * \param       buffer
 *              [out] The UART buffer data structure.
 *
 * \param       handle
 *              Handle the the UART to be associated with the UART buffer.
 *
 * \param       int_id
 *              The interrupt identifier associated with the UART.
 *
 * \param       int_target
 *              The CPU targets for the given interrupt. If unsure, specify
 *              0. This will target all CPUs by default.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_init(ALT_16550_BUFFER_t * buffer,
                                      ALT_16550_HANDLE_t * handle,
                                      ALT_INT_INTERRUPT_t int_id, uint32_t int_target);

/*!
 * Uninitializes the buffer.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       int_id
 *              The interrupt identifier associated with the UART.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_uninit(ALT_16550_BUFFER_t * buffer,
                                        ALT_INT_INTERRUPT_t int_id);


/*!
 * Reports the size of the RX buffer memory.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       size
 *              [out] The size of the RX buffer memory.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_size_rx(ALT_16550_BUFFER_t * buffer, uint32_t * size);

/*!
 * Reports the size of the TX buffer memory.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       size
 *              [out] The size of the TX buffer memory.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_size_tx(ALT_16550_BUFFER_t * buffer, uint32_t * size);

/*!
 * Reports the level or amount of data in the RX buffer memory.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       size
 *              [out] The level in the RX buffer memory.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_level_rx(ALT_16550_BUFFER_t * buffer, uint32_t * level);

/*!
 * Reports the level or amount of data in the TX buffer memory.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       size
 *              [out] The level in the TX buffer memory.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_level_tx(ALT_16550_BUFFER_t * buffer, uint32_t * level);

/*!
 * Reads raw data out of the RX buffer memory.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       data
 *              [out] Buffer used to store the data copied out.
 *
 * \param       size
 *              The most amount of the data that will be copied into buffer
 *              provided.
 *
 * \param       size_read
 *              [out] The amount of data copied out of the circular buffer.
 *              This can be less than [size] if there are fewer items in the
 *              circular buffer than the size of the data block provided.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 * \retval      ALT_E_UART_OE   RX FIFO Overflow Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_PE   RX FIFO Parity Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_FE   RX FIFO Framing Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_RFE  RX FIFO Receiver FIFO Error asynchronously
 *                              reported by the hardware via the ISR. This is a
 *                              fatal and unrecoverable error.
 */
ALT_STATUS_CODE alt_16550_buffer_read_raw(ALT_16550_BUFFER_t * buffer,
                                          char * data,
                                          size_t size,
                                          size_t * size_read);

/*!
 * Reads data out of the RX buffer memory up to the next newline ('\n') data.
 * This will typically include carriage return ('\r') that comes before.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       data
 *              [out] Buffer used to store the data copied out.
 *
 * \param       size
 *              The most amount of the data that will be copied into buffer
 *              provided.
 *
 * \param       size_read
 *              [out] The amount of data copied out of the circular buffer.
 *              This can be less than [size] if there are fewer items in the
 *              circular buffer than the size of the data block provided. If
 *              0, then there is no new line character in the RX buffer.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 * \retval      ALT_E_BUF_OVF   The buffer provided does not contain enough
 *                              space for the next batch of data.
 * \retval      ALT_E_UART_OE   RX FIFO Overflow Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_PE   RX FIFO Parity Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_FE   RX FIFO Framing Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_RFE  RX FIFO Receiver FIFO Error asynchronously
 *                              reported by the hardware via the ISR. This is a
 *                              fatal and unrecoverable error.
 */
ALT_STATUS_CODE alt_16550_buffer_read_line(ALT_16550_BUFFER_t * buffer,
                                           char * data,
                                           size_t size,
                                           size_t * size_read);

/*!
 * Writes raw data into the TX buffer memory.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       data
 *              Buffer of data to write to the circular buffer.
 *
 * \param       size
 *              The most amount of the data that will be copied into buffer
 *              provided.
 *
 * \param       size_written
 *              [out] The amount of data copied in to the circular buffer. This
 *              can be less than [size] if there are fewer space available in
 *              the circular buffer than the size of the data block provided.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 * \retval      ALT_E_UART_OE   RX FIFO Overflow Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_PE   RX FIFO Parity Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_FE   RX FIFO Framing Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_RFE  RX FIFO Receiver FIFO Error asynchronously
 *                              reported by the hardware via the ISR. This is a
 *                              fatal and unrecoverable error.
 */
ALT_STATUS_CODE alt_16550_buffer_write_raw(ALT_16550_BUFFER_t * buffer,
                                           const char * data,
                                           size_t size,
                                           size_t * size_written);

/*!
 * Writes data to the TX buffer memory, translating all LF into CRLF sequences
 * ('\n' into '\r\n').
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       data
 *              Buffer of data to write to the circular buffer.
 *
 * \param       size
 *              The most amount of the data that will be copied into buffer
 *              provided. If 0, the length of data as calculated by strlen()
 *              will be used.
 *
 * \param       size_written
 *              [out] The amount of data copied in to the circular buffer. This
 *              can be less than [size] if there are fewer space available in
 *              the circular buffer than the size of the data block provided.
 *              This value does not take into the account of the CR injections.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 * \retval      ALT_E_UART_OE   RX FIFO Overflow Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_PE   RX FIFO Parity Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_FE   RX FIFO Framing Error asynchronously reported
 *                              by the hardware via the ISR. This is a fatal
 *                              and unrecoverable error.
 * \retval      ALT_E_UART_RFE  RX FIFO Receiver FIFO Error asynchronously
 *                              reported by the hardware via the ISR. This is a
 *                              fatal and unrecoverable error.
 */
ALT_STATUS_CODE alt_16550_buffer_write_line(ALT_16550_BUFFER_t * buffer,
                                            const char * data,
                                            size_t size,
                                            size_t * size_written);

/*!
 * Instructs the buffer to echo back what was input in the RX circular buffer.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \param       inject_lf
 *              Instructs the buffer to inject a line feed ('\n') character
 *              when a carriage return ('\r') is encountered. This allows for a
 *              more suitably formatted echo output.
 *
 * \param       echo
 *              The character to echo. If 0, the character which was input will
 *              be echoed. Otherwise the character provided will be echoed.
 *              This will allow for passwords to be safely entered while
 *              providing visual feedback.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_echo_enable(ALT_16550_BUFFER_t * buffer,
                                             bool inject_lf,
                                             char echo);

/*!
 * Disables buffer echoing.
 *
 * \param       buffer
 *              The UART buffer data structure.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_buffer_echo_disable(ALT_16550_BUFFER_t * buffer);

#ifdef __cplusplus
}
#endif

#endif /* ___ALT_16550_BUFFER_H___ */
