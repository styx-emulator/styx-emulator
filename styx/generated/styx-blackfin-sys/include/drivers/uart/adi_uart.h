/*********************************************************************************

Copyright(c) 2004 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_uart.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the primary include file for the UART driver.

*********************************************************************************/

#ifndef __ADI_UART_H__
#define __ADI_UART_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Fixed enumerations and defines

*********************************************************************/




/*********************************************************************

Extensible enumerations and defines

*********************************************************************/


enum {                                                  // Command IDs
    ADI_UART_CMD_START=ADI_UART_ENUMERATION_START,      // 0x40120000
    ADI_UART_CMD_SET_DATA_BITS,                         // set the number of data bits                                  (Value = u16)
    ADI_UART_CMD_SET_STOP_BITS,                         // set the number of stop bits                                  (Value = u16)
    ADI_UART_CMD_SET_PARITY,                            // set the parity to even/odd                                   (even number = even parity, odd number = odd parity)
    ADI_UART_CMD_ENABLE_PARITY,                         // turns parity checking on/off                                 (Value = TRUE/FALSE)
    ADI_UART_CMD_SET_LINE_STATUS_EVENTS,                // turns line status events on/off                              (Value = TRUE/FALSE)
    ADI_UART_CMD_SET_BAUD_RATE,                         // set the baud rate                                            (Value = u32)
    ADI_UART_CMD_GET_TEMT,                              // senses whether or not the TSR and THR are empty              (Value = u32 *)
    ADI_UART_CMD_AUTOBAUD,                              // initiates autobaud detection                                 (Value = NULL)
    ADI_UART_CMD_SET_AUTOBAUD_CHAR,                     // sets autobaud initiation character (default = @)             (Value = u16)
    ADI_UART_CMD_SET_DIVISOR_BITS,                      // sets autobaud divisor bits (default = 7)                     (Value = u16)
    ADI_UART_CMD_ENABLE_AUTO_COMPLETE,                  // automatically completes buffer when character received       (Value = u8 completion character, ie '\r')
    ADI_UART_CMD_DISABLE_AUTO_COMPLETE,                 // disables automatic completion                                (Value = NULL)
    ADI_UART_CMD_GET_INBOUND_PROCESSED_ELEMENT_COUNT,   // returns the processed count of the current inbound buffer    (Value = u32 *)
    ADI_UART_CMD_GET_OUTBOUND_PROCESSED_ELEMENT_COUNT,  // returns the processed count of the current outbound buffer   (Value = u32 *)
    ADI_UART_CMD_COMPLETE_INBOUND_BUFFER,               // completes processing of current inbound buffer               (Value = NULL)
    ADI_UART_CMD_COMPLETE_OUTBOUND_BUFFER,              // completes processing of current outbound buffer              (Value = NULL)
    ADI_UART_CMD_ENABLE_CTS_RTS,                        // enables/disables CTS/RTS protocol                            (Value = TRUE/FALSE)
    ADI_UART_CMD_SET_CTS_RTS_POLARITY,                  // sets the polarity of the CTS/RTS signals                     (Value = TRUE - active high/FALSE - active low)
    ADI_UART_CMD_SET_CTS_RTS_THRESHOLD,                 // sets the threshold of CTS/RTS                                (Value = TRUE - high threshold/FALSE - low threshold)

    ADI_UART_CMD_SET_TRANSFER_MODE,                     /* sets UART data transfer mode                                 (Value = 0 for Full-duplex,
                                                                                                                                 1 for half-duplex (UART Transfer only),
                                                                                                                                 2 for half-duplex (UART Receive only))
                                                                                                                                 3 to disable UART traffic (disable UART Tx & Rx)
                                                           This command ia valid only in bi-directional dataflow mode, and provides a better contol of UART data transfer   */

    ADI_UART_CMD_SET_PIN_MUX_MODE                       /* 0x40120015 - Sets processor specific pin mux mode (Value - Enumeration of type ADI_UART_PIN_MUX_MODE)
                                                            from the pin mux enumeration table */

};


enum {                                              // Events
    ADI_UART_EVENT_START=ADI_UART_ENUMERATION_START,// 0x40120000
    ADI_UART_EVENT_BREAK_INTERRUPT,                 // break interrupt occurred
    ADI_UART_EVENT_FRAMING_ERROR,                   // framing error occurred
    ADI_UART_EVENT_PARITY_ERROR,                    // parity error occurred
    ADI_UART_EVENT_OVERRUN_ERROR,                   // RBR overrun occurred
    ADI_UART_EVENT_AUTOBAUD_COMPLETE                // autobaud detection completed
};


enum {                              // Return codes
    ADI_UART_RESULT_START=ADI_UART_ENUMERATION_START,   // 0x40120000
    ADI_UART_RESULT_TIMER_ERROR,                        // error controlling the autobaud timer
    ADI_UART_RESULT_BAD_BAUD_RATE,                      // bad baud rate value
    ADI_UART_RESULT_NO_BUFFER,                          // no buffer is available
    ADI_UART_RESULT_NOT_MAPPED_TO_DMA_CHANNEL,          // not mapped to a DMA channel interrupt
    ADI_UART_RESULT_DMA_CHANNEL_NOT_MAPPED_TO_INTERRUPT // DMA channel not mapped to a peripheral interrupt
};


/*********************************************************************

Data Structures

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT  ADIUARTEntryPoint;      // entry point to the Interrupt driven UART device driver
extern ADI_DEV_PDD_ENTRY_POINT  ADIUARTDmaEntryPoint;   // entry point to the DMA driven UART device driver

/*********************************************************************

Processor specific enumerations and defines

*********************************************************************/

/*
** Enumerations of UART pin muxing combinations
**  Use UART driver command (ADI_UART_CMD_SET_PIN_MUX_MODE) with one of the
**  enumeration id listed below to select a pin mux combination
*/

/********************
   Moy (ADSP-BF50x)
********************/

#if defined(__ADSP_MOY__)

typedef enum
{
    /* UART Pin Mux configuration mode 0 (default)
       For UART 0 - use Port F for Tx & Rx
       For UART 1 - use Port F for Tx & Rx */
    ADI_UART_PIN_MUX_MODE_0 = 0,

    /* UART Pin Mux configuration mode 1
       For UART 0 - use Port G for Tx & Rx
       For UART 1 - use Port G for Tx & Rx */
    ADI_UART_PIN_MUX_MODE_1

} ADI_UART_PIN_MUX_MODE;

#endif /* Moy */

/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_UART_H__ */
