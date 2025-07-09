/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ports_bf54x.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Port control service for the Moab family of Blackfin processors

*********************************************************************************/

#ifndef __ADI_PORTS_H__
#define __ADI_PORTS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

#if !defined(__ADSP_MOAB__)
#error "PORTS module not supported for the current processor family"
#endif

/**********************************************************************

Example:

Enable the pins for PB0, PC2 and PI5

{
    ADI_PORTS_DIRECTIVE Directives[] = {
        ADI_PORTS_DIRECTIVE_PB1,    // Directive enumeration to enable PB0
        ADI_PORTS_DIRECTIVE_PC2,    // Directive enumeration to enable PC2
        ADI_PORTS_DIRECTIVE_PI5     // Directive enumeration to enable PI5
    };

    adi_ports_Configure(Directives, (sizeof(Directives)/sizeof(Directives[0]));
}

**********************************************************************/

/*********************************************************************
Directive enumerations are concatenations of several pieces of information
for the port. A directive ID enumerator consists of:

    o bit 0-8   - port number (starting at 0 and incrementing by 1) (range 0-255)
    o bit 8-15  - bit position within the port function enable register for the given pin
    o bit 16    - PORTx_FER value for this bit/pin (0 for GPIO, 1 for Peripheral)
    o bit 17-18 - PORTx_MUX value to select the peripheral function mapped to the given pin
    o bit 19-31 - Not used

*********************************************************************/

/********************************************************************
Macros to create the actual directive enumerators and
to extract each of the fields within the value.
*********************************************************************/

/* macro to create the directive */
#define ADI_PORTS_CREATE_DIRECTIVE(Port,Bit,Function,MuxVal) \
    (((MuxVal) << 17) | ((Function) << 16) | ((Bit) << 8) | ((Port)))

/* macros to get the individual field values in a given directive */
#define ADI_PORTS_GET_PORT(Directive)           (((u32)Directive) & 0xFF)
#define ADI_PORTS_GET_BIT_POSITION(Directive)   ((((u32)Directive) >> 8) & 0xFF)
#define ADI_PORTS_GET_PORT_FUNCTION(Directive)  ((((u32)Directive) >> 16) & 0x01)
#define ADI_PORTS_GET_PIN_MUX_VALUE(Directive)  ((((u32)Directive) >> 17) & 0x03)

/*********************************************************************

Directives

These directives are used by the drivers and services to configure the
pin muxing logic as appropriate.

    o For all GPIO configuration directives, 'MuxVal' is ignored

*********************************************************************/

typedef enum ADI_PORTS_DIRECTIVE {

    /* Asynchronous Memory Controller Port directives */       /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_AMC_A4      = ADI_PORTS_CREATE_DIRECTIVE(  7,    8,     1,       0  ),  /* Enable Address bit 4 for Async Mem Access Address bus    */
    ADI_PORTS_DIRECTIVE_AMC_A5      = ADI_PORTS_CREATE_DIRECTIVE(  7,    9,     1,       0  ),  /* Enable Address bit 5 for Async Mem Access Address bus    */
    ADI_PORTS_DIRECTIVE_AMC_A6      = ADI_PORTS_CREATE_DIRECTIVE(  7,    10,    1,       0  ),  /* Enable Address bit 6 for Async Mem Access Address bus    */
    ADI_PORTS_DIRECTIVE_AMC_A7      = ADI_PORTS_CREATE_DIRECTIVE(  7,    11,    1,       0  ),  /* Enable Address bit 7 for Async Mem Access Address bus    */
    ADI_PORTS_DIRECTIVE_AMC_A8      = ADI_PORTS_CREATE_DIRECTIVE(  7,    12,    1,       0  ),  /* Enable Address bit 8 for Async Mem Access Address bus    */
    ADI_PORTS_DIRECTIVE_AMC_A9      = ADI_PORTS_CREATE_DIRECTIVE(  7,    13,    1,       0  ),  /* Enable Address bit 9 for Async Mem Access Address bus    */
    ADI_PORTS_DIRECTIVE_AMC_A10     = ADI_PORTS_CREATE_DIRECTIVE(  8,    0,     1,       0  ),  /* Enable Address bit 10 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A11     = ADI_PORTS_CREATE_DIRECTIVE(  8,    1,     1,       0  ),  /* Enable Address bit 11 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A12     = ADI_PORTS_CREATE_DIRECTIVE(  8,    2,     1,       0  ),  /* Enable Address bit 12 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A13     = ADI_PORTS_CREATE_DIRECTIVE(  8,    3,     1,       0  ),  /* Enable Address bit 13 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A14     = ADI_PORTS_CREATE_DIRECTIVE(  8,    4,     1,       0  ),  /* Enable Address bit 14 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A15     = ADI_PORTS_CREATE_DIRECTIVE(  8,    5,     1,       0  ),  /* Enable Address bit 15 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A16     = ADI_PORTS_CREATE_DIRECTIVE(  8,    6,     1,       0  ),  /* Enable Address bit 16 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A17     = ADI_PORTS_CREATE_DIRECTIVE(  8,    7,     1,       0  ),  /* Enable Address bit 17 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A18     = ADI_PORTS_CREATE_DIRECTIVE(  8,    8,     1,       0  ),  /* Enable Address bit 18 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A19     = ADI_PORTS_CREATE_DIRECTIVE(  8,    9,     1,       0  ),  /* Enable Address bit 19 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A20     = ADI_PORTS_CREATE_DIRECTIVE(  8,    10,    1,       0  ),  /* Enable Address bit 20 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A21     = ADI_PORTS_CREATE_DIRECTIVE(  8,    11,    1,       0  ),  /* Enable Address bit 21 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A22     = ADI_PORTS_CREATE_DIRECTIVE(  8,    12,    1,       0  ),  /* Enable Address bit 22 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A23     = ADI_PORTS_CREATE_DIRECTIVE(  8,    13,    1,       0  ),  /* Enable Address bit 23 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A24     = ADI_PORTS_CREATE_DIRECTIVE(  8,    14,    1,       0  ),  /* Enable Address bit 24 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_A25     = ADI_PORTS_CREATE_DIRECTIVE(  8,    15,    1,       0  ),  /* Enable Address bit 25 for Async Mem Access Address bus   */
    ADI_PORTS_DIRECTIVE_AMC_ARDY    = ADI_PORTS_CREATE_DIRECTIVE(  9,    0,     1,       0  ),  /* Enable ARDY/WAIT signal for Async Mem Controller         */
    ADI_PORTS_DIRECTIVE_AMC_BR      = ADI_PORTS_CREATE_DIRECTIVE(  9,    11,    1,       0  ),  /* Enable Bus Request (BR) signal for Async Mem Controller  */
    ADI_PORTS_DIRECTIVE_AMC_BG      = ADI_PORTS_CREATE_DIRECTIVE(  9,    12,    1,       0  ),  /* Enable Bus Grant (BG) signal for Async Mem Controller    */
    ADI_PORTS_DIRECTIVE_AMC_BGH     = ADI_PORTS_CREATE_DIRECTIVE(  9,    13,    1,       0  ),  /* Enable Bus Grant Hang signal for Async Mem Controller    */

    /* NAND Flash Control pin Directives */                    /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_NAND_CE     = ADI_PORTS_CREATE_DIRECTIVE(  9,    1,     1,       0  ),  /* Enable NAND Flash Chip Enable (CE)   */
    ADI_PORTS_DIRECTIVE_NAND_RB     = ADI_PORTS_CREATE_DIRECTIVE(  9,    2,     1,       0  ),  /* Enable NAND Flash Ready Busy (RB)    */

    /* ATAPI port directives */                                /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_ATAPI_A0A   = ADI_PORTS_CREATE_DIRECTIVE(  6,    2,     1,       1  ),  /* Enable ATAPI secondary home Address 0 (PG2)  */
    ADI_PORTS_DIRECTIVE_ATAPI_A1A   = ADI_PORTS_CREATE_DIRECTIVE(  6,    3,     1,       1  ),  /* Enable ATAPI secondary home Address 1 (PG3)  */
    ADI_PORTS_DIRECTIVE_ATAPI_A2A   = ADI_PORTS_CREATE_DIRECTIVE(  6,    4,     1,       1  ),  /* Enable ATAPI secondary home Address 2 (PG4)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D0A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    0,     1,       1  ),  /* Enable ATAPI secondary home Data 0    (PF0)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D1A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    1,     1,       1  ),  /* Enable ATAPI secondary home Data 1    (PF1)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D2A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    2,     1,       1  ),  /* Enable ATAPI secondary home Data 2    (PF2)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D3A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    3,     1,       1  ),  /* Enable ATAPI secondary home Data 3    (PF3)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D4A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    4,     1,       1  ),  /* Enable ATAPI secondary home Data 4    (PF4)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D5A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    5,     1,       1  ),  /* Enable ATAPI secondary home Data 5    (PF5)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D6A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    6,     1,       1  ),  /* Enable ATAPI secondary home Data 6    (PF6)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D7A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    7,     1,       1  ),  /* Enable ATAPI secondary home Data 7    (PF7)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D8A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    8,     1,       1  ),  /* Enable ATAPI secondary home Data 8    (PF8)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D9A   = ADI_PORTS_CREATE_DIRECTIVE(  5,    9,     1,       1  ),  /* Enable ATAPI secondary home Data 9    (PF9)  */
    ADI_PORTS_DIRECTIVE_ATAPI_D10A  = ADI_PORTS_CREATE_DIRECTIVE(  5,    10,    1,       1  ),  /* Enable ATAPI secondary home Data 10   (PF10) */
    ADI_PORTS_DIRECTIVE_ATAPI_D11A  = ADI_PORTS_CREATE_DIRECTIVE(  5,    11,    1,       1  ),  /* Enable ATAPI secondary home Data 11   (PF11) */
    ADI_PORTS_DIRECTIVE_ATAPI_D12A  = ADI_PORTS_CREATE_DIRECTIVE(  5,    12,    1,       1  ),  /* Enable ATAPI secondary home Data 12   (PF12) */
    ADI_PORTS_DIRECTIVE_ATAPI_D13A  = ADI_PORTS_CREATE_DIRECTIVE(  5,    13,    1,       1  ),  /* Enable ATAPI secondary home Data 13   (PF13) */
    ADI_PORTS_DIRECTIVE_ATAPI_D14A  = ADI_PORTS_CREATE_DIRECTIVE(  5,    14,    1,       1  ),  /* Enable ATAPI secondary home Data 14   (PF14) */
    ADI_PORTS_DIRECTIVE_ATAPI_D15A  = ADI_PORTS_CREATE_DIRECTIVE(  5,    15,    1,       1  ),  /* Enable ATAPI secondary home Data 15   (PF15) */
    ADI_PORTS_DIRECTIVE_ATAPI_RESET = ADI_PORTS_CREATE_DIRECTIVE(  7,    2,     1,       0  ),  /* Enable ATAPI Reset                           */
    ADI_PORTS_DIRECTIVE_ATAPI_DIOR  = ADI_PORTS_CREATE_DIRECTIVE(  9,    3,     1,       0  ),  /* Enable ATAPI Data IO Read strobe             */
    ADI_PORTS_DIRECTIVE_ATAPI_DIOW  = ADI_PORTS_CREATE_DIRECTIVE(  9,    4,     1,       0  ),  /* Enable ATAPI Write IO Read strobe            */
    ADI_PORTS_DIRECTIVE_ATAPI_CS0   = ADI_PORTS_CREATE_DIRECTIVE(  9,    5,     1,       0  ),  /* Enable ATAPI Chip Select 0 (CS0)             */
    ADI_PORTS_DIRECTIVE_ATAPI_CS1   = ADI_PORTS_CREATE_DIRECTIVE(  9,    6,     1,       0  ),  /* Enable ATAPI Chip Select 1 (CS1)             */
    ADI_PORTS_DIRECTIVE_ATAPI_DMACK = ADI_PORTS_CREATE_DIRECTIVE(  9,    7,     1,       0  ),  /* Enable ATAPI DMA Acknowledge                 */
    ADI_PORTS_DIRECTIVE_ATAPI_DMARQ = ADI_PORTS_CREATE_DIRECTIVE(  9,    8,     1,       0  ),  /* Enable ATAPI DMA Request                     */
    ADI_PORTS_DIRECTIVE_ATAPI_INTRQ = ADI_PORTS_CREATE_DIRECTIVE(  9,    9,     1,       0  ),  /* Enable ATAPI Interrupt Request               */
    ADI_PORTS_DIRECTIVE_ATAPI_IORDY = ADI_PORTS_CREATE_DIRECTIVE(  9,    10,    1,       0  ),  /* Enable ATAPI IO Ready Handshake              */

    /* Host DMA (HDMA) port directives */                      /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_HDMA_CE     = ADI_PORTS_CREATE_DIRECTIVE(  6,    5,     1,       1  ),  /* Enable HDMA CE       */
    ADI_PORTS_DIRECTIVE_HDMA_RD     = ADI_PORTS_CREATE_DIRECTIVE(  6,    6,     1,       1  ),  /* Enable HDMA RD       */
    ADI_PORTS_DIRECTIVE_HDMA_WR     = ADI_PORTS_CREATE_DIRECTIVE(  6,    7,     1,       1  ),  /* Enable HDMA WR       */
    ADI_PORTS_DIRECTIVE_HDMA_ADDR   = ADI_PORTS_CREATE_DIRECTIVE(  7,    3,     1,       0  ),  /* Enable HDMA ADDR     */
    ADI_PORTS_DIRECTIVE_HDMA_ACK    = ADI_PORTS_CREATE_DIRECTIVE(  7,    4,     1,       0  ),  /* Enable HDMA ACK      */
    ADI_PORTS_DIRECTIVE_HDMA_D0     = ADI_PORTS_CREATE_DIRECTIVE(  3,    8,     1,       1  ),  /* Enable HDMA Data 0   */
    ADI_PORTS_DIRECTIVE_HDMA_D1     = ADI_PORTS_CREATE_DIRECTIVE(  3,    9,     1,       1  ),  /* Enable HDMA Data 1   */
    ADI_PORTS_DIRECTIVE_HDMA_D2     = ADI_PORTS_CREATE_DIRECTIVE(  3,    10,    1,       1  ),  /* Enable HDMA Data 2   */
    ADI_PORTS_DIRECTIVE_HDMA_D3     = ADI_PORTS_CREATE_DIRECTIVE(  3,    11,    1,       1  ),  /* Enable HDMA Data 3   */
    ADI_PORTS_DIRECTIVE_HDMA_D4     = ADI_PORTS_CREATE_DIRECTIVE(  3,    12,    1,       1  ),  /* Enable HDMA Data 4   */
    ADI_PORTS_DIRECTIVE_HDMA_D5     = ADI_PORTS_CREATE_DIRECTIVE(  3,    13,    1,       1  ),  /* Enable HDMA Data 5   */
    ADI_PORTS_DIRECTIVE_HDMA_D6     = ADI_PORTS_CREATE_DIRECTIVE(  3,    14,    1,       1  ),  /* Enable HDMA Data 6   */
    ADI_PORTS_DIRECTIVE_HDMA_D7     = ADI_PORTS_CREATE_DIRECTIVE(  3,    15,    1,       1  ),  /* Enable HDMA Data 7   */
    ADI_PORTS_DIRECTIVE_HDMA_D8     = ADI_PORTS_CREATE_DIRECTIVE(  3,    0,     1,       1  ),  /* Enable HDMA Data 8   */
    ADI_PORTS_DIRECTIVE_HDMA_D9     = ADI_PORTS_CREATE_DIRECTIVE(  3,    1,     1,       1  ),  /* Enable HDMA Data 9   */
    ADI_PORTS_DIRECTIVE_HDMA_D10    = ADI_PORTS_CREATE_DIRECTIVE(  3,    2,     1,       1  ),  /* Enable HDMA Data 10  */
    ADI_PORTS_DIRECTIVE_HDMA_D11    = ADI_PORTS_CREATE_DIRECTIVE(  3,    3,     1,       1  ),  /* Enable HDMA Data 11  */
    ADI_PORTS_DIRECTIVE_HDMA_D12    = ADI_PORTS_CREATE_DIRECTIVE(  3,    4,     1,       1  ),  /* Enable HDMA Data 12  */
    ADI_PORTS_DIRECTIVE_HDMA_D13    = ADI_PORTS_CREATE_DIRECTIVE(  3,    5,     1,       1  ),  /* Enable HDMA Data 13  */
    ADI_PORTS_DIRECTIVE_HDMA_D14    = ADI_PORTS_CREATE_DIRECTIVE(  3,    6,     1,       1  ),  /* Enable HDMA Data 14  */
    ADI_PORTS_DIRECTIVE_HDMA_D15    = ADI_PORTS_CREATE_DIRECTIVE(  3,    7,     1,       1  ),  /* Enable HDMA Data 15  */

    /* External DMA Request Directives*/
    ADI_PORTS_DIRECTIVE_DMA_R0      = ADI_PORTS_CREATE_DIRECTIVE(  7,    5,     1,       1  ),  /* Enable External DMA Request 0*/
    ADI_PORTS_DIRECTIVE_DMA_R1      = ADI_PORTS_CREATE_DIRECTIVE(  7,    6,     1,       1  ),  /* Enable External DMA Request 1*/

    /* MXVR port directives - applies only to BF549 */         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_MXVR_MTXON  = ADI_PORTS_CREATE_DIRECTIVE(  6,    11,    1,       1  ),  /* Enable MXVR Transmit Phy On  */
    ADI_PORTS_DIRECTIVE_MXVR_MRXON  = ADI_PORTS_CREATE_DIRECTIVE(  7,    7,     1,       0  ),  /* Enable MXVR Receive Phy On   */
    ADI_PORTS_DIRECTIVE_MXVR_MTX    = ADI_PORTS_CREATE_DIRECTIVE(  7,    5,     1,       0  ),  /* Enable MXVR Transmit Data    */
    ADI_PORTS_DIRECTIVE_MXVR_MRX    = ADI_PORTS_CREATE_DIRECTIVE(  7,    6,     1,       0  ),  /* Enable MXVR Receive Data     */

    /* Secure Digital Host (SDH) Peripheral Directives */      /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SDH_CLK     = ADI_PORTS_CREATE_DIRECTIVE(  2,    12,    1,       0  ),  /* Enable SDH CLK           */
    ADI_PORTS_DIRECTIVE_SDH_CMD     = ADI_PORTS_CREATE_DIRECTIVE(  2,    13,    1,       0  ),  /* Enable SDH CMD           */
    ADI_PORTS_DIRECTIVE_SDH_D0      = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     1,       0  ),  /* Enable SDH Data 1        */
    ADI_PORTS_DIRECTIVE_SDH_D1      = ADI_PORTS_CREATE_DIRECTIVE(  2,    9,     1,       0  ),  /* Enable SDH Data 1        */
    ADI_PORTS_DIRECTIVE_SDH_D2      = ADI_PORTS_CREATE_DIRECTIVE(  2,    10,    1,       0  ),  /* Enable SDH Data 2        */
    ADI_PORTS_DIRECTIVE_SDH_D3      = ADI_PORTS_CREATE_DIRECTIVE(  2,    11,    1,       0  ),  /* Enable SDH Data 3        */

    /* Keypad Port directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW0 = ADI_PORTS_CREATE_DIRECTIVE(  3,    8,     1,       3  ),  /* Enable Keypad Row 0      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW1 = ADI_PORTS_CREATE_DIRECTIVE(  3,    9,     1,       3  ),  /* Enable Keypad Row 1      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW2 = ADI_PORTS_CREATE_DIRECTIVE(  3,    10,    1,       3  ),  /* Enable Keypad Row 2      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW3 = ADI_PORTS_CREATE_DIRECTIVE(  3,    11,    1,       3  ),  /* Enable Keypad Row 3      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW4 = ADI_PORTS_CREATE_DIRECTIVE(  4,    5,     1,       1  ),  /* Enable Keypad Row 4      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW5 = ADI_PORTS_CREATE_DIRECTIVE(  4,    3,     1,       1  ),  /* Enable Keypad Row 5      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW6 = ADI_PORTS_CREATE_DIRECTIVE(  4,    1,     1,       1  ),  /* Enable Keypad Row 6      */
    ADI_PORTS_DIRECTIVE_KEYPAD_ROW7 = ADI_PORTS_CREATE_DIRECTIVE(  4,    7,     1,       1  ),  /* Enable Keypad Row 7      */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL0 = ADI_PORTS_CREATE_DIRECTIVE(  3,    12,    1,       3  ),  /* Enable Keypad Column 0   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL1 = ADI_PORTS_CREATE_DIRECTIVE(  3,    13,    1,       3  ),  /* Enable Keypad Column 1   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL2 = ADI_PORTS_CREATE_DIRECTIVE(  3,    14,    1,       3  ),  /* Enable Keypad Column 2   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL3 = ADI_PORTS_CREATE_DIRECTIVE(  3,    15,    1,       3  ),  /* Enable Keypad Column 3   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL4 = ADI_PORTS_CREATE_DIRECTIVE(  4,    6,     1,       1  ),  /* Enable Keypad Column 4   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL5 = ADI_PORTS_CREATE_DIRECTIVE(  4,    4,     1,       1  ),  /* Enable Keypad Column 5   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL6 = ADI_PORTS_CREATE_DIRECTIVE(  4,    2,     1,       1  ),  /* Enable Keypad Column 6   */
    ADI_PORTS_DIRECTIVE_KEYPAD_COL7 = ADI_PORTS_CREATE_DIRECTIVE(  4,    0,     1,       1  ),  /* Enable Keypad Column 7   */

    /* Up/Down Counter (Rotary Encoder) Directives */          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_CNT_CUD     = ADI_PORTS_CREATE_DIRECTIVE(  7,    3,     1,       2  ),  /*Enable Count Up and Direction */
    ADI_PORTS_DIRECTIVE_CNT_CDG     = ADI_PORTS_CREATE_DIRECTIVE(  7,    4,     1,       2  ),  /*Enable Count Down and Gate    */
    ADI_PORTS_DIRECTIVE_CNT_CZM     = ADI_PORTS_CREATE_DIRECTIVE(  6,    5,     1,       3  ),  /*Enable Counter Zero Marker    */

    /* EPPI 0 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_EPPI0_CLK   = ADI_PORTS_CREATE_DIRECTIVE(  6,    0,     1,       0  ),  /* Enable EPPI 0 CLK    */
    ADI_PORTS_DIRECTIVE_EPPI0_D0    = ADI_PORTS_CREATE_DIRECTIVE(  5,    0,     1,       0  ),  /* Enable EPPI 0 D0     */
    ADI_PORTS_DIRECTIVE_EPPI0_D1    = ADI_PORTS_CREATE_DIRECTIVE(  5,    1,     1,       0  ),  /* Enable EPPI 0 D1     */
    ADI_PORTS_DIRECTIVE_EPPI0_D2    = ADI_PORTS_CREATE_DIRECTIVE(  5,    2,     1,       0  ),  /* Enable EPPI 0 D2     */
    ADI_PORTS_DIRECTIVE_EPPI0_D3    = ADI_PORTS_CREATE_DIRECTIVE(  5,    3,     1,       0  ),  /* Enable EPPI 0 D3     */
    ADI_PORTS_DIRECTIVE_EPPI0_D4    = ADI_PORTS_CREATE_DIRECTIVE(  5,    4,     1,       0  ),  /* Enable EPPI 0 D4     */
    ADI_PORTS_DIRECTIVE_EPPI0_D5    = ADI_PORTS_CREATE_DIRECTIVE(  5,    5,     1,       0  ),  /* Enable EPPI 0 D5     */
    ADI_PORTS_DIRECTIVE_EPPI0_D6    = ADI_PORTS_CREATE_DIRECTIVE(  5,    6,     1,       0  ),  /* Enable EPPI 0 D6     */
    ADI_PORTS_DIRECTIVE_EPPI0_D7    = ADI_PORTS_CREATE_DIRECTIVE(  5,    7,     1,       0  ),  /* Enable EPPI 0 D7     */
    ADI_PORTS_DIRECTIVE_EPPI0_D8    = ADI_PORTS_CREATE_DIRECTIVE(  5,    8,     1,       0  ),  /* Enable EPPI 0 D8     */
    ADI_PORTS_DIRECTIVE_EPPI0_D9    = ADI_PORTS_CREATE_DIRECTIVE(  5,    9,     1,       0  ),  /* Enable EPPI 0 D9     */
    ADI_PORTS_DIRECTIVE_EPPI0_D10   = ADI_PORTS_CREATE_DIRECTIVE(  5,    10,    1,       0  ),  /* Enable EPPI 0 D10    */
    ADI_PORTS_DIRECTIVE_EPPI0_D11   = ADI_PORTS_CREATE_DIRECTIVE(  5,    11,    1,       0  ),  /* Enable EPPI 0 D11    */
    ADI_PORTS_DIRECTIVE_EPPI0_D12   = ADI_PORTS_CREATE_DIRECTIVE(  5,    12,    1,       0  ),  /* Enable EPPI 0 D12    */
    ADI_PORTS_DIRECTIVE_EPPI0_D13   = ADI_PORTS_CREATE_DIRECTIVE(  5,    13,    1,       0  ),  /* Enable EPPI 0 D13    */
    ADI_PORTS_DIRECTIVE_EPPI0_D14   = ADI_PORTS_CREATE_DIRECTIVE(  5,    14,    1,       0  ),  /* Enable EPPI 0 D14    */
    ADI_PORTS_DIRECTIVE_EPPI0_D15   = ADI_PORTS_CREATE_DIRECTIVE(  5,    15,    1,       0  ),  /* Enable EPPI 0 D15    */
    ADI_PORTS_DIRECTIVE_EPPI0_D16   = ADI_PORTS_CREATE_DIRECTIVE(  6,    3,     1,       0  ),  /* Enable EPPI 0 D16    */
    ADI_PORTS_DIRECTIVE_EPPI0_D17   = ADI_PORTS_CREATE_DIRECTIVE(  6,    4,     1,       0  ),  /* Enable EPPI 0 D17    */
    ADI_PORTS_DIRECTIVE_EPPI0_D18   = ADI_PORTS_CREATE_DIRECTIVE(  3,    0,     1,       3  ),  /* Enable EPPI 0 D18    */
    ADI_PORTS_DIRECTIVE_EPPI0_D19   = ADI_PORTS_CREATE_DIRECTIVE(  3,    1,     1,       3  ),  /* Enable EPPI 0 D19    */
    ADI_PORTS_DIRECTIVE_EPPI0_D20   = ADI_PORTS_CREATE_DIRECTIVE(  3,    2,     1,       3  ),  /* Enable EPPI 0 D20    */
    ADI_PORTS_DIRECTIVE_EPPI0_D21   = ADI_PORTS_CREATE_DIRECTIVE(  3,    3,     1,       3  ),  /* Enable EPPI 0 D21    */
    ADI_PORTS_DIRECTIVE_EPPI0_D22   = ADI_PORTS_CREATE_DIRECTIVE(  3,    4,     1,       3  ),  /* Enable EPPI 0 D22    */
    ADI_PORTS_DIRECTIVE_EPPI0_D23   = ADI_PORTS_CREATE_DIRECTIVE(  3,    5,     1,       3  ),  /* Enable EPPI 0 D23    */
    ADI_PORTS_DIRECTIVE_EPPI0_FS1   = ADI_PORTS_CREATE_DIRECTIVE(  6,    1,     1,       0  ),  /* Enable EPPI 0 FS1    */
    ADI_PORTS_DIRECTIVE_EPPI0_FS2   = ADI_PORTS_CREATE_DIRECTIVE(  6,    2,     1,       0  ),  /* Enable EPPI 0 FS2    */
#if (__SILICON_REVISION__==0x0)
    ADI_PORTS_DIRECTIVE_EPPI0_FS3   = ADI_PORTS_CREATE_DIRECTIVE(  7,    2,     1,       2  ),  /* Enable EPPI 0 FS3    */
#else
    ADI_PORTS_DIRECTIVE_EPPI0_FS3   = ADI_PORTS_CREATE_DIRECTIVE(  7,    1,     1,       1  ),  /* Enable EPPI 2 FS3    */
#endif

    /* EPPI 1 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_EPPI1_CLK   = ADI_PORTS_CREATE_DIRECTIVE(  4,    11,    1,       0  ),  /* Enable EPPI 1 CLK    */
    ADI_PORTS_DIRECTIVE_EPPI1_D0    = ADI_PORTS_CREATE_DIRECTIVE(  3,    0,     1,       0  ),  /* Enable EPPI 1 D0     */
    ADI_PORTS_DIRECTIVE_EPPI1_D1    = ADI_PORTS_CREATE_DIRECTIVE(  3,    1,     1,       0  ),  /* Enable EPPI 1 D1     */
    ADI_PORTS_DIRECTIVE_EPPI1_D2    = ADI_PORTS_CREATE_DIRECTIVE(  3,    2,     1,       0  ),  /* Enable EPPI 1 D2     */
    ADI_PORTS_DIRECTIVE_EPPI1_D3    = ADI_PORTS_CREATE_DIRECTIVE(  3,    3,     1,       0  ),  /* Enable EPPI 1 D3     */
    ADI_PORTS_DIRECTIVE_EPPI1_D4    = ADI_PORTS_CREATE_DIRECTIVE(  3,    4,     1,       0  ),  /* Enable EPPI 1 D4     */
    ADI_PORTS_DIRECTIVE_EPPI1_D5    = ADI_PORTS_CREATE_DIRECTIVE(  3,    5,     1,       0  ),  /* Enable EPPI 1 D5     */
    ADI_PORTS_DIRECTIVE_EPPI1_D6    = ADI_PORTS_CREATE_DIRECTIVE(  3,    6,     1,       0  ),  /* Enable EPPI 1 D6     */
    ADI_PORTS_DIRECTIVE_EPPI1_D7    = ADI_PORTS_CREATE_DIRECTIVE(  3,    7,     1,       0  ),  /* Enable EPPI 1 D7     */
    ADI_PORTS_DIRECTIVE_EPPI1_D8    = ADI_PORTS_CREATE_DIRECTIVE(  3,    8,     1,       0  ),  /* Enable EPPI 1 D8     */
    ADI_PORTS_DIRECTIVE_EPPI1_D9    = ADI_PORTS_CREATE_DIRECTIVE(  3,    9,     1,       0  ),  /* Enable EPPI 1 D9     */
    ADI_PORTS_DIRECTIVE_EPPI1_D10   = ADI_PORTS_CREATE_DIRECTIVE(  3,    10,    1,       0  ),  /* Enable EPPI 1 D10    */
    ADI_PORTS_DIRECTIVE_EPPI1_D11   = ADI_PORTS_CREATE_DIRECTIVE(  3,    11,    1,       0  ),  /* Enable EPPI 1 D11    */
    ADI_PORTS_DIRECTIVE_EPPI1_D12   = ADI_PORTS_CREATE_DIRECTIVE(  3,    12,    1,       0  ),  /* Enable EPPI 1 D12    */
    ADI_PORTS_DIRECTIVE_EPPI1_D13   = ADI_PORTS_CREATE_DIRECTIVE(  3,    13,    1,       0  ),  /* Enable EPPI 1 D13    */
    ADI_PORTS_DIRECTIVE_EPPI1_D14   = ADI_PORTS_CREATE_DIRECTIVE(  3,    14,    1,       0  ),  /* Enable EPPI 1 D14    */
    ADI_PORTS_DIRECTIVE_EPPI1_D15   = ADI_PORTS_CREATE_DIRECTIVE(  3,    15,    1,       0  ),  /* Enable EPPI 1 D15    */
    ADI_PORTS_DIRECTIVE_EPPI1_FS1   = ADI_PORTS_CREATE_DIRECTIVE(  4,    12,    1,       0  ),  /* Enable EPPI 1 FS1    */
    ADI_PORTS_DIRECTIVE_EPPI1_FS2   = ADI_PORTS_CREATE_DIRECTIVE(  4,    13,    1,       0  ),  /* Enable EPPI 1 FS2    */
    ADI_PORTS_DIRECTIVE_EPPI1_FS3   = ADI_PORTS_CREATE_DIRECTIVE(  7,    0,     1,       1  ),  /* Enable EPPI 1 FS3    */

    /* EPPI 2 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_EPPI2_CLK   = ADI_PORTS_CREATE_DIRECTIVE(  6,    7,     1,       2  ),  /* Enable EPPI 2 CLK    */
    ADI_PORTS_DIRECTIVE_EPPI2_D0    = ADI_PORTS_CREATE_DIRECTIVE(  3,    8,     1,       2  ),  /* Enable EPPI 2 D0     */
    ADI_PORTS_DIRECTIVE_EPPI2_D1    = ADI_PORTS_CREATE_DIRECTIVE(  3,    9,     1,       2  ),  /* Enable EPPI 2 D1     */
    ADI_PORTS_DIRECTIVE_EPPI2_D2    = ADI_PORTS_CREATE_DIRECTIVE(  3,    10,    1,       2  ),  /* Enable EPPI 2 D2     */
    ADI_PORTS_DIRECTIVE_EPPI2_D3    = ADI_PORTS_CREATE_DIRECTIVE(  3,    11,    1,       2  ),  /* Enable EPPI 2 D3     */
    ADI_PORTS_DIRECTIVE_EPPI2_D4    = ADI_PORTS_CREATE_DIRECTIVE(  3,    12,    1,       2  ),  /* Enable EPPI 2 D4     */
    ADI_PORTS_DIRECTIVE_EPPI2_D5    = ADI_PORTS_CREATE_DIRECTIVE(  3,    13,    1,       2  ),  /* Enable EPPI 2 D5     */
    ADI_PORTS_DIRECTIVE_EPPI2_D6    = ADI_PORTS_CREATE_DIRECTIVE(  3,    14,    1,       2  ),  /* Enable EPPI 2 D6     */
    ADI_PORTS_DIRECTIVE_EPPI2_D7    = ADI_PORTS_CREATE_DIRECTIVE(  3,    15,    1,       2  ),  /* Enable EPPI 2 D7     */
    ADI_PORTS_DIRECTIVE_EPPI2_FS1   = ADI_PORTS_CREATE_DIRECTIVE(  6,    6,     1,       2  ),  /* Enable EPPI 2 FS1    */
    ADI_PORTS_DIRECTIVE_EPPI2_FS2   = ADI_PORTS_CREATE_DIRECTIVE(  6,    5,     1,       2  ),  /* Enable EPPI 2 FS2    */
#if (__SILICON_REVISION__==0x0)
    ADI_PORTS_DIRECTIVE_EPPI2_FS3   = ADI_PORTS_CREATE_DIRECTIVE(  7,    1,     1,       1  ),  /* Enable EPPI 2 FS3    */
#else
    ADI_PORTS_DIRECTIVE_EPPI2_FS3   = ADI_PORTS_CREATE_DIRECTIVE(  7,    2,     1,       2  ),  /* Enable EPPI 0 FS3    */
#endif

    /* SPI 0 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPI0_SCK    = ADI_PORTS_CREATE_DIRECTIVE(  4,    0,     1,       0  ),  /* Enable SPI 0 SCLK        */
    ADI_PORTS_DIRECTIVE_SPI0_MISO   = ADI_PORTS_CREATE_DIRECTIVE(  4,    1,     1,       0  ),  /* Enable SPI 0 MISO        */
    ADI_PORTS_DIRECTIVE_SPI0_MOSI   = ADI_PORTS_CREATE_DIRECTIVE(  4,    2,     1,       0  ),  /* Enable SPI 0 MOSI        */
    ADI_PORTS_DIRECTIVE_SPI0_SS     = ADI_PORTS_CREATE_DIRECTIVE(  4,    3,     1,       0  ),  /* Enable SPI 0 Slave Select*/
    ADI_PORTS_DIRECTIVE_SPI0_SEL1   = ADI_PORTS_CREATE_DIRECTIVE(  4,    4,     1,       0  ),  /* Enable SPI 0 Select 1    */
    ADI_PORTS_DIRECTIVE_SPI0_SEL2   = ADI_PORTS_CREATE_DIRECTIVE(  4,    5,     1,       0  ),  /* Enable SPI 0 Select 2    */
    ADI_PORTS_DIRECTIVE_SPI0_SEL3   = ADI_PORTS_CREATE_DIRECTIVE(  4,    6,     1,       0  ),  /* Enable SPI 0 Select 3    */

    /* SPI 1 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPI1_SCK    = ADI_PORTS_CREATE_DIRECTIVE(  6,    8,     1,       0  ),  /* Enable SPI 1 SCLK        */
    ADI_PORTS_DIRECTIVE_SPI1_MISO   = ADI_PORTS_CREATE_DIRECTIVE(  6,    9,     1,       0  ),  /* Enable SPI 1 MISO        */
    ADI_PORTS_DIRECTIVE_SPI1_MOSI   = ADI_PORTS_CREATE_DIRECTIVE(  6,    10,    1,       0  ),  /* Enable SPI 1 MOSI        */
    ADI_PORTS_DIRECTIVE_SPI1_SS     = ADI_PORTS_CREATE_DIRECTIVE(  6,    11,    1,       0  ),  /* Enable SPI 1 Slave Select*/
    ADI_PORTS_DIRECTIVE_SPI1_SEL1   = ADI_PORTS_CREATE_DIRECTIVE(  6,    5,     1,       0  ),  /* Enable SPI 1 Select 1    */
    ADI_PORTS_DIRECTIVE_SPI1_SEL2   = ADI_PORTS_CREATE_DIRECTIVE(  6,    6,     1,       0  ),  /* Enable SPI 1 Select 2    */
    ADI_PORTS_DIRECTIVE_SPI1_SEL3   = ADI_PORTS_CREATE_DIRECTIVE(  6,    7,     1,       0  ),  /* Enable SPI 1 Select 3    */

    /* SPI 2 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPI2_SCK    = ADI_PORTS_CREATE_DIRECTIVE(  1,    12,    1,       0  ),  /* Enable SPI 2 SCLK        */
    ADI_PORTS_DIRECTIVE_SPI2_MISO   = ADI_PORTS_CREATE_DIRECTIVE(  1,    14,    1,       0  ),  /* Enable SPI 2 MISO        */
    ADI_PORTS_DIRECTIVE_SPI2_MOSI   = ADI_PORTS_CREATE_DIRECTIVE(  1,    13,    1,       0  ),  /* Enable SPI 2 MOSI        */
    ADI_PORTS_DIRECTIVE_SPI2_SS     = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       0  ),  /* Enable SPI 2 Slave Select*/
    ADI_PORTS_DIRECTIVE_SPI2_SEL1   = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       0  ),  /* Enable SPI 2 Select 1    */
    ADI_PORTS_DIRECTIVE_SPI2_SEL2   = ADI_PORTS_CREATE_DIRECTIVE(  1,    10,    1,       0  ),  /* Enable SPI 2 Select 2    */
    ADI_PORTS_DIRECTIVE_SPI2_SEL3   = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    1,       0  ),  /* Enable SPI 2 Select 3    */

    /* SPORT 0 Peripheral Directives */                        /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPORT0_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     1,       0  ),  /* Enable SPORT 0 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT0_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     1,       0  ),  /* Enable SPORT 0 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT0_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     1,       0  ),  /* Enable SPORT 0 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT0_TSCLK= ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     1,       0  ),  /* Enable SPORT 0 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       0  ),  /* Enable SPORT 0 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT0_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       0  ),  /* Enable SPORT 0 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT0_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       0  ),  /* Enable SPORT 0 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT0_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       0  ),  /* Enable SPORT 0 TSCLK */

    /* SPORT 1 Peripheral Directives */                        /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPORT1_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  3,    0,     1,       2  ),  /* Enable SPORT 1 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT1_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  3,    1,     1,       2  ),  /* Enable SPORT 1 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT1_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  3,    2,     1,       2  ),  /* Enable SPORT 1 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT1_TSCLK= ADI_PORTS_CREATE_DIRECTIVE(  3,    3,     1,       2  ),  /* Enable SPORT 1 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT1_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  3,    4,     1,       2  ),  /* Enable SPORT 1 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT1_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  3,    5,     1,       2  ),  /* Enable SPORT 1 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT1_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  3,    6,     1,       2  ),  /* Enable SPORT 1 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT1_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  3,    7,     1,       2  ),  /* Enable SPORT 1 TSCLK */

    /* SPORT 2 Peripheral Directives */                        /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPORT2_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     1,       0  ),  /* Enable SPORT 2 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT2_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     1,       0  ),  /* Enable SPORT 2 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT2_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     1,       0  ),  /* Enable SPORT 2 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT2_TSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     1,       0  ),  /* Enable SPORT 2 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT2_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     1,       0  ),  /* Enable SPORT 2 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT2_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     1,       0  ),  /* Enable SPORT 2 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT2_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     1,       0  ),  /* Enable SPORT 2 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT2_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     1,       0  ),  /* Enable SPORT 2 TSCLK */

    /* SPORT 3 Peripheral Directives */                        /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_SPORT3_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,    8,     1,       0  ),  /* Enable SPORT 3 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT3_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     1,       0  ),  /* Enable SPORT 3 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT3_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    10,    1,       0  ),  /* Enable SPORT 3 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT3_TSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    11,    1,       0  ),  /* Enable SPORT 3 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT3_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,    12,    1,       0  ),  /* Enable SPORT 3 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT3_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,    13,    1,       0  ),  /* Enable SPORT 3 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT3_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    14,    1,       0  ),  /* Enable SPORT 3 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT3_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    15,    1,       0  ),  /* Enable SPORT 3 TSCLK */

    /* TWI 0 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_TWI0_SCL    = ADI_PORTS_CREATE_DIRECTIVE(  4,    14,    1,       0  ),  /* Enable TWI 0 SCL */
    ADI_PORTS_DIRECTIVE_TWI0_SDA    = ADI_PORTS_CREATE_DIRECTIVE(  4,    15,    1,       0  ),  /* Enable TWI 0 SDA */

    /* TWI 1 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_TWI1_SCL    = ADI_PORTS_CREATE_DIRECTIVE(  1,    0,     1,       0  ),  /* Enable TWI 1 SCL */
    ADI_PORTS_DIRECTIVE_TWI1_SDA    = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     1,       0  ),  /* Enable TWI 1 SDA */

    /* CAN 0 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_CAN0_TX     = ADI_PORTS_CREATE_DIRECTIVE(  6,    12,    1,       0  ),  /* Enable CAN 0 TX  */
    ADI_PORTS_DIRECTIVE_CAN0_RX     = ADI_PORTS_CREATE_DIRECTIVE(  6,    13,    1,       0  ),  /* Enable CAN 0 RX  */

    /* CAN 1 Peripheral Directives */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_CAN1_TX     = ADI_PORTS_CREATE_DIRECTIVE(  6,    14,    1,       0  ),  /* Enable CAN 1 TX  */
    ADI_PORTS_DIRECTIVE_CAN1_RX     = ADI_PORTS_CREATE_DIRECTIVE(  6,    15,    1,       0  ),  /* Enable CAN 1 RX  */

    /* UART 0 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_UART0_TX    = ADI_PORTS_CREATE_DIRECTIVE(  4,    7,     1,       0  ),  /* Enable UART 0 TX */
    ADI_PORTS_DIRECTIVE_UART0_RX    = ADI_PORTS_CREATE_DIRECTIVE(  4,    8,     1,       0  ),  /* Enable UART 0 RX */

    /* UART 1 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_UART1_TX    = ADI_PORTS_CREATE_DIRECTIVE(  7,    0,     1,       0  ),  /* Enable UART 1 TX */
    ADI_PORTS_DIRECTIVE_UART1_RX    = ADI_PORTS_CREATE_DIRECTIVE(  7,    1,     1,       0  ),  /* Enable UART 1 RX */
    ADI_PORTS_DIRECTIVE_UART1_RTS   = ADI_PORTS_CREATE_DIRECTIVE(  4,    9,     1,       0  ),  /* Enable UART 1 RTS*/
    ADI_PORTS_DIRECTIVE_UART1_CTS   = ADI_PORTS_CREATE_DIRECTIVE(  4,    10,    1,       0  ),  /* Enable UART 1 CTS*/

    /* UART 2 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_UART2_TX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     1,       0  ),  /* Enable UART 2 TX */
    ADI_PORTS_DIRECTIVE_UART2_RX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     1,       0  ),  /* Enable UART 2 RX */

    /* UART 3 Peripheral Directives */                         /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_UART3_TX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     1,       0  ),  /* Enable UART 3 TX */
    ADI_PORTS_DIRECTIVE_UART3_RX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     1,       0  ),  /* Enable UART 3 RX */
    ADI_PORTS_DIRECTIVE_UART3_RTS   = ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     1,       0  ),  /* Enable UART 3 RTS*/
    ADI_PORTS_DIRECTIVE_UART3_CTS   = ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     1,       0  ),  /* Enable UART 3 CTS*/

    /* Directives to enable Timers */                          /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_TMR0        = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       1  ),  /*Enable Timer 0  */
    ADI_PORTS_DIRECTIVE_TMR1        = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       1  ),  /*Enable Timer 1  */
    ADI_PORTS_DIRECTIVE_TMR2        = ADI_PORTS_CREATE_DIRECTIVE(  1,    10,    1,       1  ),  /*Enable Timer 2  */
    ADI_PORTS_DIRECTIVE_TMR3        = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    1,       1  ),  /*Enable Timer 3  */
    ADI_PORTS_DIRECTIVE_TMR4        = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     1,       1  ),  /*Enable Timer 4  */
    ADI_PORTS_DIRECTIVE_TMR5        = ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     1,       1  ),  /*Enable Timer 5  */
    ADI_PORTS_DIRECTIVE_TMR6        = ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     1,       1  ),  /*Enable Timer 6  */
    ADI_PORTS_DIRECTIVE_TMR7        = ADI_PORTS_CREATE_DIRECTIVE(  0,    13,    1,       1  ),  /*Enable Timer 7  */
    ADI_PORTS_DIRECTIVE_TMR8        = ADI_PORTS_CREATE_DIRECTIVE(  7,    2,     1,       1  ),  /*Enable Timer 8  */
    ADI_PORTS_DIRECTIVE_TMR9        = ADI_PORTS_CREATE_DIRECTIVE(  7,    3,     1,       1  ),  /*Enable Timer 9  */
    ADI_PORTS_DIRECTIVE_TMR10       = ADI_PORTS_CREATE_DIRECTIVE(  7,    4,     1,       1  ),  /*Enable Timer 10 */

    /* Port A GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PA0         = ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     0,       0  ),  /* Port A Flag 0    */
    ADI_PORTS_DIRECTIVE_PA1         = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     0,       0  ),  /* Port A Flag 1    */
    ADI_PORTS_DIRECTIVE_PA2         = ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     0,       0  ),  /* Port A Flag 2    */
    ADI_PORTS_DIRECTIVE_PA3         = ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     0,       0  ),  /* Port A Flag 3    */
    ADI_PORTS_DIRECTIVE_PA4         = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     0,       0  ),  /* Port A Flag 4    */
    ADI_PORTS_DIRECTIVE_PA5         = ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     0,       0  ),  /* Port A Flag 5    */
    ADI_PORTS_DIRECTIVE_PA6         = ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     0,       0  ),  /* Port A Flag 6    */
    ADI_PORTS_DIRECTIVE_PA7         = ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     0,       0  ),  /* Port A Flag 7    */
    ADI_PORTS_DIRECTIVE_PA8         = ADI_PORTS_CREATE_DIRECTIVE(  0,    8,     0,       0  ),  /* Port A Flag 8    */
    ADI_PORTS_DIRECTIVE_PA9         = ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     0,       0  ),  /* Port A Flag 9    */
    ADI_PORTS_DIRECTIVE_PA10        = ADI_PORTS_CREATE_DIRECTIVE(  0,    10,    0,       0  ),  /* Port A Flag 10   */
    ADI_PORTS_DIRECTIVE_PA11        = ADI_PORTS_CREATE_DIRECTIVE(  0,    11,    0,       0  ),  /* Port A Flag 11   */
    ADI_PORTS_DIRECTIVE_PA12        = ADI_PORTS_CREATE_DIRECTIVE(  0,    12,    0,       0  ),  /* Port A Flag 12   */
    ADI_PORTS_DIRECTIVE_PA13        = ADI_PORTS_CREATE_DIRECTIVE(  0,    13,    0,       0  ),  /* Port A Flag 13   */
    ADI_PORTS_DIRECTIVE_PA14        = ADI_PORTS_CREATE_DIRECTIVE(  0,    14,    0,       0  ),  /* Port A Flag 14   */
    ADI_PORTS_DIRECTIVE_PA15        = ADI_PORTS_CREATE_DIRECTIVE(  0,    15,    0,       0  ),  /* Port A Flag 15   */

    /* Port B GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PB0         = ADI_PORTS_CREATE_DIRECTIVE(  1,    0,     0,       0  ),  /* Port B Flag 0    */
    ADI_PORTS_DIRECTIVE_PB1         = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     0,       0  ),  /* Port B Flag 1    */
    ADI_PORTS_DIRECTIVE_PB2         = ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     0,       0  ),  /* Port B Flag 2    */
    ADI_PORTS_DIRECTIVE_PB3         = ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     0,       0  ),  /* Port B Flag 3    */
    ADI_PORTS_DIRECTIVE_PB4         = ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     0,       0  ),  /* Port B Flag 4    */
    ADI_PORTS_DIRECTIVE_PB5         = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     0,       0  ),  /* Port B Flag 5    */
    ADI_PORTS_DIRECTIVE_PB6         = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     0,       0  ),  /* Port B Flag 6    */
    ADI_PORTS_DIRECTIVE_PB7         = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     0,       0  ),  /* Port B Flag 7    */
    ADI_PORTS_DIRECTIVE_PB8         = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     0,       0  ),  /* Port B Flag 8    */
    ADI_PORTS_DIRECTIVE_PB9         = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     0,       0  ),  /* Port B Flag 9    */
    ADI_PORTS_DIRECTIVE_PB10        = ADI_PORTS_CREATE_DIRECTIVE(  1,    10,    0,       0  ),  /* Port B Flag 10   */
    ADI_PORTS_DIRECTIVE_PB11        = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    0,       0  ),  /* Port B Flag 11   */
    ADI_PORTS_DIRECTIVE_PB12        = ADI_PORTS_CREATE_DIRECTIVE(  1,    12,    0,       0  ),  /* Port B Flag 12   */
    ADI_PORTS_DIRECTIVE_PB13        = ADI_PORTS_CREATE_DIRECTIVE(  1,    13,    0,       0  ),  /* Port B Flag 13   */
    ADI_PORTS_DIRECTIVE_PB14        = ADI_PORTS_CREATE_DIRECTIVE(  1,    14,    0,       0  ),  /* Port B Flag 14   */

    /* Port C GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PC0         = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     0,       0  ),  /* Port C Flag 0    */
    ADI_PORTS_DIRECTIVE_PC1         = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     0,       0  ),  /* Port C Flag 1    */
    ADI_PORTS_DIRECTIVE_PC2         = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     0,       0  ),  /* Port C Flag 2    */
    ADI_PORTS_DIRECTIVE_PC3         = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     0,       0  ),  /* Port C Flag 3    */
    ADI_PORTS_DIRECTIVE_PC4         = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     0,       0  ),  /* Port C Flag 4    */
    ADI_PORTS_DIRECTIVE_PC5         = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     0,       0  ),  /* Port C Flag 5    */
    ADI_PORTS_DIRECTIVE_PC6         = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     0,       0  ),  /* Port C Flag 6    */
    ADI_PORTS_DIRECTIVE_PC7         = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     0,       0  ),  /* Port C Flag 7    */
    ADI_PORTS_DIRECTIVE_PC8         = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     0,       0  ),  /* Port C Flag 8    */
    ADI_PORTS_DIRECTIVE_PC9         = ADI_PORTS_CREATE_DIRECTIVE(  2,    9,     0,       0  ),  /* Port C Flag 9    */
    ADI_PORTS_DIRECTIVE_PC10        = ADI_PORTS_CREATE_DIRECTIVE(  2,    10,    0,       0  ),  /* Port C Flag 10   */
    ADI_PORTS_DIRECTIVE_PC11        = ADI_PORTS_CREATE_DIRECTIVE(  2,    11,    0,       0  ),  /* Port C Flag 11   */
    ADI_PORTS_DIRECTIVE_PC12        = ADI_PORTS_CREATE_DIRECTIVE(  2,    12,    0,       0  ),  /* Port C Flag 12   */
    ADI_PORTS_DIRECTIVE_PC13        = ADI_PORTS_CREATE_DIRECTIVE(  2,    13,    0,       0  ),  /* Port C Flag 13   */

    /* Port D GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PD0         = ADI_PORTS_CREATE_DIRECTIVE(  3,    0,     0,       0  ),  /* Port D Flag 0    */
    ADI_PORTS_DIRECTIVE_PD1         = ADI_PORTS_CREATE_DIRECTIVE(  3,    1,     0,       0  ),  /* Port D Flag 1    */
    ADI_PORTS_DIRECTIVE_PD2         = ADI_PORTS_CREATE_DIRECTIVE(  3,    2,     0,       0  ),  /* Port D Flag 2    */
    ADI_PORTS_DIRECTIVE_PD3         = ADI_PORTS_CREATE_DIRECTIVE(  3,    3,     0,       0  ),  /* Port D Flag 3    */
    ADI_PORTS_DIRECTIVE_PD4         = ADI_PORTS_CREATE_DIRECTIVE(  3,    4,     0,       0  ),  /* Port D Flag 4    */
    ADI_PORTS_DIRECTIVE_PD5         = ADI_PORTS_CREATE_DIRECTIVE(  3,    5,     0,       0  ),  /* Port D Flag 5    */
    ADI_PORTS_DIRECTIVE_PD6         = ADI_PORTS_CREATE_DIRECTIVE(  3,    6,     0,       0  ),  /* Port D Flag 6    */
    ADI_PORTS_DIRECTIVE_PD7         = ADI_PORTS_CREATE_DIRECTIVE(  3,    7,     0,       0  ),  /* Port D Flag 7    */
    ADI_PORTS_DIRECTIVE_PD8         = ADI_PORTS_CREATE_DIRECTIVE(  3,    8,     0,       0  ),  /* Port D Flag 8    */
    ADI_PORTS_DIRECTIVE_PD9         = ADI_PORTS_CREATE_DIRECTIVE(  3,    9,     0,       0  ),  /* Port D Flag 9    */
    ADI_PORTS_DIRECTIVE_PD10        = ADI_PORTS_CREATE_DIRECTIVE(  3,    10,    0,       0  ),  /* Port D Flag 10   */
    ADI_PORTS_DIRECTIVE_PD11        = ADI_PORTS_CREATE_DIRECTIVE(  3,    11,    0,       0  ),  /* Port D Flag 11   */
    ADI_PORTS_DIRECTIVE_PD12        = ADI_PORTS_CREATE_DIRECTIVE(  3,    12,    0,       0  ),  /* Port D Flag 12   */
    ADI_PORTS_DIRECTIVE_PD13        = ADI_PORTS_CREATE_DIRECTIVE(  3,    13,    0,       0  ),  /* Port D Flag 13   */
    ADI_PORTS_DIRECTIVE_PD14        = ADI_PORTS_CREATE_DIRECTIVE(  3,    14,    0,       0  ),  /* Port D Flag 14   */
    ADI_PORTS_DIRECTIVE_PD15        = ADI_PORTS_CREATE_DIRECTIVE(  3,    15,    0,       0  ),  /* Port D Flag 15   */

    /* Port E GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PE0         = ADI_PORTS_CREATE_DIRECTIVE(  4,    0,     0,       0  ),  /* Port E Flag 0    */
    ADI_PORTS_DIRECTIVE_PE1         = ADI_PORTS_CREATE_DIRECTIVE(  4,    1,     0,       0  ),  /* Port E Flag 1    */
    ADI_PORTS_DIRECTIVE_PE2         = ADI_PORTS_CREATE_DIRECTIVE(  4,    2,     0,       0  ),  /* Port E Flag 2    */
    ADI_PORTS_DIRECTIVE_PE3         = ADI_PORTS_CREATE_DIRECTIVE(  4,    3,     0,       0  ),  /* Port E Flag 3    */
    ADI_PORTS_DIRECTIVE_PE4         = ADI_PORTS_CREATE_DIRECTIVE(  4,    4,     0,       0  ),  /* Port E Flag 4    */
    ADI_PORTS_DIRECTIVE_PE5         = ADI_PORTS_CREATE_DIRECTIVE(  4,    5,     0,       0  ),  /* Port E Flag 5    */
    ADI_PORTS_DIRECTIVE_PE6         = ADI_PORTS_CREATE_DIRECTIVE(  4,    6,     0,       0  ),  /* Port E Flag 6    */
    ADI_PORTS_DIRECTIVE_PE7         = ADI_PORTS_CREATE_DIRECTIVE(  4,    7,     0,       0  ),  /* Port E Flag 7    */
    ADI_PORTS_DIRECTIVE_PE8         = ADI_PORTS_CREATE_DIRECTIVE(  4,    8,     0,       0  ),  /* Port E Flag 8    */
    ADI_PORTS_DIRECTIVE_PE9         = ADI_PORTS_CREATE_DIRECTIVE(  4,    9,     0,       0  ),  /* Port E Flag 9    */
    ADI_PORTS_DIRECTIVE_PE10        = ADI_PORTS_CREATE_DIRECTIVE(  4,    10,    0,       0  ),  /* Port E Flag 10   */
    ADI_PORTS_DIRECTIVE_PE11        = ADI_PORTS_CREATE_DIRECTIVE(  4,    11,    0,       0  ),  /* Port E Flag 11   */
    ADI_PORTS_DIRECTIVE_PE12        = ADI_PORTS_CREATE_DIRECTIVE(  4,    12,    0,       0  ),  /* Port E Flag 12   */
    ADI_PORTS_DIRECTIVE_PE13        = ADI_PORTS_CREATE_DIRECTIVE(  4,    13,    0,       0  ),  /* Port E Flag 13   */
    ADI_PORTS_DIRECTIVE_PE14        = ADI_PORTS_CREATE_DIRECTIVE(  4,    14,    0,       0  ),  /* Port E Flag 14   */
    ADI_PORTS_DIRECTIVE_PE15        = ADI_PORTS_CREATE_DIRECTIVE(  4,    15,    0,       0  ),  /* Port E Flag 15   */

    /* Port F GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PF0         = ADI_PORTS_CREATE_DIRECTIVE(  5,    0,     0,       0  ),  /* Port F Flag 0    */
    ADI_PORTS_DIRECTIVE_PF1         = ADI_PORTS_CREATE_DIRECTIVE(  5,    1,     0,       0  ),  /* Port F Flag 1    */
    ADI_PORTS_DIRECTIVE_PF2         = ADI_PORTS_CREATE_DIRECTIVE(  5,    2,     0,       0  ),  /* Port F Flag 2    */
    ADI_PORTS_DIRECTIVE_PF3         = ADI_PORTS_CREATE_DIRECTIVE(  5,    3,     0,       0  ),  /* Port F Flag 3    */
    ADI_PORTS_DIRECTIVE_PF4         = ADI_PORTS_CREATE_DIRECTIVE(  5,    4,     0,       0  ),  /* Port F Flag 4    */
    ADI_PORTS_DIRECTIVE_PF5         = ADI_PORTS_CREATE_DIRECTIVE(  5,    5,     0,       0  ),  /* Port F Flag 5    */
    ADI_PORTS_DIRECTIVE_PF6         = ADI_PORTS_CREATE_DIRECTIVE(  5,    6,     0,       0  ),  /* Port F Flag 6    */
    ADI_PORTS_DIRECTIVE_PF7         = ADI_PORTS_CREATE_DIRECTIVE(  5,    7,     0,       0  ),  /* Port F Flag 7    */
    ADI_PORTS_DIRECTIVE_PF8         = ADI_PORTS_CREATE_DIRECTIVE(  5,    8,     0,       0  ),  /* Port F Flag 8    */
    ADI_PORTS_DIRECTIVE_PF9         = ADI_PORTS_CREATE_DIRECTIVE(  5,    9,     0,       0  ),  /* Port F Flag 9    */
    ADI_PORTS_DIRECTIVE_PF10        = ADI_PORTS_CREATE_DIRECTIVE(  5,    10,    0,       0  ),  /* Port F Flag 10   */
    ADI_PORTS_DIRECTIVE_PF11        = ADI_PORTS_CREATE_DIRECTIVE(  5,    11,    0,       0  ),  /* Port F Flag 11   */
    ADI_PORTS_DIRECTIVE_PF12        = ADI_PORTS_CREATE_DIRECTIVE(  5,    12,    0,       0  ),  /* Port F Flag 12   */
    ADI_PORTS_DIRECTIVE_PF13        = ADI_PORTS_CREATE_DIRECTIVE(  5,    13,    0,       0  ),  /* Port F Flag 13   */
    ADI_PORTS_DIRECTIVE_PF14        = ADI_PORTS_CREATE_DIRECTIVE(  5,    14,    0,       0  ),  /* Port F Flag 14   */
    ADI_PORTS_DIRECTIVE_PF15        = ADI_PORTS_CREATE_DIRECTIVE(  5,    15,    0,       0  ),  /* Port F Flag 15   */

    /* Port G GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PG0         = ADI_PORTS_CREATE_DIRECTIVE(  6,    0,     0,       0  ),  /* Port G Flag 0    */
    ADI_PORTS_DIRECTIVE_PG1         = ADI_PORTS_CREATE_DIRECTIVE(  6,    1,     0,       0  ),  /* Port G Flag 1    */
    ADI_PORTS_DIRECTIVE_PG2         = ADI_PORTS_CREATE_DIRECTIVE(  6,    2,     0,       0  ),  /* Port G Flag 2    */
    ADI_PORTS_DIRECTIVE_PG3         = ADI_PORTS_CREATE_DIRECTIVE(  6,    3,     0,       0  ),  /* Port G Flag 3    */
    ADI_PORTS_DIRECTIVE_PG4         = ADI_PORTS_CREATE_DIRECTIVE(  6,    4,     0,       0  ),  /* Port G Flag 4    */
    ADI_PORTS_DIRECTIVE_PG5         = ADI_PORTS_CREATE_DIRECTIVE(  6,    5,     0,       0  ),  /* Port G Flag 5    */
    ADI_PORTS_DIRECTIVE_PG6         = ADI_PORTS_CREATE_DIRECTIVE(  6,    6,     0,       0  ),  /* Port G Flag 6    */
    ADI_PORTS_DIRECTIVE_PG7         = ADI_PORTS_CREATE_DIRECTIVE(  6,    7,     0,       0  ),  /* Port G Flag 7    */
    ADI_PORTS_DIRECTIVE_PG8         = ADI_PORTS_CREATE_DIRECTIVE(  6,    8,     0,       0  ),  /* Port G Flag 8    */
    ADI_PORTS_DIRECTIVE_PG9         = ADI_PORTS_CREATE_DIRECTIVE(  6,    9,     0,       0  ),  /* Port G Flag 9    */
    ADI_PORTS_DIRECTIVE_PG10        = ADI_PORTS_CREATE_DIRECTIVE(  6,    10,    0,       0  ),  /* Port G Flag 10   */
    ADI_PORTS_DIRECTIVE_PG11        = ADI_PORTS_CREATE_DIRECTIVE(  6,    11,    0,       0  ),  /* Port G Flag 11   */
    ADI_PORTS_DIRECTIVE_PG12        = ADI_PORTS_CREATE_DIRECTIVE(  6,    12,    0,       0  ),  /* Port G Flag 12   */
    ADI_PORTS_DIRECTIVE_PG13        = ADI_PORTS_CREATE_DIRECTIVE(  6,    13,    0,       0  ),  /* Port G Flag 13   */
    ADI_PORTS_DIRECTIVE_PG14        = ADI_PORTS_CREATE_DIRECTIVE(  6,    14,    0,       0  ),  /* Port G Flag 14   */
    ADI_PORTS_DIRECTIVE_PG15        = ADI_PORTS_CREATE_DIRECTIVE(  6,    15,    0,       0  ),  /* Port G Flag 15   */

    /* Port H GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PH0         = ADI_PORTS_CREATE_DIRECTIVE(  7,    0,     0,       0  ),  /* Port H Flag 0    */
    ADI_PORTS_DIRECTIVE_PH1         = ADI_PORTS_CREATE_DIRECTIVE(  7,    1,     0,       0  ),  /* Port H Flag 1    */
    ADI_PORTS_DIRECTIVE_PH2         = ADI_PORTS_CREATE_DIRECTIVE(  7,    2,     0,       0  ),  /* Port H Flag 2    */
    ADI_PORTS_DIRECTIVE_PH3         = ADI_PORTS_CREATE_DIRECTIVE(  7,    3,     0,       0  ),  /* Port H Flag 3    */
    ADI_PORTS_DIRECTIVE_PH4         = ADI_PORTS_CREATE_DIRECTIVE(  7,    4,     0,       0  ),  /* Port H Flag 4    */
    ADI_PORTS_DIRECTIVE_PH5         = ADI_PORTS_CREATE_DIRECTIVE(  7,    5,     0,       0  ),  /* Port H Flag 5    */
    ADI_PORTS_DIRECTIVE_PH6         = ADI_PORTS_CREATE_DIRECTIVE(  7,    6,     0,       0  ),  /* Port H Flag 6    */
    ADI_PORTS_DIRECTIVE_PH7         = ADI_PORTS_CREATE_DIRECTIVE(  7,    7,     0,       0  ),  /* Port H Flag 7    */
    ADI_PORTS_DIRECTIVE_PH8         = ADI_PORTS_CREATE_DIRECTIVE(  7,    8,     0,       0  ),  /* Port H Flag 8    */
    ADI_PORTS_DIRECTIVE_PH9         = ADI_PORTS_CREATE_DIRECTIVE(  7,    9,     0,       0  ),  /* Port H Flag 9    */
    ADI_PORTS_DIRECTIVE_PH10        = ADI_PORTS_CREATE_DIRECTIVE(  7,    10,    0,       0  ),  /* Port H Flag 10   */
    ADI_PORTS_DIRECTIVE_PH11        = ADI_PORTS_CREATE_DIRECTIVE(  7,    11,    0,       0  ),  /* Port H Flag 11   */
    ADI_PORTS_DIRECTIVE_PH12        = ADI_PORTS_CREATE_DIRECTIVE(  7,    12,    0,       0  ),  /* Port H Flag 12   */
    ADI_PORTS_DIRECTIVE_PH13        = ADI_PORTS_CREATE_DIRECTIVE(  7,    13,    0,       0  ),  /* Port H Flag 13   */

    /* Port I GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PI0         = ADI_PORTS_CREATE_DIRECTIVE(  8,    0,     0,       0  ),  /* Port I Flag 0    */
    ADI_PORTS_DIRECTIVE_PI1         = ADI_PORTS_CREATE_DIRECTIVE(  8,    1,     0,       0  ),  /* Port I Flag 1    */
    ADI_PORTS_DIRECTIVE_PI2         = ADI_PORTS_CREATE_DIRECTIVE(  8,    2,     0,       0  ),  /* Port I Flag 2    */
    ADI_PORTS_DIRECTIVE_PI3         = ADI_PORTS_CREATE_DIRECTIVE(  8,    3,     0,       0  ),  /* Port I Flag 3    */
    ADI_PORTS_DIRECTIVE_PI4         = ADI_PORTS_CREATE_DIRECTIVE(  8,    4,     0,       0  ),  /* Port I Flag 4    */
    ADI_PORTS_DIRECTIVE_PI5         = ADI_PORTS_CREATE_DIRECTIVE(  8,    5,     0,       0  ),  /* Port I Flag 5    */
    ADI_PORTS_DIRECTIVE_PI6         = ADI_PORTS_CREATE_DIRECTIVE(  8,    6,     0,       0  ),  /* Port I Flag 6    */
    ADI_PORTS_DIRECTIVE_PI7         = ADI_PORTS_CREATE_DIRECTIVE(  8,    7,     0,       0  ),  /* Port I Flag 7    */
    ADI_PORTS_DIRECTIVE_PI8         = ADI_PORTS_CREATE_DIRECTIVE(  8,    8,     0,       0  ),  /* Port I Flag 8    */
    ADI_PORTS_DIRECTIVE_PI9         = ADI_PORTS_CREATE_DIRECTIVE(  8,    9,     0,       0  ),  /* Port I Flag 9    */
    ADI_PORTS_DIRECTIVE_PI10        = ADI_PORTS_CREATE_DIRECTIVE(  8,    10,    0,       0  ),  /* Port I Flag 10   */
    ADI_PORTS_DIRECTIVE_PI11        = ADI_PORTS_CREATE_DIRECTIVE(  8,    11,    0,       0  ),  /* Port I Flag 11   */
    ADI_PORTS_DIRECTIVE_PI12        = ADI_PORTS_CREATE_DIRECTIVE(  8,    12,    0,       0  ),  /* Port I Flag 12   */
    ADI_PORTS_DIRECTIVE_PI13        = ADI_PORTS_CREATE_DIRECTIVE(  8,    13,    0,       0  ),  /* Port I Flag 13   */
    ADI_PORTS_DIRECTIVE_PI14        = ADI_PORTS_CREATE_DIRECTIVE(  8,    14,    0,       0  ),  /* Port I Flag 14   */
    ADI_PORTS_DIRECTIVE_PI15        = ADI_PORTS_CREATE_DIRECTIVE(  8,    15,    0,       0  ),  /* Port I Flag 15   */

    /* Port J GPIO Directives */                               /* Port, Bit, Function, MuxVal */
    ADI_PORTS_DIRECTIVE_PJ0         = ADI_PORTS_CREATE_DIRECTIVE(  9,    0,     0,       0  ),  /* Port J Flag 0    */
    ADI_PORTS_DIRECTIVE_PJ1         = ADI_PORTS_CREATE_DIRECTIVE(  9,    1,     0,       0  ),  /* Port J Flag 1    */
    ADI_PORTS_DIRECTIVE_PJ2         = ADI_PORTS_CREATE_DIRECTIVE(  9,    2,     0,       0  ),  /* Port J Flag 2    */
    ADI_PORTS_DIRECTIVE_PJ3         = ADI_PORTS_CREATE_DIRECTIVE(  9,    3,     0,       0  ),  /* Port J Flag 3    */
    ADI_PORTS_DIRECTIVE_PJ4         = ADI_PORTS_CREATE_DIRECTIVE(  9,    4,     0,       0  ),  /* Port J Flag 4    */
    ADI_PORTS_DIRECTIVE_PJ5         = ADI_PORTS_CREATE_DIRECTIVE(  9,    5,     0,       0  ),  /* Port J Flag 5    */
    ADI_PORTS_DIRECTIVE_PJ6         = ADI_PORTS_CREATE_DIRECTIVE(  9,    6,     0,       0  ),  /* Port J Flag 6    */
    ADI_PORTS_DIRECTIVE_PJ7         = ADI_PORTS_CREATE_DIRECTIVE(  9,    7,     0,       0  ),  /* Port J Flag 7    */
    ADI_PORTS_DIRECTIVE_PJ8         = ADI_PORTS_CREATE_DIRECTIVE(  9,    8,     0,       0  ),  /* Port J Flag 8    */
    ADI_PORTS_DIRECTIVE_PJ9         = ADI_PORTS_CREATE_DIRECTIVE(  9,    9,     0,       0  ),  /* Port J Flag 9    */
    ADI_PORTS_DIRECTIVE_PJ10        = ADI_PORTS_CREATE_DIRECTIVE(  9,    10,    0,       0  ),  /* Port J Flag 10   */
    ADI_PORTS_DIRECTIVE_PJ11        = ADI_PORTS_CREATE_DIRECTIVE(  9,    11,    0,       0  ),  /* Port J Flag 11   */
    ADI_PORTS_DIRECTIVE_PJ12        = ADI_PORTS_CREATE_DIRECTIVE(  9,    12,    0,       0  ),  /* Port J Flag 12   */
    ADI_PORTS_DIRECTIVE_PJ13        = ADI_PORTS_CREATE_DIRECTIVE(  9,    13,    0,       0  ),  /* Port J Flag 13   */
    ADI_PORTS_DIRECTIVE_PJ14        = ADI_PORTS_CREATE_DIRECTIVE(  9,    14,    0,       0  ),  /* Port J Flag 14   */
    ADI_PORTS_DIRECTIVE_PJ15        = ADI_PORTS_CREATE_DIRECTIVE(  9,    15,    0,       0  )   /* Port J Flag 15   */

} ADI_PORTS_DIRECTIVE;

/*********************************************************************

Return codes

*********************************************************************/

typedef enum ADI_PORTS_RESULT {
    ADI_PORTS_RESULT_SUCCESS = 0,                       /* Generic success */
    ADI_PORTS_RESULT_FAILED  = 1,                       /* Generic failure */

    ADI_PORTS_RESULT_START=ADI_PORTS_ENUMERATION_START, /* insure this order remains */
    ADI_PORTS_RESULT_BAD_DIRECTIVE,                     /* (0x90001) A directive is invalid for the specified peripheral    */
    ADI_PORTS_RESULT_NULL_ARRAY                         /* (0x90002) Array passed is NULL                                   */

} ADI_PORTS_RESULT;

/*********************************************************************

API Functions

*********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

ADI_PORTS_RESULT adi_ports_Init(            /* initializes the ports service                    */
    void                *pCriticalRegionArg /* parameter for critical region function           */
);

ADI_PORTS_RESULT adi_ports_Terminate(       /* terminates the Ports service                     */
    void
);

ADI_PORTS_RESULT adi_ports_Configure(       /* Configures GPIO pins for GPIO or Peripheral use  */
    ADI_PORTS_DIRECTIVE *pDirectives,       /* pointer to an array of directives                */
    u32                 nDirectives         /* number of directives                             */
);

#ifdef __cplusplus
}
#endif

#endif /* Not ASM */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_PORTS_H__ */
