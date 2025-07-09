/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ports_bf51x.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Port control service for the Brodie family of Blackfin processors

*********************************************************************************/

#ifndef __ADI_PORTS_H__
#define __ADI_PORTS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

#if !defined(__ADSP_BRODIE__)
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
    o bit 19-23 - PORTx_MUX bit position within the port mux register (5 bits, range 0-31)
    o bit 24-31 - Not used

*********************************************************************/

/********************************************************************
Macros to create the actual directive enumerators and
to extract each of the fields within the value.
*********************************************************************/

/* macro to create the directive */
#define ADI_PORTS_CREATE_DIRECTIVE(Port,Bit,Function,MuxVal,MuxPos) \
    ( ((MuxPos) << 19) | ((MuxVal) << 17) | ((Function) << 16) | ((Bit) << 8) | (Port) )

/* macros to get the individual field values in a given directive */
#define ADI_PORTS_GET_PORT(Directive)               (((u32)Directive) & 0xFF)
#define ADI_PORTS_GET_BIT_POSITION(Directive)      ((((u32)Directive) >> 8) & 0xFF)
#define ADI_PORTS_GET_PORT_FUNCTION(Directive)     ((((u32)Directive) >> 16) & 0x01)
#define ADI_PORTS_GET_PIN_MUX_VALUE(Directive)     ((((u32)Directive) >> 17) & 0x03)
#define ADI_PORTS_GET_PIN_MUX_POSITION(Directive)  ((((u32)Directive) >> 19) & 0x1F)

/*********************************************************************

Directives

These directives are used by the drivers and services to configure the
pin muxing logic as appropriate.

    o For all GPIO configuration directives, 'MuxVal' is ignored

*********************************************************************/

typedef enum ADI_PORTS_DIRECTIVE {

    /* "Port" designates port F, G or H, indexed as 0, 1 and 2                 */
    /* "Bit" is port bit position, 0:15                                        */
    /* "Function" is mux enable, selecting alternate function rather than GPIO */
    /* "MuxVal" is alternate mux function selection value                      */
    /* "MuxPos" is LS bit position for PORTx_MUX register                      */

    /* MII/RMII (MAC) Eithernet Interface                        Port, Bit, Function, MuxVal, MuxPos                                         */
    ADI_PORTS_DIRECTIVE_MAC_COL    = ADI_PORTS_CREATE_DIRECTIVE(  0,     6,    1,       0,       2  ),  /* MAC Eithernet Collision Signal    */
    ADI_PORTS_DIRECTIVE_MAC_CRS    = ADI_PORTS_CREATE_DIRECTIVE(  1,     0,    1,       0,       0  ),  /* MAC Eithernet Carrier Sense       */
    ADI_PORTS_DIRECTIVE_MAC_MDC    = ADI_PORTS_CREATE_DIRECTIVE(  0,     8,    1,       0,       6  ),  /* MAC Eithernet Management Clock    */
    ADI_PORTS_DIRECTIVE_MAC_MDIO   = ADI_PORTS_CREATE_DIRECTIVE(  0,     9,    1,       0,       6  ),  /* MAC Eithernet Management Data I/O */
    ADI_PORTS_DIRECTIVE_MAC_PHYINT = ADI_PORTS_CREATE_DIRECTIVE(  0,    15,    1,       0,      10  ),  /* MAC Eithernet Physical Interface  */
    ADI_PORTS_DIRECTIVE_MAC_RXCLK  = ADI_PORTS_CREATE_DIRECTIVE(  0,     4,    1,       0,       2  ),  /* MAC Eithernet Rcv Clock           */
    ADI_PORTS_DIRECTIVE_MAC_RXD0   = ADI_PORTS_CREATE_DIRECTIVE(  0,    11,    1,       0,       8  ),  /* MAC Eithernet Rcv Data Bit 0      */
    ADI_PORTS_DIRECTIVE_MAC_RXD1   = ADI_PORTS_CREATE_DIRECTIVE(  0,    13,    1,       0,       8  ),  /* MAC Eithernet Rcv Data Bit 1      */
    ADI_PORTS_DIRECTIVE_MAC_RXD2   = ADI_PORTS_CREATE_DIRECTIVE(  0,     1,    1,       0,       1  ),  /* MAC Eithernet Rcv Data Bit 2      */
    ADI_PORTS_DIRECTIVE_MAC_RXD3   = ADI_PORTS_CREATE_DIRECTIVE(  0,     3,    1,       0,       2  ),  /* MAC Eithernet Rcv Data Bit 3      */
    ADI_PORTS_DIRECTIVE_MAC_RXDV   = ADI_PORTS_CREATE_DIRECTIVE(  0,     5,    1,       0,       2  ),  /* MAC Eithernet Rcv Data Valid      */
    ADI_PORTS_DIRECTIVE_MAC_RXER   = ADI_PORTS_CREATE_DIRECTIVE(  1,     1,    1,       0,       0  ),  /* MAC Eithernet Rcv Error           */
    ADI_PORTS_DIRECTIVE_MAC_TXCLK  = ADI_PORTS_CREATE_DIRECTIVE(  1,     2,    1,       0,       0  ),  /* MAC Eithernet Xmt Clock           */
    ADI_PORTS_DIRECTIVE_MAC_TXD0   = ADI_PORTS_CREATE_DIRECTIVE(  0,    10,    1,       0,       6  ),  /* MAC Eithernet Xmt Data Bit 0      */
    ADI_PORTS_DIRECTIVE_MAC_TXD1   = ADI_PORTS_CREATE_DIRECTIVE(  0,    12,    1,       0,       8  ),  /* MAC Eithernet Xmt Data Bit 1      */
    ADI_PORTS_DIRECTIVE_MAC_TXD2   = ADI_PORTS_CREATE_DIRECTIVE(  0,     0,    1,       0,       0  ),  /* MAC Eithernet Xmt Data Bit 2      */
    ADI_PORTS_DIRECTIVE_MAC_TXD3   = ADI_PORTS_CREATE_DIRECTIVE(  0,     2,    1,       0,       2  ),  /* MAC Eithernet Xmt Data Bit 3      */
    ADI_PORTS_DIRECTIVE_MAC_TXEN   = ADI_PORTS_CREATE_DIRECTIVE(  0,    14,    1,       0,       8  ),  /* MAC Eithernet Xmt Enable          */

    /* PPI Peripheral Directives                                     Port, Bit, Function, MuxVal, MuxPos                      */
    ADI_PORTS_DIRECTIVE_PPI_CLK_MUX1 = ADI_PORTS_CREATE_DIRECTIVE(    1,   12,     1,       1,      14  ),  /* Enable PPI CLK */
    ADI_PORTS_DIRECTIVE_PPI_CLK_MUX2 = ADI_PORTS_CREATE_DIRECTIVE(    1,    5,     1,       2,       6  ),  /* Enable PPI CLK */
    ADI_PORTS_DIRECTIVE_PPI_D0       = ADI_PORTS_CREATE_DIRECTIVE(    0,    0,     1,       1,       0  ),  /* Enable PPI D0  */
    ADI_PORTS_DIRECTIVE_PPI_D1       = ADI_PORTS_CREATE_DIRECTIVE(    0,    1,     1,       1,       2  ),  /* Enable PPI D1  */
    ADI_PORTS_DIRECTIVE_PPI_D2       = ADI_PORTS_CREATE_DIRECTIVE(    0,    2,     1,       1,       2  ),  /* Enable PPI D2  */
    ADI_PORTS_DIRECTIVE_PPI_D3       = ADI_PORTS_CREATE_DIRECTIVE(    0,    3,     1,       1,       2  ),  /* Enable PPI D3  */
    ADI_PORTS_DIRECTIVE_PPI_D4       = ADI_PORTS_CREATE_DIRECTIVE(    0,    4,     1,       1,       2  ),  /* Enable PPI D4  */
    ADI_PORTS_DIRECTIVE_PPI_D5       = ADI_PORTS_CREATE_DIRECTIVE(    0,    5,     1,       1,       2  ),  /* Enable PPI D5  */
    ADI_PORTS_DIRECTIVE_PPI_D6       = ADI_PORTS_CREATE_DIRECTIVE(    0,    6,     1,       1,       2  ),  /* Enable PPI D6  */
    ADI_PORTS_DIRECTIVE_PPI_D7       = ADI_PORTS_CREATE_DIRECTIVE(    0,    7,     1,       1,       4  ),  /* Enable PPI D7  */
    ADI_PORTS_DIRECTIVE_PPI_D8       = ADI_PORTS_CREATE_DIRECTIVE(    0,    8,     1,       1,       6  ),  /* Enable PPI D8  */
    ADI_PORTS_DIRECTIVE_PPI_D9       = ADI_PORTS_CREATE_DIRECTIVE(    0,    9,     1,       1,       6  ),  /* Enable PPI D9  */
    ADI_PORTS_DIRECTIVE_PPI_D10      = ADI_PORTS_CREATE_DIRECTIVE(    0,   10,     1,       1,       6  ),  /* Enable PPI D10 */
    ADI_PORTS_DIRECTIVE_PPI_D11      = ADI_PORTS_CREATE_DIRECTIVE(    0,   11,     1,       1,       8  ),  /* Enable PPI D11 */
    ADI_PORTS_DIRECTIVE_PPI_D12      = ADI_PORTS_CREATE_DIRECTIVE(    0,   12,     1,       1,       8  ),  /* Enable PPI D12 */
    ADI_PORTS_DIRECTIVE_PPI_D13      = ADI_PORTS_CREATE_DIRECTIVE(    0,   13,     1,       1,       8  ),  /* Enable PPI D13 */
    ADI_PORTS_DIRECTIVE_PPI_D14      = ADI_PORTS_CREATE_DIRECTIVE(    0,   14,     1,       1,       8  ),  /* Enable PPI D14 */
    ADI_PORTS_DIRECTIVE_PPI_D15      = ADI_PORTS_CREATE_DIRECTIVE(    0,   15,     1,       1,      10  ),  /* Enable PPI D15 */
    ADI_PORTS_DIRECTIVE_PPI_FS1_MUX1 = ADI_PORTS_CREATE_DIRECTIVE(    1,   13,     1,       1,      14  ),  /* Enable PPI FS1 */
    ADI_PORTS_DIRECTIVE_PPI_FS1_MUX2 = ADI_PORTS_CREATE_DIRECTIVE(    1,    6,     1,       2,       6  ),  /* Enable PPI FS1 */
    ADI_PORTS_DIRECTIVE_PPI_FS2_MUX1 = ADI_PORTS_CREATE_DIRECTIVE(    1,   14,     1,       1,      14  ),  /* Enable PPI FS2 */
    ADI_PORTS_DIRECTIVE_PPI_FS2_MUX2 = ADI_PORTS_CREATE_DIRECTIVE(    1,    7,     1,       2,       6  ),  /* Enable PPI FS2 */
    ADI_PORTS_DIRECTIVE_PPI_FS3      = ADI_PORTS_CREATE_DIRECTIVE(    1,   15,     1,       1,      14  ),  /* Enable PPI FS3 */

    /* PWM Motor Control Directives                                Port, Bit, Function, MuxVal, MuxPos                                  */
    ADI_PORTS_DIRECTIVE_PWM_PRI_AH   = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     1,       2,       2  ),  /* PWM Primary Phase A High   */
    ADI_PORTS_DIRECTIVE_PWM_PRI_AL   = ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     1,       2,       2  ),  /* PWM Primary Phase A Low    */
    ADI_PORTS_DIRECTIVE_PWM_PRI_BH   = ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     1,       2,       2  ),  /* PWM Primary Phase B High   */
    ADI_PORTS_DIRECTIVE_PWM_PRI_BL   = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     1,       2,       2  ),  /* PWM Primary Phase B Low    */
    ADI_PORTS_DIRECTIVE_PWM_PRI_CH   = ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     1,       2,       2  ),  /* PWM Primary Phase C High   */
    ADI_PORTS_DIRECTIVE_PWM_PRI_CL   = ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     1,       2,       2  ),  /* PWM Primary Phase C Low    */
    ADI_PORTS_DIRECTIVE_PWM_PRI_SYNC = ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     1,       2,       4  ),  /* PWM Primary Sync           */
    ADI_PORTS_DIRECTIVE_PWM_SEC_AH   = ADI_PORTS_CREATE_DIRECTIVE(  0,   11,     1,       2,       8  ),  /* PWM Secondary Phase A High */
    ADI_PORTS_DIRECTIVE_PWM_SEC_AL   = ADI_PORTS_CREATE_DIRECTIVE(  0,   12,     1,       2,       8  ),  /* PWM Secondary Phase A Low  */
    ADI_PORTS_DIRECTIVE_PWM_SEC_BH   = ADI_PORTS_CREATE_DIRECTIVE(  0,   13,     1,       2,       8  ),  /* PWM Secondary Phase B High */
    ADI_PORTS_DIRECTIVE_PWM_SEC_BL   = ADI_PORTS_CREATE_DIRECTIVE(  0,   14,     1,       2,       8  ),  /* PWM Secondary Phase B Low  */
    ADI_PORTS_DIRECTIVE_PWM_SEC_CH   = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     1,       2,       0  ),  /* PWM Secondary Phase C High */
    ADI_PORTS_DIRECTIVE_PWM_SEC_CL   = ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     1,       2,       0  ),  /* PWM Secondary Phase C Low  */
    ADI_PORTS_DIRECTIVE_PWM_SEC_SYNC = ADI_PORTS_CREATE_DIRECTIVE(  0,   15,     1,       2,      10  ),  /* PWM Secondary Sync         */
    ADI_PORTS_DIRECTIVE_PWM_TRIPB    = ADI_PORTS_CREATE_DIRECTIVE(  1,   14,     1,       2,      14  ),  /* PWM TripB                  */

    /* SPI0 Peripheral Directives                               Port, Bit, Function, MuxVal, MuxPos                                */
    ADI_PORTS_DIRECTIVE_SPI0_MISO = ADI_PORTS_CREATE_DIRECTIVE(  1,   13,     1,       0,      14  ),  /* Enable SPI0 MISO         */
    ADI_PORTS_DIRECTIVE_SPI0_MOSI = ADI_PORTS_CREATE_DIRECTIVE(  1,   14,     1,       0,      14  ),  /* Enable SPI0 MOSI         */
    ADI_PORTS_DIRECTIVE_SPI0_SCK  = ADI_PORTS_CREATE_DIRECTIVE(  1,   12,     1,       0,      14  ),  /* Enable SPI0 SCLK         */
    ADI_PORTS_DIRECTIVE_SPI0_SEL1 = ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     1,       0,       4  ),  /* Enable SPI0 Select 1     */
    ADI_PORTS_DIRECTIVE_SPI0_SEL2 = ADI_PORTS_CREATE_DIRECTIVE(  1,   15,     1,       0,      14  ),  /* Enable SPI0 Select 2     */
    ADI_PORTS_DIRECTIVE_SPI0_SEL3 = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       2,       2  ),  /* Enable SPI0 Select 3     */

    /* SPI0_SEL4 is not actually pinned out, but we need to manage FER to select internal Stacked Flash                            */
    ADI_PORTS_DIRECTIVE_SPI0_SEL4 = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     1,       0,       8  ),  /* Stacked Flash SPISEL4    */

    ADI_PORTS_DIRECTIVE_SPI0_SEL5 = ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     1,       2,       2  ),  /* Enable SPI0 Select 5     */
    ADI_PORTS_DIRECTIVE_SPI0_SS   = ADI_PORTS_CREATE_DIRECTIVE(  1,   11,     1,       0,      12  ),  /* Enable SPI0 Slave Select */

    /* SPI1 Peripheral Directives                               Port, Bit, Function, MuxVal, MuxPos                                */
    ADI_PORTS_DIRECTIVE_SPI1_MISO = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     1,       1,       0  ),  /* Enable SPI1 MISO         */
    ADI_PORTS_DIRECTIVE_SPI1_MOSI = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     1,       1,       0  ),  /* Enable SPI1 MOSI         */
    ADI_PORTS_DIRECTIVE_SPI1_SCK  = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     1,       1,       0  ),  /* Enable SPI1 SCLK         */
    ADI_PORTS_DIRECTIVE_SPI1_SEL1 = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       2,       4  ),  /* Enable SPI1 Select 1     */
    ADI_PORTS_DIRECTIVE_SPI1_SEL2 = ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     1,       2,       0  ),  /* Enable SPI1 Select 2     */
    ADI_PORTS_DIRECTIVE_SPI1_SEL3 = ADI_PORTS_CREATE_DIRECTIVE(  1,    0,     1,       2,       0  ),  /* Enable SPI1 Select 3     */
    ADI_PORTS_DIRECTIVE_SPI1_SEL4 = ADI_PORTS_CREATE_DIRECTIVE(  0,    8,     1,       2,       6  ),  /* Enable SPI1 Select 4     */
    ADI_PORTS_DIRECTIVE_SPI1_SEL5 = ADI_PORTS_CREATE_DIRECTIVE(  1,   11,     1,       2,      12  ),  /* Enable SPI1 Select 5     */
    ADI_PORTS_DIRECTIVE_SPI1_SS   = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     1,       1,       0  ),  /* Enable SPI1 Slave Select */

    /* Timer Directives                                            Port, Bit, Function, MuxVal, MuxPos                                 */
    ADI_PORTS_DIRECTIVE_TMR0_MUX1    = ADI_PORTS_CREATE_DIRECTIVE(  1,   13,     1,       1,      14  ),  /*Enable Timer 0             */
    ADI_PORTS_DIRECTIVE_TMR0_MUX2    = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     1,       2,       6  ),  /*Enable Timer 0             */
    ADI_PORTS_DIRECTIVE_TMR1_MUX1    = ADI_PORTS_CREATE_DIRECTIVE(  1,   14,     1,       1,      14  ),  /*Enable Timer 1             */
    ADI_PORTS_DIRECTIVE_TMR1_MUX2    = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     1,       2,       6  ),  /*Enable Timer 1             */
    ADI_PORTS_DIRECTIVE_TMR2         = ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     1,       2,       6  ),  /*Enable Timer 2             */
    ADI_PORTS_DIRECTIVE_TMR3         = ADI_PORTS_CREATE_DIRECTIVE(  0,   10,     1,       2,       6  ),  /*Enable Timer 3             */
    ADI_PORTS_DIRECTIVE_TMR4         = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       2,      10  ),  /*Enable Timer 4             */
    ADI_PORTS_DIRECTIVE_TMR5         = ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     1,       2,       4  ),  /*Enable Timer 5             */
    ADI_PORTS_DIRECTIVE_TMR6         = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       2,       8  ),  /*Enable Timer 6             */
    ADI_PORTS_DIRECTIVE_TMR7         = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       2,       6  ),  /*Enable Timer 7             */
    ADI_PORTS_DIRECTIVE_TMR_CLK_MUX1 = ADI_PORTS_CREATE_DIRECTIVE(  1,   12,     1,       1,      14  ),  /*Enable Timer Clock on MUX1 */
    ADI_PORTS_DIRECTIVE_TMR_CLK_MUX2 = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     1,       2,       6  ),  /*Enable Timer Clock on MUX2 */

    /* SPORT0 Peripheral Directives                                Port, Bit, Function, MuxVal, MuxPos                            */
    ADI_PORTS_DIRECTIVE_SPORT0_DRPRI = ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     1,       0,       2  ),  /* Enable SPORT 0 DRPRI */
    ADI_PORTS_DIRECTIVE_SPORT0_DRSEC = ADI_PORTS_CREATE_DIRECTIVE(  1,   10,     1,       0,      10  ),  /* Enable SPORT 0 DRSEC */
    ADI_PORTS_DIRECTIVE_SPORT0_DTPRI = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     1,       0,       6  ),  /* Enable SPORT 0 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT0_DTSEC = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       0,      10  ),  /* Enable SPORT 0 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT0_RFS   = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     1,       0,       6  ),  /* Enable SPORT 0 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT0_RSCLK = ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     1,       0,       4  ),  /* Enable SPORT 0 RSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0_TFS   = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     1,       0,       6  ),  /* Enable SPORT 0 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT0_TSCLK = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       0,       8  ),  /* Enable SPORT 0 TSCLK */

    /* SPORT1 Peripheral Directives                                Port, Bit, Function, MuxVal, MuxPos                            */
    ADI_PORTS_DIRECTIVE_SPORT1_DRPRI = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     1,       0,       0  ),  /* Enable SPORT 1 DRPRI */
    ADI_PORTS_DIRECTIVE_SPORT1_DRSEC = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       0,       6  ),  /* Enable SPORT 1 DRSEC */
    ADI_PORTS_DIRECTIVE_SPORT1_DTPRI = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     1,       0,       0  ),  /* Enable SPORT 1 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT1_DTSEC = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       0,       4  ),  /* Enable SPORT 1 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT1_RFS   = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     1,       0,       0  ),  /* Enable SPORT 1 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT1_RSCLK = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     1,       0,       0  ),  /* Enable SPORT 1 RSCLK */
    ADI_PORTS_DIRECTIVE_SPORT1_TFS   = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       0,       2  ),  /* Enable SPORT 1 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT1_TSCLK = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       0,       2  ),  /* Enable SPORT 1 TSCLK */

    /* UART Peripheral Directives                              Port, Bit, Function, MuxVal, MuxPos                        */
    ADI_PORTS_DIRECTIVE_UART0_RX = ADI_PORTS_CREATE_DIRECTIVE(  1,   10,     1,       1,      10  ),  /* Enable UART 0 RX */
    ADI_PORTS_DIRECTIVE_UART0_TX = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       1,      10  ),  /* Enable UART 0 TX */
    ADI_PORTS_DIRECTIVE_UART1_RX = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       1,       6  ),  /* Enable UART 1 RX  */
    ADI_PORTS_DIRECTIVE_UART1_TX = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       1,       4  ),  /* Enable UART 1 TX  */

    /* RSI (Removable Storage Interface) Peripheral Directives  Port, Bit, Function, MuxVal, MuxPos                                   */
    ADI_PORTS_DIRECTIVE_RSI_CLK   = ADI_PORTS_CREATE_DIRECTIVE(  1,     8,    1,       1,       8  ),  /* Enable RSI Clock            */
    ADI_PORTS_DIRECTIVE_RSI_CMD   = ADI_PORTS_CREATE_DIRECTIVE(  1,     7,    1,       1,       6  ),  /* Enable RSI Command/Response */
    ADI_PORTS_DIRECTIVE_RSI_DATA0 = ADI_PORTS_CREATE_DIRECTIVE(  1,     3,    1,       1,       2  ),  /* Enable RSI Data0 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA1 = ADI_PORTS_CREATE_DIRECTIVE(  1,     4,    1,       1,       4  ),  /* Enable RSI Data1 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA2 = ADI_PORTS_CREATE_DIRECTIVE(  1,     5,    1,       1,       6  ),  /* Enable RSI Data2 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA3 = ADI_PORTS_CREATE_DIRECTIVE(  1,     6,    1,       1,       6  ),  /* Enable RSI Data3 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA4 = ADI_PORTS_CREATE_DIRECTIVE(  2,     0,    1,       2,       0  ),  /* Enable RSI Data4 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA5 = ADI_PORTS_CREATE_DIRECTIVE(  2,     1,    1,       2,       0  ),  /* Enable RSI Data5 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA6 = ADI_PORTS_CREATE_DIRECTIVE(  2,     2,    1,       2,       0  ),  /* Enable RSI Data6 Bit        */
    ADI_PORTS_DIRECTIVE_RSI_DATA7 = ADI_PORTS_CREATE_DIRECTIVE(  2,     3,    1,       2,       0  ),  /* Enable RSI Data7 Bit        */

    /* SD Compatibility directives */
    ADI_PORTS_DIRECTIVE_SDH_CLK   = ADI_PORTS_DIRECTIVE_RSI_CLK,    /* Enable RSI Clock            */
    ADI_PORTS_DIRECTIVE_SDH_CMD   = ADI_PORTS_DIRECTIVE_RSI_CMD,    /* Enable RSI Command/Response */
    ADI_PORTS_DIRECTIVE_SDH_D0 = ADI_PORTS_DIRECTIVE_RSI_DATA0,  /* Enable RSI Data0 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D1 = ADI_PORTS_DIRECTIVE_RSI_DATA1,  /* Enable RSI Data1 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D2 = ADI_PORTS_DIRECTIVE_RSI_DATA2,  /* Enable RSI Data2 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D3 = ADI_PORTS_DIRECTIVE_RSI_DATA3,  /* Enable RSI Data3 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D4 = ADI_PORTS_DIRECTIVE_RSI_DATA4,  /* Enable RSI Data4 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D5 = ADI_PORTS_DIRECTIVE_RSI_DATA5,  /* Enable RSI Data5 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D6 = ADI_PORTS_DIRECTIVE_RSI_DATA6,  /* Enable RSI Data6 Bit        */
    ADI_PORTS_DIRECTIVE_SDH_D7 = ADI_PORTS_DIRECTIVE_RSI_DATA7,  /* Enable RSI Data7 Bit        */

    /* Precision Time Protocol (IEEE-1588) Directives            Port, Bit, Function, MuxVal, MuxPos                                    */
    ADI_PORTS_DIRECTIVE_PTP_CLKIN  = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       2,       2  ),  /* PTP clock input enable       */
    ADI_PORTS_DIRECTIVE_PTP_CLKOUT = ADI_PORTS_CREATE_DIRECTIVE(  1,   13,     1,       2,      14  ),  /* PTP clock output enable      */
    ADI_PORTS_DIRECTIVE_PTP_PPS    = ADI_PORTS_CREATE_DIRECTIVE(  1,   12,     1,       2,      14  ),  /* PTP pulses per second enable */
    //ADI_PORTS_DIRECTIVE_PTP_PPS    = ADI_PORTS_CREATE_DIRECTIVE(  1,   12,     1,       2,      14  ),  /* PTP pulses per second enable */

    /* External DMA Request Directives                       Port, Bit, Function, MuxVal, MuxPos                                    */
    ADI_PORTS_DIRECTIVE_DMA_R0 = ADI_PORTS_CREATE_DIRECTIVE(  1,     2,    1,       1,       0  ),  /* Enable External DMA Request 0*/
    ADI_PORTS_DIRECTIVE_DMA_R1 = ADI_PORTS_CREATE_DIRECTIVE(  1,     1,    1,       1,       0  ),  /* Enable External DMA Request 1*/

    /* Asynchronous (DRAM) Memory Control Bits                  Port, Bit, Function, MuxVal, MuxPos                                  */
    ADI_PORTS_DIRECTIVE_DRAM_AMS2 = ADI_PORTS_CREATE_DIRECTIVE(  1,   11,     1,       1,      12  ),  /* DRAM Memory Bank2 Select   */
    ADI_PORTS_DIRECTIVE_DRAM_AMS3 = ADI_PORTS_CREATE_DIRECTIVE(  1,   15,     1,       2,      14  ),  /* DRAM Memory Bank3 Select   */
    ADI_PORTS_DIRECTIVE_DRAM_AOE  = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       1,       2  ),  /* DRAM Memory Output Enable  */
    ADI_PORTS_DIRECTIVE_DRAM_ARDY = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       1,       2  ),  /* DRAM Memory Ready Response */

    /* External Device HWAIT handshake for SPI Slave Mode, UART Flow Control, additional ACK/RDY signal, etc.                  */
    ADI_PORTS_DIRECTIVE_HWAIT = ADI_PORTS_CREATE_DIRECTIVE(  1,   0,     1,       1,       0  ),  /* External handshake enable */

    /* Port F GPIO Directives                              Port, Bit, Function, MuxVal, MuxPos                      */
    ADI_PORTS_DIRECTIVE_PF0  = ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     0,       0,       0  ),  /* Port F Flag 0  */
    ADI_PORTS_DIRECTIVE_PF1  = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     0,       0,       2  ),  /* Port F Flag 1  */
    ADI_PORTS_DIRECTIVE_PF2  = ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     0,       0,       2  ),  /* Port F Flag 2  */
    ADI_PORTS_DIRECTIVE_PF3  = ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     0,       0,       2  ),  /* Port F Flag 3  */
    ADI_PORTS_DIRECTIVE_PF4  = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     0,       0,       2  ),  /* Port F Flag 4  */
    ADI_PORTS_DIRECTIVE_PF5  = ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     0,       0,       2  ),  /* Port F Flag 5  */
    ADI_PORTS_DIRECTIVE_PF6  = ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     0,       0,       2  ),  /* Port F Flag 6  */
    ADI_PORTS_DIRECTIVE_PF7  = ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     0,       0,       4  ),  /* Port F Flag 7  */
    ADI_PORTS_DIRECTIVE_PF8  = ADI_PORTS_CREATE_DIRECTIVE(  0,    8,     0,       0,       6  ),  /* Port F Flag 8  */
    ADI_PORTS_DIRECTIVE_PF9  = ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     0,       0,       6  ),  /* Port F Flag 9  */
    ADI_PORTS_DIRECTIVE_PF10 = ADI_PORTS_CREATE_DIRECTIVE(  0,   10,     0,       0,       6  ),  /* Port F Flag 10 */
    ADI_PORTS_DIRECTIVE_PF11 = ADI_PORTS_CREATE_DIRECTIVE(  0,   11,     0,       0,       8  ),  /* Port F Flag 11 */
    ADI_PORTS_DIRECTIVE_PF12 = ADI_PORTS_CREATE_DIRECTIVE(  0,   12,     0,       0,       8  ),  /* Port F Flag 12 */
    ADI_PORTS_DIRECTIVE_PF13 = ADI_PORTS_CREATE_DIRECTIVE(  0,   13,     0,       0,       8  ),  /* Port F Flag 13 */
    ADI_PORTS_DIRECTIVE_PF14 = ADI_PORTS_CREATE_DIRECTIVE(  0,   14,     0,       0,       8  ),  /* Port F Flag 14 */
    ADI_PORTS_DIRECTIVE_PF15 = ADI_PORTS_CREATE_DIRECTIVE(  0,   15,     0,       0,      10  ),  /* Port F Flag 15 */

    /* Port G GPIO Directives                              Port, Bit, Function, MuxVal, MuxPos                      */
    ADI_PORTS_DIRECTIVE_PG0  = ADI_PORTS_CREATE_DIRECTIVE(  1,    0,     0,       0,       0  ),  /* Port G Flag 0  */
    ADI_PORTS_DIRECTIVE_PG1  = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     0,       0,       0  ),  /* Port G Flag 1  */
    ADI_PORTS_DIRECTIVE_PG2  = ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     0,       0,       0  ),  /* Port G Flag 2  */
    ADI_PORTS_DIRECTIVE_PG3  = ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     0,       0,       2  ),  /* Port G Flag 3  */
    ADI_PORTS_DIRECTIVE_PG4  = ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     0,       0,       4  ),  /* Port G Flag 4  */
    ADI_PORTS_DIRECTIVE_PG5  = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     0,       0,       6  ),  /* Port G Flag 5  */
    ADI_PORTS_DIRECTIVE_PG6  = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     0,       0,       6  ),  /* Port G Flag 6  */
    ADI_PORTS_DIRECTIVE_PG7  = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     0,       0,       6  ),  /* Port G Flag 7  */
    ADI_PORTS_DIRECTIVE_PG8  = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     0,       0,       8  ),  /* Port G Flag 8  */
    ADI_PORTS_DIRECTIVE_PG9  = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     0,       0,      10  ),  /* Port G Flag 9  */
    ADI_PORTS_DIRECTIVE_PG10 = ADI_PORTS_CREATE_DIRECTIVE(  1,   10,     0,       0,      10  ),  /* Port G Flag 10 */
    ADI_PORTS_DIRECTIVE_PG11 = ADI_PORTS_CREATE_DIRECTIVE(  1,   11,     0,       0,      12  ),  /* Port G Flag 11 */
    ADI_PORTS_DIRECTIVE_PG12 = ADI_PORTS_CREATE_DIRECTIVE(  1,   12,     0,       0,      14  ),  /* Port G Flag 12 */
    ADI_PORTS_DIRECTIVE_PG13 = ADI_PORTS_CREATE_DIRECTIVE(  1,   13,     0,       0,      14  ),  /* Port G Flag 13 */
    ADI_PORTS_DIRECTIVE_PG14 = ADI_PORTS_CREATE_DIRECTIVE(  1,   14,     0,       0,      14  ),  /* Port G Flag 14 */
    ADI_PORTS_DIRECTIVE_PG15 = ADI_PORTS_CREATE_DIRECTIVE(  1,   15,     0,       0,      14  ),  /* Port G Flag 15 */

    /* Port H GPIO Directives                              Port, Bit, Function, MuxVal, MuxPos                        */
    ADI_PORTS_DIRECTIVE_PH0  = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     0,       0,       0  ),  /* Port H Flag 0    */
    ADI_PORTS_DIRECTIVE_PH1  = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     0,       0,       0  ),  /* Port H Flag 1    */
    ADI_PORTS_DIRECTIVE_PH2  = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     0,       0,       0  ),  /* Port H Flag 2    */
    ADI_PORTS_DIRECTIVE_PH3  = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     0,       0,       0  ),  /* Port H Flag 3    */
    ADI_PORTS_DIRECTIVE_PH4  = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     0,       0,       2  ),  /* Port H Flag 4    */
    ADI_PORTS_DIRECTIVE_PH5  = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     0,       0,       2  ),  /* Port H Flag 5    */
    ADI_PORTS_DIRECTIVE_PH6  = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     0,       0,       4  ),  /* Port H Flag 6    */
    ADI_PORTS_DIRECTIVE_PH7  = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     0,       0,       6  )   /* Port H Flag 7    */


    /*****************************************\
    |  Hardwired PortJ signals include:       |
    |  PJ0: SCL 5V I/O TWI Serial Clock Line  |
    |  PJ1: SCD 5V I/O TWI Serial Data Line   |
    \*****************************************/


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
