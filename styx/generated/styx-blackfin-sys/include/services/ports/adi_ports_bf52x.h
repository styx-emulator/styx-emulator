/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ports_bf52x.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Port control service for the Kookaburra family of Blackfin processors

*********************************************************************************/

#ifndef __ADI_PORTS_H__
#define __ADI_PORTS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

#if !defined(__ADSP_KOOKABURRA__) && !defined(__ADSP_MOCKINGBIRD__)
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

    /* Note: 52x has only 4 ports, F, G, H and J, indexed as 0, 1, 2 and 3 */

    /* PPI Peripheral Directives */                            /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_PPICLK_TMRCLK
                                  = ADI_PORTS_CREATE_DIRECTIVE(    0,    0,     1,       1,      12  ),  /* Enable PPICLK/TMPCLK (PortJ:2) */
    ADI_PORTS_DIRECTIVE_PPI_FS2_MUX0
                                  = ADI_PORTS_CREATE_DIRECTIVE(    1,    5,     1,       0,       2  ),  /* Enable PPI FS2    */
    ADI_PORTS_DIRECTIVE_PPI_FS2_MUX2
                                  = ADI_PORTS_CREATE_DIRECTIVE(    1,    5,     1,       2,       2  ),  /* Enable PPI FS2    */
    ADI_PORTS_DIRECTIVE_PPI_FS3   = ADI_PORTS_CREATE_DIRECTIVE(    1,    6,     1,       2,       2  ),  /* Enable PPI FS3    */
    ADI_PORTS_DIRECTIVE_PPI_D0    = ADI_PORTS_CREATE_DIRECTIVE(    0,    0,     1,       0,       0  ),  /* Enable PPI D0     */
    ADI_PORTS_DIRECTIVE_PPI_D1    = ADI_PORTS_CREATE_DIRECTIVE(    0,    1,     1,       0,       0  ),  /* Enable PPI D1     */
    ADI_PORTS_DIRECTIVE_PPI_D2    = ADI_PORTS_CREATE_DIRECTIVE(    0,    2,     1,       0,       0  ),  /* Enable PPI D2     */
    ADI_PORTS_DIRECTIVE_PPI_D3    = ADI_PORTS_CREATE_DIRECTIVE(    0,    3,     1,       0,       0  ),  /* Enable PPI D3     */
    ADI_PORTS_DIRECTIVE_PPI_D4    = ADI_PORTS_CREATE_DIRECTIVE(    0,    4,     1,       0,       0  ),  /* Enable PPI D4     */
    ADI_PORTS_DIRECTIVE_PPI_D5    = ADI_PORTS_CREATE_DIRECTIVE(    0,    5,     1,       0,       0  ),  /* Enable PPI D5     */
    ADI_PORTS_DIRECTIVE_PPI_D6    = ADI_PORTS_CREATE_DIRECTIVE(    0,    6,     1,       0,       0  ),  /* Enable PPI D6     */
    ADI_PORTS_DIRECTIVE_PPI_D7    = ADI_PORTS_CREATE_DIRECTIVE(    0,    7,     1,       0,       0  ),  /* Enable PPI D7     */
    ADI_PORTS_DIRECTIVE_PPI_D8    = ADI_PORTS_CREATE_DIRECTIVE(    0,    8,     1,       0,       2  ),  /* Enable PPI D8     */
    ADI_PORTS_DIRECTIVE_PPI_D9    = ADI_PORTS_CREATE_DIRECTIVE(    0,    9,     1,       0,       2  ),  /* Enable PPI D9     */
    ADI_PORTS_DIRECTIVE_PPI_D10   = ADI_PORTS_CREATE_DIRECTIVE(    0,    10,    1,       0,       4  ),  /* Enable PPI D10    */
    ADI_PORTS_DIRECTIVE_PPI_D11   = ADI_PORTS_CREATE_DIRECTIVE(    0,    11,    1,       0,       6  ),  /* Enable PPI D11    */
    ADI_PORTS_DIRECTIVE_PPI_D12   = ADI_PORTS_CREATE_DIRECTIVE(    0,    12,    1,       0,       8  ),  /* Enable PPI D12    */
    ADI_PORTS_DIRECTIVE_PPI_D13   = ADI_PORTS_CREATE_DIRECTIVE(    0,    13,    1,       0,       8  ),  /* Enable PPI D13    */
    ADI_PORTS_DIRECTIVE_PPI_D14   = ADI_PORTS_CREATE_DIRECTIVE(    0,    14,    1,       0,       10 ),  /* Enable PPI D14    */
    ADI_PORTS_DIRECTIVE_PPI_D15   = ADI_PORTS_CREATE_DIRECTIVE(    0,    15,    1,       0,       10 ),  /* Enable PPI D15    */

    /* PORT F SPORT 0 Peripheral Directives */                  /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_SPORT0F_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     1,       1,       0  ),  /* Enable SPORT 0 DRPRI */
    ADI_PORTS_DIRECTIVE_SPORT0F_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     1,       1,       0  ),  /* Enable SPORT 0 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT0F_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     1,       1,       0  ),  /* Enable SPORT 0 RSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0F_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     1,       1,       0  ),  /* Enable SPORT 0 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT0F_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     1,       1,       0  ),  /* Enable SPORT 0 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT0F_TSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     1,       1,       0  ),  /* Enable SPORT 0 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0F_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     1,       1,       0  ),  /* Enable SPORT 0 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT0F_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     1,       1,       0  ),  /* Enable SPORT 0 DRSEC */

    /* PORT F SPORT 1 Peripheral Directives */                  /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_SPORT1F_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,    8,     1,       1,       2  ),  /* Enable SPORT 1 DRPRI */
    ADI_PORTS_DIRECTIVE_SPORT1F_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     1,       1,       2  ),  /* Enable SPORT 1 RSCLK */
    ADI_PORTS_DIRECTIVE_SPORT1F_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,   10,     1,       1,       4  ),  /* Enable SPORT 1 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT1F_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  0,   11,     1,       1,       6  ),  /* Enable SPORT 1 TFS   */
    ADI_PORTS_DIRECTIVE_SPORT1F_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  0,   12,     1,       1,       8  ),  /* Enable SPORT 1 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT1F_TSCLK= ADI_PORTS_CREATE_DIRECTIVE(  0,   13,     1,       1,       8  ),  /* Enable SPORT 1 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT1F_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,   14,     1,       1,      10  ),  /* Enable SPORT 1 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT1F_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  0,   15,     1,       1,      10  ),  /* Enable SPORT 1 DRSEC */

    /* PORT G SPORT0 Peripheral Directives */
    ADI_PORTS_DIRECTIVE_SPORT0G_DRSEC= ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     1,       1,       0  ),  /* Enable SPORT 0 DRSEC */
    ADI_PORTS_DIRECTIVE_SPORT0G_DTSEC= ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     1,       1,       0  ),  /* Enable SPORT 0 DTSEC */
    ADI_PORTS_DIRECTIVE_SPORT0G_DTPRI= ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     1,       0,       2  ),  /* Enable SPORT 0 DTPRI */
    ADI_PORTS_DIRECTIVE_SPORT0G_DRPRI= ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     1,       1,       4  ),  /* Enable SPORT 0 DRPRI */
    ADI_PORTS_DIRECTIVE_SPORT0G_RFS  = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       1,       4  ),  /* Enable SPORT 0 RFS   */
    ADI_PORTS_DIRECTIVE_SPORT0G_RSCLK= ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       1,       6  ),  /* Enable SPORT 0 RSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0G_TSCLK_MUX1
                                     = ADI_PORTS_CREATE_DIRECTIVE(  1,   10,     1,       1,       8  ),  /* Enable SPORT 0 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0G_TSCLK_MUX0
                                     = ADI_PORTS_CREATE_DIRECTIVE(  1,   14,     1,       0,       12 ),  /* Enable SPORT 0 TSCLK */
    ADI_PORTS_DIRECTIVE_SPORT0G_TFS  = ADI_PORTS_CREATE_DIRECTIVE(  1,   15,     1,       0,       12 ),  /* Enable SPORT 0 TFS   */

    /* NAND Flash Memory Directives */                         /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_NAND_CE     = ADI_PORTS_CREATE_DIRECTIVE(  2,    10,    1,       0,       4  ),  /* Enable NAND Flash Chip Enable          */
    ADI_PORTS_DIRECTIVE_NAND_WEB    = ADI_PORTS_CREATE_DIRECTIVE(  2,    11,    1,       0,       4  ),  /* Enable NAND Flash Write Enable Bar     */
    ADI_PORTS_DIRECTIVE_NAND_REB    = ADI_PORTS_CREATE_DIRECTIVE(  2,    12,    1,       0,       4  ),  /* Enable NAND Flash Read Enable Bar      */
    ADI_PORTS_DIRECTIVE_NAND_BUSY   = ADI_PORTS_CREATE_DIRECTIVE(  2,    13,    1,       0,       4  ),  /* Enable NAND Flash Busy                 */
    ADI_PORTS_DIRECTIVE_NAND_CLE    = ADI_PORTS_CREATE_DIRECTIVE(  2,    14,    1,       0,       4  ),  /* Enable NAND Flash Command Latch Enable */
    ADI_PORTS_DIRECTIVE_NAND_ALE    = ADI_PORTS_CREATE_DIRECTIVE(  2,    15,    1,       0,       4  ),  /* Enable NAND Flash Address Latch Enable */
    ADI_PORTS_DIRECTIVE_NAND_FD0    = ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 0    */
    ADI_PORTS_DIRECTIVE_NAND_FD1    = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 1    */
    ADI_PORTS_DIRECTIVE_NAND_FD2    = ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 2    */
    ADI_PORTS_DIRECTIVE_NAND_FD3    = ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 3    */
    ADI_PORTS_DIRECTIVE_NAND_FD4    = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 4    */
    ADI_PORTS_DIRECTIVE_NAND_FD5    = ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 5    */
    ADI_PORTS_DIRECTIVE_NAND_FD6    = ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 6    */
    ADI_PORTS_DIRECTIVE_NAND_FD7    = ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     1,       2,       0  ),  /* Enable NAND Flash Port F Data Bit 7    */
    ADI_PORTS_DIRECTIVE_NAND_HD0    = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 0    */
    ADI_PORTS_DIRECTIVE_NAND_HD1    = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 1    */
    ADI_PORTS_DIRECTIVE_NAND_HD2    = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 2    */
    ADI_PORTS_DIRECTIVE_NAND_HD3    = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 3    */
    ADI_PORTS_DIRECTIVE_NAND_HD4    = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 4    */
    ADI_PORTS_DIRECTIVE_NAND_HD5    = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 5    */
    ADI_PORTS_DIRECTIVE_NAND_HD6    = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 6    */
    ADI_PORTS_DIRECTIVE_NAND_HD7    = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       0,       0  ),  /* Enable NAND Flash Port H Data Bit 7    */

    /* SPI Peripheral Directives */                            /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_SPI_SEL1    = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     1,       2,       0  ),  /* Enable SPI Select 1     */
    ADI_PORTS_DIRECTIVE_SPI_SEL2    = ADI_PORTS_CREATE_DIRECTIVE(  0,    12,    1,       2,       8  ),  /* Enable SPI Select 2     */
    ADI_PORTS_DIRECTIVE_SPI_SEL3    = ADI_PORTS_CREATE_DIRECTIVE(  0,    13,    1,       2,       8  ),  /* Enable SPI Select 3     */
    ADI_PORTS_DIRECTIVE_SPI_SEL4    = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     1,       0,       2  ),  /* Enable SPI Select 4     */
    ADI_PORTS_DIRECTIVE_SPI_SEL5    = ADI_PORTS_CREATE_DIRECTIVE(  2,    9,     1,       0,       4  ),  /* Enable SPI Select 5     */
    ADI_PORTS_DIRECTIVE_SPI_SEL6    = ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     1,       2,       2  ),  /* Enable SPI Select 6     */
    ADI_PORTS_DIRECTIVE_SPI_SEL7    = ADI_PORTS_CREATE_DIRECTIVE(  0,    10,    1,       2,       4  ),  /* Enable SPI Select 7     */
    ADI_PORTS_DIRECTIVE_SPI_SCK_MUX0= ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     1,       0,       0  ),  /* Enable SPI SCLK         */
    ADI_PORTS_DIRECTIVE_SPI_SCK_MUX2= ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     1,       2,       0  ),  /* Enable SPI SCLK         */
    ADI_PORTS_DIRECTIVE_SPI_MISO_MUX0=ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     1,       0,       0  ),  /* Enable SPI MISO         */
    ADI_PORTS_DIRECTIVE_SPI_MISO_MUX2=ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     1,       2,       0  ),  /* Enable SPI MISO         */
    ADI_PORTS_DIRECTIVE_SPI_MOSI_MUX0=ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     1,       0,       0  ),  /* Enable SPI MOSI         */
    ADI_PORTS_DIRECTIVE_SPI_MOSI_MUX2=ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     1,       2,       0  ),  /* Enable SPI MOSI         */
    ADI_PORTS_DIRECTIVE_SPI_SS      = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     1,       0,       0  ),  /* Enable SPI Slave Select */

    /* MII/RMII (MAC) Eithernet Interface */                   /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_MAC_MDC     = ADI_PORTS_CREATE_DIRECTIVE(  1,    14,    1,       1,       12 ),  /* MAC Eithernet Management Clock    */
    ADI_PORTS_DIRECTIVE_MAC_PHYINT  = ADI_PORTS_CREATE_DIRECTIVE(  1,    15,    1,       1,       12 ),  /* MAC Eithernet Physical Interface  */
    ADI_PORTS_DIRECTIVE_MAC_CRS     = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     1,       1,       0  ),  /* MAC Eithernet Carrier Sense       */
    ADI_PORTS_DIRECTIVE_MAC_RXER    = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     1,       1,       0  ),  /* MAC Eithernet Rcv Error           */
    ADI_PORTS_DIRECTIVE_MAC_MDIO    = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     1,       1,       0  ),  /* MAC Eithernet Management Data I/O */
    ADI_PORTS_DIRECTIVE_MAC_TXEN    = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     1,       1,       0  ),  /* MAC Eithernet Xmt Enable          */
    ADI_PORTS_DIRECTIVE_MAC_TXCLK   = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       1,       0  ),  /* MAC Eithernet Xmt Clock           */
    ADI_PORTS_DIRECTIVE_MAC_TXD0    = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       1,       0  ),  /* MAC Eithernet Xmt Data Bit 0      */
    ADI_PORTS_DIRECTIVE_MAC_RXD0    = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       1,       0  ),  /* MAC Eithernet Rcv Data Bit 0      */
    ADI_PORTS_DIRECTIVE_MAC_TXD1    = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       1,       0  ),  /* MAC Eithernet Xmt Data Bit 1      */
    ADI_PORTS_DIRECTIVE_MAC_RXD1    = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     1,       1,       2  ),  /* MAC Eithernet Rcv Data Bit 1      */
    ADI_PORTS_DIRECTIVE_MAC_TXD2    = ADI_PORTS_CREATE_DIRECTIVE(  2,    9,     1,       1,       4  ),  /* MAC Eithernet Xmt Data Bit 2      */
    ADI_PORTS_DIRECTIVE_MAC_RXD2    = ADI_PORTS_CREATE_DIRECTIVE(  2,    10,    1,       1,       4  ),  /* MAC Eithernet Rcv Data Bit 2      */
    ADI_PORTS_DIRECTIVE_MAC_TXD3    = ADI_PORTS_CREATE_DIRECTIVE(  2,    11,    1,       1,       4  ),  /* MAC Eithernet Xmt Data Bit 3      */
    ADI_PORTS_DIRECTIVE_MAC_RXD3    = ADI_PORTS_CREATE_DIRECTIVE(  2,    12,    1,       1,       4  ),  /* MAC Eithernet Rcv Data Bit 3      */
    ADI_PORTS_DIRECTIVE_MAC_RXCLK   = ADI_PORTS_CREATE_DIRECTIVE(  2,    13,    1,       1,       4  ),  /* MAC Eithernet Rcv Clock           */
    ADI_PORTS_DIRECTIVE_MAC_RXDV    = ADI_PORTS_CREATE_DIRECTIVE(  2,    14,    1,       1,       4  ),  /* MAC Eithernet Rcv Data Valid      */
    ADI_PORTS_DIRECTIVE_MAC_COL     = ADI_PORTS_CREATE_DIRECTIVE(  2,    15,    1,       1,       4  ),  /* MAC Eithernet Collision Signal    */

    /* Host DMA (HDMA) port directives */                      /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_HDMA_WR     = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    1,       2,       10 ),  /* Enable HDMA WR       */
    ADI_PORTS_DIRECTIVE_HDMA_ACK    = ADI_PORTS_CREATE_DIRECTIVE(  1,    12,    1,       2,       10 ),  /* Enable HDMA ACK      */
    ADI_PORTS_DIRECTIVE_HDMA_ADDR   = ADI_PORTS_CREATE_DIRECTIVE(  1,    13,    1,       2,       10 ),  /* Enable HDMA ADDR     */
    ADI_PORTS_DIRECTIVE_HDMA_RD     = ADI_PORTS_CREATE_DIRECTIVE(  1,    14,    1,       2,       12 ),  /* Enable HDMA RD       */
    ADI_PORTS_DIRECTIVE_HDMA_CE     = ADI_PORTS_CREATE_DIRECTIVE(  1,    15,    1,       2,       12 ),  /* Enable HDMA CE       */
    ADI_PORTS_DIRECTIVE_HDMA_D0     = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     1,       2,       0  ),  /* Enable HDMA Data 0   */
    ADI_PORTS_DIRECTIVE_HDMA_D1     = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     1,       2,       0  ),  /* Enable HDMA Data 1   */
    ADI_PORTS_DIRECTIVE_HDMA_D2     = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     1,       2,       0  ),  /* Enable HDMA Data 2   */
    ADI_PORTS_DIRECTIVE_HDMA_D3     = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     1,       2,       0  ),  /* Enable HDMA Data 3   */
    ADI_PORTS_DIRECTIVE_HDMA_D4     = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     1,       2,       0  ),  /* Enable HDMA Data 4   */
    ADI_PORTS_DIRECTIVE_HDMA_D5     = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     1,       2,       0  ),  /* Enable HDMA Data 5   */
    ADI_PORTS_DIRECTIVE_HDMA_D6     = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     1,       2,       0  ),  /* Enable HDMA Data 6   */
    ADI_PORTS_DIRECTIVE_HDMA_D7     = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     1,       2,       0  ),  /* Enable HDMA Data 7   */
    ADI_PORTS_DIRECTIVE_HDMA_D8     = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     1,       2,       2  ),  /* Enable HDMA Data 8   */
    ADI_PORTS_DIRECTIVE_HDMA_D9     = ADI_PORTS_CREATE_DIRECTIVE(  2,    9,     1,       2,       4  ),  /* Enable HDMA Data 9   */
    ADI_PORTS_DIRECTIVE_HDMA_D10    = ADI_PORTS_CREATE_DIRECTIVE(  2,    10,    1,       2,       4  ),  /* Enable HDMA Data 10  */
    ADI_PORTS_DIRECTIVE_HDMA_D11    = ADI_PORTS_CREATE_DIRECTIVE(  2,    11,    1,       2,       4  ),  /* Enable HDMA Data 11  */
    ADI_PORTS_DIRECTIVE_HDMA_D12    = ADI_PORTS_CREATE_DIRECTIVE(  2,    12,    1,       2,       4  ),  /* Enable HDMA Data 12  */
    ADI_PORTS_DIRECTIVE_HDMA_D13    = ADI_PORTS_CREATE_DIRECTIVE(  2,    13,    1,       2,       4  ),  /* Enable HDMA Data 13  */
    ADI_PORTS_DIRECTIVE_HDMA_D14    = ADI_PORTS_CREATE_DIRECTIVE(  2,    14,    1,       2,       4  ),  /* Enable HDMA Data 14  */
    ADI_PORTS_DIRECTIVE_HDMA_D15    = ADI_PORTS_CREATE_DIRECTIVE(  2,    15,    1,       2,       4  ),  /* Enable HDMA Data 15  */

    /* Directives to enable Timers */                          /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_TMR1_MUX0   = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     1,       0,       2  ),  /*Enable Timer 1  */
    ADI_PORTS_DIRECTIVE_TMR1_MUX2   = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     1,       2,       2  ),  /*Enable Timer 1  */
    ADI_PORTS_DIRECTIVE_TMR2        = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     1,       1,       2  ),  /*Enable Timer 2  */
    ADI_PORTS_DIRECTIVE_TMR3        = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     1,       0,       4  ),  /*Enable Timer 3  */
    ADI_PORTS_DIRECTIVE_TMR4        = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       0,       4  ),  /*Enable Timer 4  */
    ADI_PORTS_DIRECTIVE_TMR5        = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     1,       0,       6  ),  /*Enable Timer 5  */
    ADI_PORTS_DIRECTIVE_TMR6        = ADI_PORTS_CREATE_DIRECTIVE(  1,    10,    1,       0,       8  ),  /*Enable Timer 6  */
    ADI_PORTS_DIRECTIVE_TMR7_MUX0   = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    1,       0,       10 ),  /*Enable Timer 7  */
    ADI_PORTS_DIRECTIVE_TMR7_MUX1   = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    1,       1,       10 ),  /*Enable Timer 7  */

    /* External DMA Request Directives*/
    ADI_PORTS_DIRECTIVE_DMA_R1      = ADI_PORTS_CREATE_DIRECTIVE(  1,    12,    1,       0,       10 ),  /* Enable External DMA Request 1*/
    ADI_PORTS_DIRECTIVE_DMA_R0      = ADI_PORTS_CREATE_DIRECTIVE(  1,    13,    1,       0,       10 ),  /* Enable External DMA Request 0*/

    /* UART 0 on PortG Peripheral Directives */                /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_UART0G_TX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     1,       2,       4  ),  /* Enable UART 0 TX on PortG */
    ADI_PORTS_DIRECTIVE_UART0G_RX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     1,       2,       4  ),  /* Enable UART 0 RX on PortG */

    /* UART 1 on PortG Peripheral Directives */                /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_UART1G_TX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    12,    1,       1,       10 ),  /* Enable UART 1 TX on PortG */
    ADI_PORTS_DIRECTIVE_UART1G_RX    = ADI_PORTS_CREATE_DIRECTIVE(  1,    13,    1,       1,       10 ),  /* Enable UART 1 RX on PortG */

    /* UART 1 on PortF Peripheral Directives */                /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_UART1F_TX    = ADI_PORTS_CREATE_DIRECTIVE(  0,    14,    1,       2,       10 ),  /* Enable UART 1 TX on PortF */
    ADI_PORTS_DIRECTIVE_UART1F_RX    = ADI_PORTS_CREATE_DIRECTIVE(  0,    15,    1,       2,       10 ),  /* Enable UART 1 RX on PortF */

    /* Port F GPIO Directives */                               /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_PF0         = ADI_PORTS_CREATE_DIRECTIVE(  0,    0,     0,       0,       0  ),  /* Port F Flag 0    */
    ADI_PORTS_DIRECTIVE_PF1         = ADI_PORTS_CREATE_DIRECTIVE(  0,    1,     0,       0,       0  ),  /* Port F Flag 1    */
    ADI_PORTS_DIRECTIVE_PF2         = ADI_PORTS_CREATE_DIRECTIVE(  0,    2,     0,       0,       0  ),  /* Port F Flag 2    */
    ADI_PORTS_DIRECTIVE_PF3         = ADI_PORTS_CREATE_DIRECTIVE(  0,    3,     0,       0,       0  ),  /* Port F Flag 3    */
    ADI_PORTS_DIRECTIVE_PF4         = ADI_PORTS_CREATE_DIRECTIVE(  0,    4,     0,       0,       0  ),  /* Port F Flag 4    */
    ADI_PORTS_DIRECTIVE_PF5         = ADI_PORTS_CREATE_DIRECTIVE(  0,    5,     0,       0,       0  ),  /* Port F Flag 5    */
    ADI_PORTS_DIRECTIVE_PF6         = ADI_PORTS_CREATE_DIRECTIVE(  0,    6,     0,       0,       0  ),  /* Port F Flag 6    */
    ADI_PORTS_DIRECTIVE_PF7         = ADI_PORTS_CREATE_DIRECTIVE(  0,    7,     0,       0,       0  ),  /* Port F Flag 7    */
    ADI_PORTS_DIRECTIVE_PF8         = ADI_PORTS_CREATE_DIRECTIVE(  0,    8,     0,       0,       2  ),  /* Port F Flag 8    */
    ADI_PORTS_DIRECTIVE_PF9         = ADI_PORTS_CREATE_DIRECTIVE(  0,    9,     0,       0,       2  ),  /* Port F Flag 9    */
    ADI_PORTS_DIRECTIVE_PF10        = ADI_PORTS_CREATE_DIRECTIVE(  0,    10,    0,       0,       4  ),  /* Port F Flag 10   */
    ADI_PORTS_DIRECTIVE_PF11        = ADI_PORTS_CREATE_DIRECTIVE(  0,    11,    0,       0,       6  ),  /* Port F Flag 11   */
    ADI_PORTS_DIRECTIVE_PF12        = ADI_PORTS_CREATE_DIRECTIVE(  0,    12,    0,       0,       8  ),  /* Port F Flag 12   */
    ADI_PORTS_DIRECTIVE_PF13        = ADI_PORTS_CREATE_DIRECTIVE(  0,    13,    0,       0,       8  ),  /* Port F Flag 13   */
    ADI_PORTS_DIRECTIVE_PF14        = ADI_PORTS_CREATE_DIRECTIVE(  0,    14,    0,       0,       10 ),  /* Port F Flag 14   */
    ADI_PORTS_DIRECTIVE_PF15        = ADI_PORTS_CREATE_DIRECTIVE(  0,    15,    0,       0,       10 ),  /* Port F Flag 15   */

    /* Port G GPIO Directives */                               /* Port, Bit, Function, MuxVal, MuxPos */
    /* Note: PG0 is hardwired as HWAIT and not configurabble */
    ADI_PORTS_DIRECTIVE_PG1         = ADI_PORTS_CREATE_DIRECTIVE(  1,    1,     0,       0,       0  ),  /* Port G Flag 1    */
    ADI_PORTS_DIRECTIVE_PG2         = ADI_PORTS_CREATE_DIRECTIVE(  1,    2,     0,       0,       0  ),  /* Port G Flag 2    */
    ADI_PORTS_DIRECTIVE_PG3         = ADI_PORTS_CREATE_DIRECTIVE(  1,    3,     0,       0,       0  ),  /* Port G Flag 3    */
    ADI_PORTS_DIRECTIVE_PG4         = ADI_PORTS_CREATE_DIRECTIVE(  1,    4,     0,       0,       0  ),  /* Port G Flag 4    */
    ADI_PORTS_DIRECTIVE_PG5         = ADI_PORTS_CREATE_DIRECTIVE(  1,    5,     0,       0,       2  ),  /* Port G Flag 5    */
    ADI_PORTS_DIRECTIVE_PG6         = ADI_PORTS_CREATE_DIRECTIVE(  1,    6,     0,       0,       2  ),  /* Port G Flag 6    */
    ADI_PORTS_DIRECTIVE_PG7         = ADI_PORTS_CREATE_DIRECTIVE(  1,    7,     0,       0,       4  ),  /* Port G Flag 7    */
    ADI_PORTS_DIRECTIVE_PG8         = ADI_PORTS_CREATE_DIRECTIVE(  1,    8,     0,       0,       4  ),  /* Port G Flag 8    */
    ADI_PORTS_DIRECTIVE_PG9         = ADI_PORTS_CREATE_DIRECTIVE(  1,    9,     0,       0,       6  ),  /* Port G Flag 9    */
    ADI_PORTS_DIRECTIVE_PG10        = ADI_PORTS_CREATE_DIRECTIVE(  1,    10,    0,       0,       8  ),  /* Port G Flag 10   */
    ADI_PORTS_DIRECTIVE_PG11        = ADI_PORTS_CREATE_DIRECTIVE(  1,    11,    0,       0,       10 ),  /* Port G Flag 11   */
    ADI_PORTS_DIRECTIVE_PG12        = ADI_PORTS_CREATE_DIRECTIVE(  1,    12,    0,       0,       10 ),  /* Port G Flag 12   */
    ADI_PORTS_DIRECTIVE_PG13        = ADI_PORTS_CREATE_DIRECTIVE(  1,    13,    0,       0,       10 ),  /* Port G Flag 13   */
    ADI_PORTS_DIRECTIVE_PG14        = ADI_PORTS_CREATE_DIRECTIVE(  1,    14,    0,       0,       12 ),  /* Port G Flag 14   */
    ADI_PORTS_DIRECTIVE_PG15        = ADI_PORTS_CREATE_DIRECTIVE(  1,    15,    0,       0,       12 ),  /* Port G Flag 15   */

    /* Port H GPIO Directives */                               /* Port, Bit, Function, MuxVal, MuxPos */
    ADI_PORTS_DIRECTIVE_PH0         = ADI_PORTS_CREATE_DIRECTIVE(  2,    0,     0,       0,       0  ),  /* Port H Flag 0    */
    ADI_PORTS_DIRECTIVE_PH1         = ADI_PORTS_CREATE_DIRECTIVE(  2,    1,     0,       0,       0  ),  /* Port H Flag 1    */
    ADI_PORTS_DIRECTIVE_PH2         = ADI_PORTS_CREATE_DIRECTIVE(  2,    2,     0,       0,       0  ),  /* Port H Flag 2    */
    ADI_PORTS_DIRECTIVE_PH3         = ADI_PORTS_CREATE_DIRECTIVE(  2,    3,     0,       0,       0  ),  /* Port H Flag 3    */
    ADI_PORTS_DIRECTIVE_PH4         = ADI_PORTS_CREATE_DIRECTIVE(  2,    4,     0,       0,       0  ),  /* Port H Flag 4    */
    ADI_PORTS_DIRECTIVE_PH5         = ADI_PORTS_CREATE_DIRECTIVE(  2,    5,     0,       0,       0  ),  /* Port H Flag 5    */
    ADI_PORTS_DIRECTIVE_PH6         = ADI_PORTS_CREATE_DIRECTIVE(  2,    6,     0,       0,       0  ),  /* Port H Flag 6    */
    ADI_PORTS_DIRECTIVE_PH7         = ADI_PORTS_CREATE_DIRECTIVE(  2,    7,     0,       0,       0  ),  /* Port H Flag 7    */
    ADI_PORTS_DIRECTIVE_PH8         = ADI_PORTS_CREATE_DIRECTIVE(  2,    8,     0,       0,       2  ),  /* Port H Flag 8    */
    ADI_PORTS_DIRECTIVE_PH9         = ADI_PORTS_CREATE_DIRECTIVE(  2,    9,     0,       0,       4  ),  /* Port H Flag 9    */
    ADI_PORTS_DIRECTIVE_PH10        = ADI_PORTS_CREATE_DIRECTIVE(  2,    10,    0,       0,       4  ),  /* Port H Flag 10   */
    ADI_PORTS_DIRECTIVE_PH11        = ADI_PORTS_CREATE_DIRECTIVE(  2,    11,    0,       0,       4  ),  /* Port H Flag 11   */
    ADI_PORTS_DIRECTIVE_PH12        = ADI_PORTS_CREATE_DIRECTIVE(  2,    12,    0,       0,       4  ),  /* Port H Flag 12   */
    ADI_PORTS_DIRECTIVE_PH13        = ADI_PORTS_CREATE_DIRECTIVE(  2,    13,    0,       0,       4  ),  /* Port H Flag 13   */
    ADI_PORTS_DIRECTIVE_PH14        = ADI_PORTS_CREATE_DIRECTIVE(  2,    14,    0,       0,       4  ),  /* Port H Flag 13   */
    ADI_PORTS_DIRECTIVE_PH15        = ADI_PORTS_CREATE_DIRECTIVE(  2,    15,    0,       0,       4  )   /* Port H Flag 13   */

    /* Port J does not provide GPIO functionality... */

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
