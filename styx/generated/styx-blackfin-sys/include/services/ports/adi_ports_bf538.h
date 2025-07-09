/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            Port control service for the Stirling family of Blackfin processors

*********************************************************************************/

#ifndef __ADI_PORTS_H__
#define __ADI_PORTS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)


#if !defined(__ADSP_STIRLING__)
#error "PORTS module not supported for the current processor family"
#endif


/**********************************************************************

Example:

Enable the pins for PC0, PC1, PC2, CTX, CRX and MRX

{
    ADI_PORTS_DIRECTIVE Directives[] = {
        ADI_PORTS_DIRECTIVE_PC0,
        ADI_PORTS_DIRECTIVE_PC1,
        ADI_PORTS_DIRECTIVE_PC2,
        ADI_PORTS_DIRECTIVE_CTX,
        ADI_PORTS_DIRECTIVE_CRX,
        ADI_PORTS_DIRECTIVE_MRX
    };

    adi_ports_Configure(Directives, (sizeof(Directives)/sizeof(Directives[0]));
}

**********************************************************************/



/*********************************************************************
Various macros used by port control

Application code does not use these macros but rather are used by the
port service to control the ports

Directive enumerations are concatenations of several pieces of information
for the port. A directive ID enumerator consists of:

    o bit 0-7   - port index
    o bit 8-15  - bit position within the port control register for the given pin
    o bit 16-23 - value for the bit
    o bit 24-31 - not used

Macros are provided to create the actual directive enumerators and to
extract each of the fields within the value.

*********************************************************************/

// macro to create the directive
#define ADI_PORTS_CREATE_DIRECTIVE(Position,Value,Port)    (((Value) << 16) | ((Position) << 8) | ((Port)))

// macros to get the individual field values
#define ADI_PORTS_GET_PORT(Directive)           (((u32)Directive) & 0xff)
#define ADI_PORTS_GET_BIT_POSITION(Directive)   ((((u32)Directive) >> 8) & 0xff)
#define ADI_PORTS_GET_BIT_VALUE(Directive)      ((((u32)Directive) >> 16) & 0xff)


// macro to create a mask that can be used for the port register
#define ADI_PORTS_GET_MASK(Directive)   (1 << ADI_PORTS_GET_BIT_POSITION(Directive))



/*********************************************************************

Directives

These directives are used by the drivers and services to configure the
pin muxing logic as appropriate.

*********************************************************************/

typedef enum ADI_PORTS_DIRECTIVE {

    ADI_PORTS_DIRECTIVE_PC0     = ADI_PORTS_CREATE_DIRECTIVE(0,  1, 0), // port c flag0
    ADI_PORTS_DIRECTIVE_PC1     = ADI_PORTS_CREATE_DIRECTIVE(1,  1, 0), // port c flag1
    ADI_PORTS_DIRECTIVE_PC2     = ADI_PORTS_CREATE_DIRECTIVE(2,  0, 0), // port c flag2 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC3     = ADI_PORTS_CREATE_DIRECTIVE(3,  0, 0), // port c flag3 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC4     = ADI_PORTS_CREATE_DIRECTIVE(4,  1, 0), // port c flag4
    ADI_PORTS_DIRECTIVE_PC5     = ADI_PORTS_CREATE_DIRECTIVE(5,  1, 0), // port c flag5
    ADI_PORTS_DIRECTIVE_PC6     = ADI_PORTS_CREATE_DIRECTIVE(6,  1, 0), // port c flag6
    ADI_PORTS_DIRECTIVE_PC7     = ADI_PORTS_CREATE_DIRECTIVE(7,  1, 0), // port c flag7
    ADI_PORTS_DIRECTIVE_PC8     = ADI_PORTS_CREATE_DIRECTIVE(8,  1, 0), // port c flag8
    ADI_PORTS_DIRECTIVE_PC9     = ADI_PORTS_CREATE_DIRECTIVE(9,  1, 0), // port c flag9
    ADI_PORTS_DIRECTIVE_PC10    = ADI_PORTS_CREATE_DIRECTIVE(10, 0, 0), // port c flag10 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC11    = ADI_PORTS_CREATE_DIRECTIVE(11, 0, 0), // port c flag11 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC12    = ADI_PORTS_CREATE_DIRECTIVE(12, 0, 0), // port c flag12 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC13    = ADI_PORTS_CREATE_DIRECTIVE(13, 0, 0), // port c flag13 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC14    = ADI_PORTS_CREATE_DIRECTIVE(14, 0, 0), // port c flag14 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PC15    = ADI_PORTS_CREATE_DIRECTIVE(15, 0, 0), // port c flag15 (not used by peripheral)

    ADI_PORTS_DIRECTIVE_PD0     = ADI_PORTS_CREATE_DIRECTIVE(0,  1, 1), // port d flag0
    ADI_PORTS_DIRECTIVE_PD1     = ADI_PORTS_CREATE_DIRECTIVE(1,  1, 1), // port d flag1
    ADI_PORTS_DIRECTIVE_PD2     = ADI_PORTS_CREATE_DIRECTIVE(2,  1, 1), // port d flag2
    ADI_PORTS_DIRECTIVE_PD3     = ADI_PORTS_CREATE_DIRECTIVE(3,  1, 1), // port d flag3
    ADI_PORTS_DIRECTIVE_PD4     = ADI_PORTS_CREATE_DIRECTIVE(4,  1, 1), // port d flag4
    ADI_PORTS_DIRECTIVE_PD5     = ADI_PORTS_CREATE_DIRECTIVE(5,  1, 1), // port d flag5
    ADI_PORTS_DIRECTIVE_PD6     = ADI_PORTS_CREATE_DIRECTIVE(6,  1, 1), // port d flag6
    ADI_PORTS_DIRECTIVE_PD7     = ADI_PORTS_CREATE_DIRECTIVE(7,  1, 1), // port d flag7
    ADI_PORTS_DIRECTIVE_PD8     = ADI_PORTS_CREATE_DIRECTIVE(8,  1, 1), // port d flag8
    ADI_PORTS_DIRECTIVE_PD9     = ADI_PORTS_CREATE_DIRECTIVE(9,  1, 1), // port d flag9
    ADI_PORTS_DIRECTIVE_PD10    = ADI_PORTS_CREATE_DIRECTIVE(10, 1, 1), // port d flag10
    ADI_PORTS_DIRECTIVE_PD11    = ADI_PORTS_CREATE_DIRECTIVE(11, 1, 1), // port d flag11
    ADI_PORTS_DIRECTIVE_PD12    = ADI_PORTS_CREATE_DIRECTIVE(12, 1, 1), // port d flag12
    ADI_PORTS_DIRECTIVE_PD13    = ADI_PORTS_CREATE_DIRECTIVE(13, 1, 1), // port d flag13
    ADI_PORTS_DIRECTIVE_PD14    = ADI_PORTS_CREATE_DIRECTIVE(14, 0, 1), // port d flag14 (not used by peripheral)
    ADI_PORTS_DIRECTIVE_PD15    = ADI_PORTS_CREATE_DIRECTIVE(15, 0, 1), // port d flag15 (not used by peripheral)

    ADI_PORTS_DIRECTIVE_PE0     = ADI_PORTS_CREATE_DIRECTIVE(0,  1, 2), // port e flag0
    ADI_PORTS_DIRECTIVE_PE1     = ADI_PORTS_CREATE_DIRECTIVE(1,  1, 2), // port e flag1
    ADI_PORTS_DIRECTIVE_PE2     = ADI_PORTS_CREATE_DIRECTIVE(2,  1, 2), // port e flag2
    ADI_PORTS_DIRECTIVE_PE3     = ADI_PORTS_CREATE_DIRECTIVE(3,  1, 2), // port e flag3
    ADI_PORTS_DIRECTIVE_PE4     = ADI_PORTS_CREATE_DIRECTIVE(4,  1, 2), // port e flag4
    ADI_PORTS_DIRECTIVE_PE5     = ADI_PORTS_CREATE_DIRECTIVE(5,  1, 2), // port e flag5
    ADI_PORTS_DIRECTIVE_PE6     = ADI_PORTS_CREATE_DIRECTIVE(6,  1, 2), // port e flag6
    ADI_PORTS_DIRECTIVE_PE7     = ADI_PORTS_CREATE_DIRECTIVE(7,  1, 2), // port e flag7
    ADI_PORTS_DIRECTIVE_PE8     = ADI_PORTS_CREATE_DIRECTIVE(8,  1, 2), // port e flag8
    ADI_PORTS_DIRECTIVE_PE9     = ADI_PORTS_CREATE_DIRECTIVE(9,  1, 2), // port e flag9
    ADI_PORTS_DIRECTIVE_PE10    = ADI_PORTS_CREATE_DIRECTIVE(10, 1, 2), // port e flag10
    ADI_PORTS_DIRECTIVE_PE11    = ADI_PORTS_CREATE_DIRECTIVE(11, 1, 2), // port e flag11
    ADI_PORTS_DIRECTIVE_PE12    = ADI_PORTS_CREATE_DIRECTIVE(12, 1, 2), // port e flag12
    ADI_PORTS_DIRECTIVE_PE13    = ADI_PORTS_CREATE_DIRECTIVE(13, 1, 2), // port e flag13
    ADI_PORTS_DIRECTIVE_PE14    = ADI_PORTS_CREATE_DIRECTIVE(14, 1, 2), // port e flag14
    ADI_PORTS_DIRECTIVE_PE15    = ADI_PORTS_CREATE_DIRECTIVE(15, 1, 2), // port e flag15

    ADI_PORTS_DIRECTIVE_CTX     = ADI_PORTS_CREATE_DIRECTIVE(0,  0, 0), // port c CAN transmit             (flag0)
    ADI_PORTS_DIRECTIVE_CRX     = ADI_PORTS_CREATE_DIRECTIVE(1,  0, 0), // port c CAN receive              (flag1)
    ADI_PORTS_DIRECTIVE_MRX     = ADI_PORTS_CREATE_DIRECTIVE(4,  0, 0), // port c MXVR receive             (flag4)
    ADI_PORTS_DIRECTIVE_MTX     = ADI_PORTS_CREATE_DIRECTIVE(5,  0, 0), // port c MXVR transmit            (flag5)
    ADI_PORTS_DIRECTIVE_MMCLK   = ADI_PORTS_CREATE_DIRECTIVE(6,  0, 0), // port c MXVR master clock 0      (flag6)
    ADI_PORTS_DIRECTIVE_MBCLK   = ADI_PORTS_CREATE_DIRECTIVE(7,  0, 0), // port c MXVR bit clock 1         (flag7)
    ADI_PORTS_DIRECTIVE_MFS     = ADI_PORTS_CREATE_DIRECTIVE(8,  0, 0), // port c MXVR recovered clock 2   (flag8)
    ADI_PORTS_DIRECTIVE_MTXON   = ADI_PORTS_CREATE_DIRECTIVE(9,  0, 0), // port c MXVR transmit FOT enable (flag9)

    ADI_PORTS_DIRECTIVE_MOSI1   = ADI_PORTS_CREATE_DIRECTIVE(0,  0, 1), // port d SPI1 master out slave in (flag0)
    ADI_PORTS_DIRECTIVE_MISO1   = ADI_PORTS_CREATE_DIRECTIVE(1,  0, 1), // port d SPI1 master in slave out (flag1)
    ADI_PORTS_DIRECTIVE_SCK1    = ADI_PORTS_CREATE_DIRECTIVE(2,  0, 1), // port d SPI1 clock               (flag2)
    ADI_PORTS_DIRECTIVE_SPI1SS  = ADI_PORTS_CREATE_DIRECTIVE(3,  0, 1), // port d SPI1 slave select input  (flag3)
    ADI_PORTS_DIRECTIVE_SPI1SEL = ADI_PORTS_CREATE_DIRECTIVE(4,  0, 1), // port d SPI1 slave select enable (flag4)
    ADI_PORTS_DIRECTIVE_MOSI2   = ADI_PORTS_CREATE_DIRECTIVE(5,  0, 1), // port d SPI2 master out slave in (flag5)
    ADI_PORTS_DIRECTIVE_MISO2   = ADI_PORTS_CREATE_DIRECTIVE(6,  0, 1), // port d SPI2 master in slave out (flag6)
    ADI_PORTS_DIRECTIVE_SCK2    = ADI_PORTS_CREATE_DIRECTIVE(7,  0, 1), // port d SPI2 clock               (flag7)
    ADI_PORTS_DIRECTIVE_SPI2SS  = ADI_PORTS_CREATE_DIRECTIVE(8,  0, 1), // port d SPI2 slave select input  (flag8)
    ADI_PORTS_DIRECTIVE_SPI2SEL = ADI_PORTS_CREATE_DIRECTIVE(9,  0, 1), // port d SPI2 slave select enable (flag9)
    ADI_PORTS_DIRECTIVE_RX1     = ADI_PORTS_CREATE_DIRECTIVE(10, 0, 1), // port d UART1 receive            (flag10)
    ADI_PORTS_DIRECTIVE_TX1     = ADI_PORTS_CREATE_DIRECTIVE(11, 0, 1), // port d UART1 transmit           (flag11)
    ADI_PORTS_DIRECTIVE_RX2     = ADI_PORTS_CREATE_DIRECTIVE(12, 0, 1), // port d UART2 receive            (flag12)
    ADI_PORTS_DIRECTIVE_TX2     = ADI_PORTS_CREATE_DIRECTIVE(13, 0, 1), // port d UART2 transmit           (flag13)

    ADI_PORTS_DIRECTIVE_RSCLK2  = ADI_PORTS_CREATE_DIRECTIVE(0,  0, 2), // port e SPORT2 rx serial clock   (flag0)
    ADI_PORTS_DIRECTIVE_RFS2    = ADI_PORTS_CREATE_DIRECTIVE(1,  0, 2), // port e SPORT2 rx frame sync     (flag1)
    ADI_PORTS_DIRECTIVE_DR2PRI  = ADI_PORTS_CREATE_DIRECTIVE(2,  0, 2), // port e SPORT2 rx data primary   (flag2)
    ADI_PORTS_DIRECTIVE_DR2SEC  = ADI_PORTS_CREATE_DIRECTIVE(3,  0, 2), // port e SPORT2 rx data secondary (flag3)
    ADI_PORTS_DIRECTIVE_TSCLK2  = ADI_PORTS_CREATE_DIRECTIVE(4,  0, 2), // port e SPORT2 tx serial clock   (flag4)
    ADI_PORTS_DIRECTIVE_TFS2    = ADI_PORTS_CREATE_DIRECTIVE(5,  0, 2), // port e SPORT2 tx frame sync     (flag5)
    ADI_PORTS_DIRECTIVE_DT2PRI  = ADI_PORTS_CREATE_DIRECTIVE(6,  0, 2), // port e SPORT2 tx data primary   (flag6)
    ADI_PORTS_DIRECTIVE_DT2SEC  = ADI_PORTS_CREATE_DIRECTIVE(7,  0, 2), // port e SPORT2 tx data secondary (flag7)
    ADI_PORTS_DIRECTIVE_RSCLK3  = ADI_PORTS_CREATE_DIRECTIVE(8,  0, 2), // port e SPORT3 rx serial clock   (flag8)
    ADI_PORTS_DIRECTIVE_RFS3    = ADI_PORTS_CREATE_DIRECTIVE(9,  0, 2), // port e SPORT3 rx frame sync     (flag9)
    ADI_PORTS_DIRECTIVE_DR3PRI  = ADI_PORTS_CREATE_DIRECTIVE(10, 0, 2), // port e SPORT3 rx data primary   (flag10)
    ADI_PORTS_DIRECTIVE_DR3SEC  = ADI_PORTS_CREATE_DIRECTIVE(11, 0, 2), // port e SPORT3 rx data secondary (flag11)
    ADI_PORTS_DIRECTIVE_TSCLK3  = ADI_PORTS_CREATE_DIRECTIVE(12, 0, 2), // port e SPORT3 tx serial clock   (flag12)
    ADI_PORTS_DIRECTIVE_TFS3    = ADI_PORTS_CREATE_DIRECTIVE(13, 0, 2), // port e SPORT3 tx frame sync     (flag13)
    ADI_PORTS_DIRECTIVE_DT3PRI  = ADI_PORTS_CREATE_DIRECTIVE(14, 0, 2), // port e SPORT3 tx data primary   (flag14)
    ADI_PORTS_DIRECTIVE_DT3SEC  = ADI_PORTS_CREATE_DIRECTIVE(15, 0, 2)  // port e SPORT3 tx data secondary (flag15)

} ADI_PORTS_DIRECTIVE;



/*********************************************************************

Return codes

*********************************************************************/

typedef enum ADI_PORTS_RESULT {
    ADI_PORTS_RESULT_SUCCESS=0,                         // Generic success
    ADI_PORTS_RESULT_FAILED=1,                          // Generic failure

    ADI_PORTS_RESULT_START=ADI_PORTS_ENUMERATION_START, // insure this order remains
    ADI_PORTS_RESULT_BAD_DIRECTIVE                      // (0x90001) A directive is invalid for the specified peripheral
} ADI_PORTS_RESULT;




/*********************************************************************

API Functions

*********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


ADI_PORTS_RESULT
adi_ports_Init(             // initializes the ports service
    void    *pCriticalRegionArg             // parameter for critical region function
);

ADI_PORTS_RESULT
adi_ports_Terminate(            // terminates the Ports service
    void
);


ADI_PORTS_RESULT
adi_ports_Configure(        // enables an array of pins
    ADI_PORTS_DIRECTIVE *pDirectives,   // array of directives
    u32                 nDirectives     // number of directives
);

#ifdef __cplusplus
}
#endif




#endif // Not ASM

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_PORTS_H__ */
