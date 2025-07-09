/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$Revision: 3682 $
$Date: 2010-11-01 16:56:32 -0400 (Mon, 01 Nov 2010) $

Description:
            Disable misra diagnostics as necessary.

*********************************************************************************/
#ifdef _MISRA_RULES

#if !defined(_LANGUAGE_ASM)

#pragma diag(suppress:misra_rule_5_1:"ADI header uses long identifier names")
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header uses basic types")

#pragma diag(suppress:misra_rule_1_1:"enumeration list with trailing comma")
#pragma diag(suppress:misra_rule_2_2:"ADI header uses C++ style comments")
#pragma diag(suppress:misra_rule_8_8:"ADI header declares remove with different linkage name")
#pragma diag(suppress:misra_rule_9_3:"ADI header initial enum constants have initialized values")
#pragma diag(suppress:misra_rule_19_10:"ADI header parameter of function macros not required to be parenthesised")
#pragma diag(suppress:misra_rule_16_3:"ADI header prototype does not specify parameter name")
#pragma diag(suppress:misra_rule_20_1:"ADI Header defines NULL")


/* Unavoidable Misra Suppressions: */
#pragma diag(suppress:misra_rule_2_4:"ADI header comment has code-like sequence")
#pragma diag(suppress:misra_rule_6_4:"ADI header uses short bit fields")
#pragma diag(suppress:misra_rule_10_5:"ADI header use of constants in shift")
#pragma diag(suppress:misra_rule_12_8:"ADI header use of constants in shift")
#pragma diag(suppress:misra_rule_18_4:"ADI header requires use of unions")
#pragma diag(suppress:misra_rule_19_1:"ADI header uses include later")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any macro substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header requires function macros")
#pragma diag(suppress:misra_rule_20_2:"ADI header declares standard library names ")

#pragma diag(suppress:misra_rule_4_2:"ADI header uses a trigraph")
#pragma diag(suppress:misra_rule_8_2:"ADI header uses inline void function declaration") /* Suppression for device drivers */
#pragma diag(suppress:misra_rule_8_5:"ADI header may define functions and objects") /* Suppression for device drivers */
#pragma diag(suppress:misra_rule_8_10:"ADI header declarations/definitions do not all have internal linkage where/when external linkage is not required")       /* Suppression for device drivers */
#pragma diag(suppress:misra_rule_10_1_a:"ADI header uses implicit integer conversion to a different underlying type that is not of a wider integer type of the same signedness")
#pragma diag(suppress:misra_rule_12_7:"ADI header applies bit wise operators to operands whose underlying type is signed")
#pragma diag(suppress:misra_rule_18_1:"ADI header has structure or union type definitions that are not complete at the end of a translation unit")
#pragma diag(suppress:misra_rule_19_2:"ADI header uses non-standard characters in #include header file names")      /* Suppression for device drivers */
#pragma diag(suppress:misra_rule_19_11:"ADI header may use a macro before definition ") /* Suppression for device drivers */
#pragma diag(suppress:misra_rule_19_13:"ADI header use the # and ## pre-processor operators") /* Suppression for device drivers */
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#pragma diag(suppress:misra_rule_20_9:"ADI header includes stio.h in production code") /* Suppression for device drivers */

#endif /* _LANGUAGE_ASM */

#endif /* _MISRA_RULES */
