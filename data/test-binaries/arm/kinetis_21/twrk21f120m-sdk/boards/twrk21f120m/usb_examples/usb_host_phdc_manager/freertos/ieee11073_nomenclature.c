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

#include "usb_host_config.h"
#include "usb_host.h"
#include "usb.h"
#include "ieee11073_types.h"
#include "ieee11073_nomenclature.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#if defined(__ICCARM__)
#define _INT8_P_CASTING_
#else
#define _INT8_P_CASTING_ (int8_t *)
#endif

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* Nomenclature ascii table */
const nomenclature_ascii_struct_t g_nomenclatureAsciiTable[] = {
    {MDC_ATTRIBUTE_ID_TYPE, _INT8_P_CASTING_ "ID type"},
    {MDC_ATTRIBUTE_METRIC_SPECIFICATION_SMALL, _INT8_P_CASTING_ "Small metric specification "},
    {MDC_ATTRIBUTE_UNIT_CODE, _INT8_P_CASTING_ "Unit code"},
    {MDC_ATTRIBUTE_VALUE_MAP, _INT8_P_CASTING_ "Value map"},
    {MDC_MASS_BODY_ACTUAL, _INT8_P_CASTING_ "Body Weight"},
    {MDC_LENGTH_BODY_ACTUAL, _INT8_P_CASTING_ "Body Length"},
    {MDC_RATIO_MASS_BODY_LENGTH_SQUARE, _INT8_P_CASTING_ "BMI"},
    {MDC_DIM_PERCENT, _INT8_P_CASTING_ "%"},
    {MDC_DIM_KILOGRAM, _INT8_P_CASTING_ "kg"},
    {MDC_DIM_MINUTE, _INT8_P_CASTING_ "min"},
    {MDC_DIM_HOUR, _INT8_P_CASTING_ "h"},
    {MDC_DIM_DAY, _INT8_P_CASTING_ "d"},
    {MDC_DIM_DEGREE_C, _INT8_P_CASTING_ "degrC"},
    {MDC_DIM_KG_PER_M_SQUARE, _INT8_P_CASTING_ "kg/m2"}};

/* Nomenclature partition table */
const partition_ascii_struct_t g_partitionAsciiTable[] = {
    {MDC_PARTITION_OBJECT, _INT8_P_CASTING_ "Object Infrastructure"},
    {MDC_PARTITION_SCADA, _INT8_P_CASTING_ "SCADA"},
    {MDC_PARTITION_DIMENSION, _INT8_P_CASTING_ "Dimension"},
    {MDC_PARTITION_INFRASTRUCTURE, _INT8_P_CASTING_ "Infrastructure"},
    {MDC_PARTITION_PHD_DISEASE_MANAGEMENT, _INT8_P_CASTING_ "Disease Mgmt"},
    {MDC_PARTITION_PHD_HEALTH_FITNESS, _INT8_P_CASTING_ "H&F Set"},
    {MDC_PARTITION_PHD_AGING_INDEPENDENTLY, _INT8_P_CASTING_ "Aging Independently"},
    {MDC_PARTITION_RETURN_CODE, _INT8_P_CASTING_ "Return Codes"},
    {MDC_PARTITION_EXTERNAL_NOMENCLATURE, _INT8_P_CASTING_ "Ext. Nomenclature"}};

const uint16_t g_nomAsciiCount = sizeof(g_nomenclatureAsciiTable) / sizeof(g_nomenclatureAsciiTable[0U]);
const uint16_t g_partitionAsciiCount = sizeof(g_partitionAsciiTable) / sizeof(g_partitionAsciiTable[0U]);
