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

#ifndef _IEEE11073_NOMENCLATURE_
#define _IEEE11073_NOMENCLATURE_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief Medical Partition codes */
#define MDC_PARTITION_OBJECT (1U)         /*!< Medical partition object */
#define MDC_PARTITION_SCADA (2U)          /*!< Medical partition SCADA */
#define MDC_PARTITION_DIMENSION (4U)      /*!< Medical partition dimension */
#define MDC_PARTITION_INFRASTRUCTURE (8U) /*!< Medical partition infrastructure */
#define MDC_PARTITION_PHD_DISEASE_MANAGEMENT                                            \
    (128U) /*!< Medical partition personal health device disease management */
#define MDC_PARTITION_PHD_HEALTH_FITNESS (129U) /*!< Medical partition personal health device health and fitness */
#define MDC_PARTITION_PHD_AGING_INDEPENDENTLY \
    (130U)                               /*!< Medical partition personal health device aging and independently */
#define MDC_PARTITION_RETURN_CODE (255U) /*!< Medical partition return code */
#define MDC_PARTITION_EXTERNAL_NOMENCLATURE (256U) /*!< Medical partition external nomenclature */

/*! @brief Virtual Medical Class */
#define MDC_MOC_VMO_METRIC (4U)                        /*!< Virtual Medical Base class */
#define MDC_MOC_VMO_METRIC_ENUMERATION (5U)            /*!< Virtual Medical Enumeration class */
#define MDC_MOC_VMO_METRIC_NUMERIC (6U)                /*!< Virtual Medical Numeric class */
#define MDC_MOC_VMO_METRIC_REAL_TIME_SAMPLE_ARRAY (9U) /*!< Virtual Medical Real Time Sample Array class */

/*! @brief Scanner class */
#define MDC_MOC_SCANNER (16U)                       /*!< Scanner class */
#define MDC_MOC_SCANNER_CONFIGURABLE (17U)          /*!< Scanner configurable class */
#define MDC_MOC_SCANNER_CONFIGURABLE_EPISODIC (18U) /*!< Scanner episodic configurable class */
#define MDC_MOC_SCANNER_CONFIGURABLE_PERIODIC (19U) /*!< Scanner periodic configurable class */

/*! @brief Scanner attributes */
#define MDC_ATTRIBUTE_SCANNER_HANDLE_LIST (2679U)           /*!< Scan handle list */
#define MDC_ATTRIBUTE_SCANNER_HANDLE_ATTR_VALUE_MAP (2643U) /*!< Scan handle attribute value map */

/*! @brief Configurable scanner attributes */
#define MDC_ATTRIBUTE_CONFIRM_MODE (2323U) /*!< Event reports are confirmed */

#define MDC_ATTRIBUTE_TX_WIND (2453U) /*!< Transmit Window */

/*! @brief Virtual medical system - Medical device system */
#define MDC_MOC_VMS_MDS_SIMPLE (37U)

/*! @brief Persistently Measurement class */
#define MDC_MOC_VMO_PM_STORE (61U) /*!< PM store class */
#define MDC_MOC_PM_SEGMENT (62U)   /*!< PM segment class */

/*! @brief Medical Device System Attributes */
#define MDC_ATTRIBUTE_ID_HANDLE (2337U)        /*!< MDS handle atrribute, shall be 0 */
#define MDC_ATTRIBUTE_SYSTEM_TYPE (2438U)      /*!< Type of the Agent device */
#define MDC_ATTRIBUTE_ID_MODEL (2344U)         /*!< Manufacturer and model number of the Agent device */
#define MDC_ATTRIBUTE_SYS_ID (2436U)           /*!< IEEE extended unique identifier*/
#define MDC_ATTRIBUTE_DEVICE_CONFIG_ID (2628U) /*!< Agent device configuration ID */
#define MDC_ATTRIBUTE_VALUE_MAP (2645U)        /*!< Define the attributes that are reported in fixed format message */
#define MDC_ATTRIBUTE_ID_PRODUCT_SPECIFICATION (2349U)           /*!< Product specification */
#define MDC_ATTRIBUTE_MDS_TIME_INFORMATION (2629U)               /*!< MDS time information */
#define MDC_ATTRIBUTE_TIME_ABSOLUTE (2439U)                      /*!< MDS absolute time */
#define MDC_ATTRIBUTE_TIME_RELATIVE (2447U)                      /*!< MDS relative time */
#define MDC_ATTRIBUTE_TIME_RELATIVE_HIGH_RESPONSE (2536U)        /*!< MDS high response relative time */
#define MDC_ATTRIBUTE_TIME_ABSOLUTE_ADJUST (2658U)               /*!< Data and time adjustment */
#define MDC_ATTRIBUTE_POWER_STATUS (2389U)                       /*!< Power status */
#define MDC_ATTRIBUTE_VALUE_BATTERY_CHARGE (2460U)               /*!< Battery level */
#define MDC_ATTRIBUTE_TIME_BATTERY_REMAIN (2440U)                /*!< Remaining battery time */
#define MDC_ATTRIBUTE_REGULATORY_CERTIFICATION_DATA_LIST (2635U) /*!< Regulatory and certification data list */
#define MDC_ATTRIBUTE_SYSTEM_TYPE_SPECIFICATION_LIST (2650U)     /*!< System type specification list */
#define MDC_ATTRIBUTE_CONFIRM_TIMEOUT                                            \
    (2324U) /*!< Defines the minimums time that the agent shall wait \
                for a response message from manager */

/*! @brief PM Segment attributes */
#define MDC_ATTRIBUTE_ID_INSTANCE_NUMBER (2338U)          /*!< Instance number */
#define MDC_ATTRIBUTE_PM_SEGMENT_ENTRY_MAP (2638U)        /*!< PM segment entry map */
#define MDC_ATTRIBUTE_PM_SEGMENT_PERSON_ID (2639U)        /*!< PM segment person ID */
#define MDC_ATTRIBUTE_OPERATION_STATE (2387U)             /*!< Operation state */
#define MDC_ATTRIBUTE_PM_SEGMENT_LABEL (2648U)            /*!< PM segment label */
#define MDC_ATTRIBUTE_TIME_SEGMENT_START_ABSOLUTE (2450U) /*!< Segment start absolute time */
#define MDC_ATTRIBUTE_TIME_SEGMENT_END_ABSOLUTE (2442U)   /*!< Segment end absolute time */
#define MDC_ATTRIBUTE_SEGMENT_USAGE_COUNT (2427U)         /*!< Segment usage count */
#define MDC_ATTRIBUTE_SEGMENT_STATISTICS (2640U)          /*!< Segment statistics */
#define MDC_ATTRIBUTE_SEGMENT_FIXED_DATA (2641U)          /*!< Fixed segment data */
#define MDC_ATTRIBUTE_PM_SEGMENT_ELEM_STAT_ATTR (2642U)   /*!< PM segment element status */
#define MDC_ATTRIBUTE_TRANSFER_TIMEOUT (2660U)            /*!< Transfer timeout */

/*! @brief Metric attributes */
#define MDC_ATTRIBUTE_ID_TYPE (2351U)                           /*!< Attribute ID type */
#define MDC_ATTRIBUTE_SUPPLEMENTAL_TYPES (2657U)                /*!< Supplemental type */
#define MDC_ATTRIBUTE_METRIC_SPECIFICATION_SMALL (2630U)        /*!< Metric specification small */
#define MDC_ATTRIBUTE_METRIC_STRUCTURE_SMALL (2675U)            /*!< Metric structure small */
#define MDC_ATTRIBUTE_MEASUREMENT_STATUS (2375U)                /*!< Measurement status */
#define MDC_ATTRIBUTE_ID_PHYSIO (2347U)                         /*!< Metric ID */
#define MDC_ATTRIBUTE_ID_PHYSIO_LIST (2678U)                    /*!< Metric ID list */
#define MDC_ATTRIBUTE_METRIC_ID_PARTITION (2655U)               /*!< Metric ID partition */
#define MDC_ATTRIBUTE_UNIT_CODE (2454U)                         /*!< Metric Unit code */
#define MDC_ATTRIBUTE_SOURCE_HANDLE_REFERENCE (2631U)           /*!< Source handle reference */
#define MDC_ATTRIBUTE_ID_LABEL_STRING (2343U)                   /*!< Label string */
#define MDC_ATTRIBUTE_UNIT_LABEL_STRING (2457U)                 /*!< Unit Label string */
#define MDC_ATTRIBUTE_TIME_STAMP_ABSOLUTE (2448U)               /*!< Absolute time stamp */
#define MDC_ATTRIBUTE_TIME_STAMP_RELATIVE (2449U)               /*!< Relative time stamp */
#define MDC_ATTRIBUTE_TIME_STAMP_RELATIVE_HIGH_RESPONSE (2537U) /*!< High response relative time stamp */
#define MDC_ATTRIBUTE_TIME_MEASURE_ACTIVE_PERIOD (2649U)        /*!< Measure active period */

/*! @brief PM store attributes */
#define MDC_ATTRIBUTE_PM_STORE_CAPABILITY (2637U)           /*!< PM store capable */
#define MDC_ATTRIBUTE_METRIC_STORE_SAMPLE_ALGORITHM (2371U) /*!< Store sample algorithm */
#define MDC_ATTRIBUTE_METRIC_STORE_CAPACITY_COUNT (2369U)   /*!< Store capacity count */
#define MDC_ATTRIBUTE_METRIC_STORE_USAGE_COUNT (2372U)      /*!< Store usage count */
#define MDC_ATTRIBUTE_PM_STORE_LABEL_STRING (2647U)         /*!< PM store label string */
#define MDC_ATTRIBUTE_NUMBER_SEGMENT (2385U)                /*!< Number of segment */
#define MDC_ATTRIBUTE_CLEAR_TIMEOUT (2659U)                 /*!< Clear timeout */

/*! @brief Numeric attributes */
#define MDC_ATTRIBUTE_NUMERIC_VALUE_OBSERVATION_SIMPLE (2646U)          /*!< Simple numeric observed value */
#define MDC_ATTRIBUTE_NUMERIC_COMPOUND_VALUE_OBSERVATION_SIMPLE (2676U) /*!< Compound simple numeric observed value */
#define MDC_ATTRIBUTE_NUMERIC_VALUE_OBSERVATION_BASIC (2636U)           /*!< Basic numeric observed value */
#define MDC_ATTRIBUTE_NUMERIC_COMPOUND_VALUE_OBSERVATION_BASIC (2677U)  /*!< Compound basic numeric observed value */
#define MDC_ATTRIBUTE_NUMERIC_VALUE_OBSERVATION (2384U)                 /*!< Numeric observed value */
#define MDC_ATTRIBUTE_NUMERIC_COMPOUND_VALUE_OBSERVATION (2379U)        /*!< Compound numeric observed value */
#define MDC_ATTRIBUTE_NUMERIC_ACCURACY (2378U)                          /*!< Numeric accuracy */

/*! @brief Real Time Sample Array attributes */
#define MDC_ATTRIBUTE_TIME_SAMPLE_PERIOD (2445U)            /*!< Sample period */
#define MDC_ATTRIBUTE_SIMPLE_SA_OBSERVATION_VALUE (2632U)   /*!< Sample SA observed value */
#define MDC_ATTRIBUTE_SCALE_RANGE_SPECIFICATION_I8 (2417U)  /*!< Scale range spec 8 */
#define MDC_ATTRIBUTE_SCALE_RANGE_SPECIFICATION_I16 (2415U) /*!< Scale range spec 16 */
#define MDC_ATTRIBUTE_SCALE_RANGE_SPECIFICATION_I32 (2416U) /*!< Scale range spec 32 */
#define MDC_ATTRIBUTE_SA_SPECIFICATION (2413U)              /*!< SA specification */

/*! @brief Periodic configurable scanner object attributes */
#define MDC_ATTRIBUTE_SCANNER_REPORT_PERIODIC (2421U)

/*! @brief Enumeration attributes */
#define MDC_ATTRIBUTE_ENUM_OBSERVATION_VALUE_SIMPLE_OID (2633U)     /*!< Enumeration observed value simple OID */
#define MDC_ATTRIBUTE_ENUM_OBSERVATION_VALUE_SIMPLE_BIT_STR (2661U) /*!< Enumeratioin observed value simple bit str */
#define MDC_ATTRIBUTE_ENUM_OBSERVATION_VALUE_BASIC_BIT_STR (2662U)  /*!< Enumeration observed value basic bit str */
#define MDC_ATTRIBUTE_ENUM_OBSERVATION_VALUE_SIMPLE_STR (2634U)     /*!< Enumeration observed value simple str */
#define MDC_ATTRIBUTE_ENUM_OBSERVATION_VALUE (2462U)                /*!< Enumeration observed value */
#define MDC_ATTRIBUTE_ENUM_OBSERVATION_VALUE_PARTITION (2656U)      /*!< Enumeration observed value partition */

/*! @brief Episodic configurable scanner attributes */
#define MDC_ATTRIBUTE_SCANNER_REPORT_PD_MIN (2644U) /*!< Minimum reporting interval */

/*! @brief PM store object methods */
#define MDC_ACT_SEGMENT_CLEAR (3084U)           /*!< Clear segment */
#define MDC_ACT_SEGMENT_GET_INFORMATION (3085U) /*!< Get segment information */
#define MDC_ACT_SEGMENT_TRIGGER_XFER (3100U)    /*!< Trigger segment data xfer */

/*! @brief MDS object methods */
#define MDC_ACT_DATA_REQUEST (3099U) /*!< Data request */
#define MDC_ACT_SET_TIME (3095U)     /*!< Set time */

/*! @brief MDS object events */
#define MDC_NOTI_CONFIGURATION (3356U)                  /*!< Configuration event */
#define MDC_NOTI_SCAN_REPORT_VAR (3358U)                /*!< Scan report info var */
#define MDC_NOTI_SCAN_REPORT_FIXED (3357U)              /*!< Scan report info fixed */
#define MDC_NOTI_SCAN_REPORT_MULTI_PERSON_VAR (3360U)   /*!< Scan report multi person var */
#define MDC_NOTI_SCAN_REPORT_MULTI_PERSON_FIXED (3359U) /*!< Scan report multi person fixed */

/*! @brief PM store object events */
#define MDC_NOTI_SEGMENT_DATA (3361U) /*!< Segment data event */

/*! @brief Episodic configurable scanner object events */
#define MDC_NOTI_UNBUF_SCAN_REPORT_VAR (3362U)                  /*!< Unbuf scan report var */
#define MDC_NOTI_UNBUF_SCAN_REPORT_FIXED (3363U)                /*!< Unbuf scan report fixed */
#define MDC_NOTI_UNBUF_SCAN_REPORT_GROUPED (3364U)              /*!< Unbuf scan report grouped */
#define MDC_NOTI_UNBUF_SCAN_REPORT_MULTI_PERSON_VAR (3365U)     /*!< Unbuf scan report multi person var */
#define MDC_NOTI_UNBUF_SCAN_REPORT_MULTI_PERSON_FIXED (3366U)   /*!< Unbuf scan report multi person fixed */
#define MDC_NOTI_UNBUF_SCAN_REPORT_MULTI_PERSON_GROUPED (3367U) /*!< Unbuf scan report multi person grouped */

/*! @brief Periodic configurable scanner object events */
#define MDC_NOTI_BUF_SCAN_REPORT_VAR (3368U)                  /*!< Buffered scan report var */
#define MDC_NOTI_BUF_SCAN_REPORT_FIXED (3369U)                /*!< Buffered scan report fixed */
#define MDC_NOTI_BUF_SCAN_REPORT_GROUPED (3370U)              /*!< Buffered scan report grouped */
#define MDC_NOTI_BUF_SCAN_REPORT_MULTI_PERSON_VAR (3371U)     /*!< Buffered scan report multi person var */
#define MDC_NOTI_BUF_SCAN_REPORT_MULTI_PERSON_FIXED (3372U)   /*!< Buffered scan report multi person fixed */
#define MDC_NOTI_BUF_SCAN_REPORT_MULTI_PERSON_GROUPED (3373U) /*!< Buffered scan report multi person grouped */

/*! @brief Body mass */
#define MDC_MASS_BODY_ACTUAL (57664U) /*!< Body mass */
/*! @brief Body height */
#define MDC_LENGTH_BODY_ACTUAL (57666U) /*!< Body length */
/*! @brief Body mass index */
#define MDC_RATIO_MASS_BODY_LENGTH_SQUARE (57680U) /*!< BMI */

/*! @brief Unid code*/
#define MDC_DIM_PERCENT (544U)          /*!< Percent % */
#define MDC_DIM_KILOGRAM (1731U)        /*!< kg */
#define MDC_DIM_KG_PER_M_SQUARE (1952U) /*!< kg/m2 */
#define MDC_DIM_MINUTE (2208U)          /*!< minute */
#define MDC_DIM_HOUR (2240U)            /*!< hour */
#define MDC_DIM_DAY (2272U)             /*!< day */
#define MDC_DIM_DEGREE_C (6048U)        /*!< oC */

/*! @brief Device specification list */
#define MDC_DEV_SPEC_PROFILE_PULSE_OXIMETER (4100U)  /*!< Pulse oximeter */
#define MDC_DEV_SPEC_PROFILE_BLOOD_PRESSURE (4103U)  /*!< Blood pressure */
#define MDC_DEV_SPEC_PROFILE_THERMOMETER (4104U)     /*!< Thermometer */
#define MDC_DEV_SPEC_PROFILE_SCALE (4111U)           /*!< Scale */
#define MDC_DEV_SPEC_PROFILE_GLUCOSE (4113U)         /*!< Glucose meter */
#define MDC_DEV_SPEC_PROFILE_HF_CARDIO (4137U)       /*!< HF cardio */
#define MDC_DEV_SPEC_PROFILE_HF_STRENGTH (4138U)     /*!< HF strength */
#define MDC_DEV_SPEC_PROFILE_AI_ACTIVITY_HUB (4167U) /*!< Activity hub */
#define MDC_DEV_SPEC_PROFILE_AI_MED_MINDER (4168U)   /*!< Med Minder */

/*! @brief Types */
typedef struct _nomenclature_ascii_struct
{
    oid_type_t type;
    int8_t *asciiString;
} nomenclature_ascii_struct_t;

typedef struct _partition_ascii_struct
{
    nom_partition_t partition;
    int8_t *asciiString;
} partition_ascii_struct_t;

/*******************************************************************************
 * Variables
 ******************************************************************************/

extern const nomenclature_ascii_struct_t g_nomenclatureAsciiTable[];
extern const partition_ascii_struct_t g_partitionAsciiTable[];
extern const uint16_t g_nomAsciiCount;
extern const uint16_t g_partitionAsciiCount;

#endif /* _IEEE11073_NOMENCLATURE_ */
