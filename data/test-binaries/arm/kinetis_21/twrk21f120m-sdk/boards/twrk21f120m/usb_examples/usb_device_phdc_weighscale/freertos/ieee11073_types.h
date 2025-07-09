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
#ifndef _IEEE11073_TYPES_H_
#define _IEEE11073_TYPES_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

STRUCT_PACKED
struct _any
{
    uint16_t length;
    uint8_t value[1]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _any any_t;

typedef uint16_t oid_type_t;

typedef uint16_t private_oid_t;

typedef uint16_t handle_t;

typedef uint16_t inst_number_t;

typedef uint16_t nom_partition_t;
#define NOM_PART_UNSPEC 0U
#define NOM_PART_OBJ 1U
#define NOM_PART_METRIC 2U
#define NOM_PART_ALERT 3U
#define NOM_PART_DIM 4U
#define NOM_PART_VATTR 5U
#define NOM_PART_PGRP 6U
#define NOM_PART_SITES 7U
#define NOM_PART_INFRASTRUCT 8U
#define NOM_PART_FEF 9U
#define NOM_PART_ECG_EXTN 10U
#define NOM_PART_PHD_DM 128U
#define NOM_PART_PHD_HF 129U
#define NOM_PART_PHD_AI 130U
#define NOM_PART_RET_CODE 255U
#define NOM_PART_EXT_NOM 256U
#define NOM_PART_PRIV 1024U
STRUCT_PACKED
struct _type
{
    nom_partition_t partition;
    oid_type_t code;
} STRUCT_UNPACKED;
typedef struct _type type_t;

STRUCT_PACKED
struct _ava_type
{
    oid_type_t attributeId;
    any_t attributeValue;
} STRUCT_UNPACKED;
typedef struct _ava_type ava_type_t;

STRUCT_PACKED
struct _attribute_list
{
    uint16_t count;
    uint16_t length;
    ava_type_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _attribute_list attribute_list_t;

STRUCT_PACKED
struct _attribute_id_list
{
    uint16_t count;
    uint16_t length;
    oid_type_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _attribute_id_list attribute_id_list_t;

typedef uint32_t float_type_t;
typedef uint16_t sfloat_type_t;
typedef uint32_t relative_time_t;
STRUCT_PACKED
struct _high_res_relative_time
{
    uint8_t value[8U];
} STRUCT_UNPACKED;
typedef struct _high_res_relative_time high_res_relative_time_t;

STRUCT_PACKED
struct _absolute_time_adjust
{
    uint8_t value[6U];
} STRUCT_UNPACKED;
typedef struct _absolute_time_adjust absolute_time_adjust_t;

STRUCT_PACKED
struct _absolute_time
{
    uint8_t century;
    uint8_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t secFractions;
} STRUCT_UNPACKED;
typedef struct _absolute_time absolute_time_t;

typedef uint16_t operational_state_t;
#define OS_DISABLED 0U
#define OS_ENABLED 1U
#define OS_NOT_AVAILABLE 2U
STRUCT_PACKED
struct _octet_string
{
    uint16_t length;
    uint8_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _octet_string octet_string_t;

STRUCT_PACKED
struct _system_model
{
    octet_string_t manufacturer;
    octet_string_t modelNumber;
} STRUCT_UNPACKED;
typedef struct _system_model system_model_t;

STRUCT_PACKED
struct _prod_spec_entry
{
    uint16_t specType;
#define UNSPECIFIED 0U
#define SERIAL_NUMBER 1U
#define PART_NUMBER 2U
#define HW_REVISION 3U
#define SW_REVISION 4U
#define FW_REVISION 5U
#define PROTOCOL_REVISION 6U
#define PROD_SPEC_GMDN 7U
    private_oid_t componentId;
    octet_string_t prodSpec;
} STRUCT_UNPACKED;
typedef struct _prod_spec_entry prod_spec_entry_t;

STRUCT_PACKED
struct _production_spec
{
    uint16_t count;
    uint16_t length;
    prod_spec_entry_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _production_spec production_spec_t;

typedef uint16_t power_status_t;
#define ON_MAINS 0x8000U
#define ON_BATTERY 0x4000U
#define CHARGING_FULL 0x0080U
#define CHARGING_TRICKLE 0x0040U
#define CHARGING_OFF 0x0020U
STRUCT_PACKED
struct _bat_measure
{
    float_type_t value;
    oid_type_t unit;
} STRUCT_UNPACKED;
typedef struct _bat_measure bat_measure_t;

typedef uint16_t measurement_status;
#define MS_INVALID 0x8000U
#define MS_QUESTIONABLE 0x4000U
#define MS_NOT_AVAILABLE 0x2000U
#define MS_CALIBRATION_ONGOING 0x1000U
#define MS_TEST_DATA 0x0800U
#define MS_DEMO_DATA 0x0400U
#define MS_VALIDATED_DATA 0x0080U
#define MS_EARLY_INDICATION 0x0040U
#define MS_MSMT_ONGOING 0x0020U
STRUCT_PACKED
struct _nu_obs_value
{
    oid_type_t metricId;
    measurement_status state;
    oid_type_t unitCode;
    float_type_t value;
} STRUCT_UNPACKED;
typedef struct _nu_obs_value nu_obs_value_t;

STRUCT_PACKED
struct _nu_obs_value_cmp
{
    uint16_t count;
    uint16_t length;
    nu_obs_value_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _nu_obs_value_cmp nu_obs_value_cmp_t;

STRUCT_PACKED
struct _sample_type
{
    uint8_t sampleSize;
    uint8_t significantBits;
} STRUCT_UNPACKED;
typedef struct _sample_type sample_type_t;
#define SAMPLE_TYPE_SIGNIFICANT_BITS_SIGNED_SAMPLES 255U
typedef uint16_t sa_flags_t;
#define SMOOTH_CURVE 0x8000U
#define DELAYED_CURVE 0x4000U
#define STATIC_SCALE 0x2000U
#define SA_EXT_VAL_RANGE 0x1000U
STRUCT_PACKED
struct _sa_spec
{
    uint16_t arraySize;
    sample_type_t sampleType;
    sa_flags_t flags;
} STRUCT_UNPACKED;
typedef struct _sa_spec sa_spec_t;

STRUCT_PACKED
struct _scale_range_spec8
{
    float_type_t lowerAbsoluteValue;
    float_type_t upperAbsoluteValue;
    uint8_t lowerScaledValue;
    uint8_t upperScaledValue;
} STRUCT_UNPACKED;
typedef struct _scale_range_spec8 scale_range_spec8_t;

STRUCT_PACKED
struct _scale_range_spec16
{
    float_type_t lowerAbsoluteValue;
    float_type_t upperAbsoluteValue;
    uint16_t lowerScaledValue;
    uint16_t upperScaledValue;
} STRUCT_UNPACKED;
typedef struct _scale_range_spec16 scale_range_spec16_t;

STRUCT_PACKED
struct _scale_range_spec32
{
    float_type_t lowerAbsoluteValue;
    float_type_t upperAbsoluteValue;
    uint32_t lowerScaledValue;
    uint32_t upperScaledValue;
} STRUCT_UNPACKED;
typedef struct _scale_range_spec32 scale_range_spec32_t;

union _scale_range_spec32_union
{
    oid_type_t enumObjId;
    octet_string_t enumTextString;
    uint32_t enumBitStr; /* BITS-32 */
};
typedef union _scale_range_spec32_union scale_range_spec32_union_t;

STRUCT_PACKED
struct _enum_val
{
    uint16_t choice;
    uint16_t length;
#define OBJ_ID_CHOSEN 0x0001U
#define TEXT_STRING_CHOSEN 0x0002U
#define BIT_STR_CHOSEN 0x0010U
    scale_range_spec32_union_t u;
} STRUCT_UNPACKED;
typedef struct _enum_val enum_val_t;

STRUCT_PACKED
struct _enum_obs_value
{
    oid_type_t metricId;
    measurement_status state;
    enum_val_t value;
} STRUCT_UNPACKED;
typedef struct _enum_obs_value enum_obs_value_t;

STRUCT_PACKED
struct _attr_val_map_entry
{
    oid_type_t attributeId;
    uint16_t attributeLen;
} STRUCT_UNPACKED;
typedef struct _attr_val_map_entry attr_val_map_entry_t;

STRUCT_PACKED
struct _attr_val_map
{
    uint16_t count;
    uint16_t length;
    attr_val_map_entry_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _attr_val_map attr_val_map_t;

STRUCT_PACKED
struct _handle_attr_val_map_entry
{
    handle_t objectHandle;
    attr_val_map_t attrValMap;
} STRUCT_UNPACKED;
typedef struct _handle_attr_val_map_entry handle_attr_val_map_entry_t;

typedef uint16_t confirm_mode;
#define UNCONFIRMED 0x0000U
#define CONFIRMED 0x0001U
STRUCT_PACKED
struct _handle_attr_val_map
{
    uint16_t count;
    uint16_t length;
    handle_attr_val_map_entry_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _handle_attr_val_map handle_attr_val_map_t;

typedef uint16_t sto_sample_alg_t;
#define ST_ALG_NOS 0x0000U
#define ST_ALG_MOVING_AVERAGE 0x0001U
#define ST_ALG_RECURSIVE_ 0x0002U
#define ST_ALG_MIN_PICK 0x0003U
#define ST_ALG_MAX_PICK 0x0004U
#define ST_ALG_MEDIAN 0x0005U
#define ST_ALG_TRENDED 0x0200U
#define ST_ALG_NO_DOWNSAMPLING 0x0400U
STRUCT_PACKED
struct _set_time_invoke
{
    absolute_time_t dateTime;
    float_type_t accuracy;
} STRUCT_UNPACKED;
typedef struct _set_time_invoke set_time_invoke_t;

STRUCT_PACKED
struct _segm_id_list
{
    uint16_t count;
    uint16_t length;
    inst_number_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _segm_id_list segm_id_list_t;

STRUCT_PACKED
struct _abs_time_range
{
    absolute_time_t fromTime;
    absolute_time_t toTime;
} STRUCT_UNPACKED;
typedef struct _abs_time_range abs_time_range_t;

STRUCT_PACKED
struct _segment_info
{
    inst_number_t segInstNo;
    attribute_list_t segInfo;
} STRUCT_UNPACKED;
typedef struct _segment_info segment_info_t;

STRUCT_PACKED
struct _segment_info_list
{
    uint16_t count;
    uint16_t length;
    segment_info_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _segment_info_list segment_info_list_t;

union _segm_selection_union
{
    uint16_t allSegments;
    segm_id_list_t segmIdList;
    abs_time_range_t absTimeRange;
};
typedef union _segm_selection_union segm_selection_union_t;

STRUCT_PACKED
struct _segm_selection
{
    uint16_t choice;
    uint16_t length;
#define ALL_SEGMENTS_CHOSEN 0x0001U
#define SEGM_ID_LIST_CHOSEN 0x0002U
#define ABS_TIME_RANGE_CHOSEN 0x0003U
    segm_selection_union_t u;
} STRUCT_UNPACKED;
typedef struct _segm_selection segm_selection_t;

typedef uint16_t pm_store_capab_t;
#define PMSC_VAR_NO_OF_SEGM 0x8000U
#define PMSC_EPI_SEG_ENTRIES 0x0800U
#define PMSC_PERI_SEG_ENTRIES 0x0400U
#define PMSC_ABS_TIME_SELECT 0x0200U
#define PMSC_CLEAR_SEGM_BY_LIST_SUP 0x0100U
#define PMSC_CLEAR_SEGM_BY_TIME_SUP 0x0080U
#define PMSC_CLEAR_SEGM_REMOVE 0x0040U
#define PMSC_MULTI_PERSON 0x0008U
typedef uint16_t segm_entry_header_t;
#define SEG_ELEM_HDR_ABSOLUTE_TIME 0x8000U
#define SEG_ELEM_HDR_RELATIVE_TIME 0x4000U
#define SEG_ELEM_HDR_HIRES_RELATIVE_TIME 0x2000U
STRUCT_PACKED
struct _segm_entry_elem
{
    oid_type_t classId;
    type_t metricType;
    handle_t handle;
    attr_val_map_t attrValMap;
} STRUCT_UNPACKED;
typedef struct _segm_entry_elem segm_entry_elem_t;

STRUCT_PACKED
struct _segm_entry_elem_list
{
    uint16_t count;
    uint16_t length;
    segm_entry_elem_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _segm_entry_elem_list segm_entry_elem_list_t;

STRUCT_PACKED
struct _pm_segment_entry_map
{
    segm_entry_header_t segmEntryHeader;
    segm_entry_elem_list_t segmEntryElemList;
} STRUCT_UNPACKED;
typedef struct _pm_segment_entry_map pm_segment_entry_map_t;

STRUCT_PACKED
struct _segm_elem_static_attr_entry
{
    oid_type_t classId;
    type_t metricType;
    attribute_list_t attributeList;
} STRUCT_UNPACKED;
typedef struct _segm_elem_static_attr_entry segm_elem_static_attr_entry_t;

STRUCT_PACKED
struct _pm_segm_elem_static_attrList
{
    uint16_t count;
    uint16_t length;
    segm_elem_static_attr_entry_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _pm_segm_elem_static_attrList pm_segm_elem_static_attrList_t;

STRUCT_PACKED
struct _trig_segm_sata_xfer_req
{
    inst_number_t segInstNo;
} STRUCT_UNPACKED;
typedef struct _trig_segm_sata_xfer_req trig_segm_sata_xfer_req_t;

typedef uint16_t trig_segm_xfer_rsp_t;
#define TSXR_SUCCESSFUL 0U
#define TSXR_FAIL_NO_SUCH_SEGMENT 1U
#define TSXR_FAIL_SEGM_TRY_LATER 2U
#define TSXR_FAIL_SEGM_EMPTY 3U
#define TSXR_FAIL_OTHER 512U
STRUCT_PACKED
struct _trig_segm_data_xfer_rsp
{
    inst_number_t segInstNo;
    trig_segm_xfer_rsp_t trigSegmXferRsp;
} STRUCT_UNPACKED;
typedef struct _trig_segm_data_xfer_rsp trig_segm_data_xfer_rsp_t;

typedef uint16_t segm_evt_status;
#define SEVTSTA_FIRST_ENTRY 0x8000U
#define SEVTSTA_LAST_ENTRY 0x4000U
#define SEVTSTA_AGENT_ABORT 0x0800U
#define SEVTSTA_MANAGER_CONFIRM 0x0080U
#define SEVTSTA_MANAGER_ABORT 0x0008U
STRUCT_PACKED
struct _segm_data_event_descr
{
    inst_number_t segmInstance;
    uint32_t segmEvtEntryIndex;
    uint32_t segmEvtEntryCount;
    segm_evt_status segmEvt;
} STRUCT_UNPACKED;
typedef struct _segm_data_event_descr segm_data_event_descr_t;

STRUCT_PACKED
struct _segment_data_event
{
    segm_data_event_descr_t segmDataEventDescr;
    octet_string_t segmDataEventEntries;
} STRUCT_UNPACKED;
typedef struct _segment_data_event segment_data_event_t;

STRUCT_PACKED
struct _segment_data_result
{
    segm_data_event_descr_t segmDataEventDescr;
} STRUCT_UNPACKED;
typedef struct _segment_data_result segment_data_result_t;

typedef uint16_t segm_stat_type_t;
#define SEGM_STAT_TYPE_MINIMUM 1U
#define SEGM_STAT_TYPE_MAXIMUM 2U
#define SEGM_STAT_TYPE_AVERAGE 3U
STRUCT_PACKED
struct _segment_statistic_entry
{
    segm_stat_type_t segmStatType;
    octet_string_t segmStatEntry;
} STRUCT_UNPACKED;
typedef struct _segment_statistic_entry segment_statistic_entry_t;

STRUCT_PACKED
struct _segment_statistics
{
    uint16_t count;
    uint16_t length;
    segment_statistic_entry_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _segment_statistics segment_statistics_t;

STRUCT_PACKED
struct _observation_scan
{
    handle_t objectHandle;
    attribute_list_t attributes;
} STRUCT_UNPACKED;
typedef struct _observation_scan observation_scan_t;

typedef oid_type_t time_protocol_id_t;

typedef uint32_t association_version_t;
#define ASSOC_VERSION1 0x80000000U
typedef uint32_t protocol_version_t;
#define PROTOCOL_VERSION1 0x80000000U
typedef uint16_t encoding_rules_t;
#define MEDICAL_ENCODING_RULES 0x8000U
#define XER 0x4000U
#define PER 0x2000U
STRUCT_PACKED
struct _uuid_ident
{
    uint8_t value[16U];
} STRUCT_UNPACKED;
typedef struct _uuid_ident uuid_ident_t;

typedef uint16_t data_proto_id_t;
#define DATA_PROTO_ID_20601 20601U
#define DATA_PROTO_ID_EXTERNAL 65535U
STRUCT_PACKED
struct _data_proto
{
    data_proto_id_t dataProtoId;
    any_t dataProtoInfo;
} STRUCT_UNPACKED;
typedef struct _data_proto data_proto_t;

STRUCT_PACKED
struct _data_proto_list
{
    uint16_t count;
    uint16_t length;
    data_proto_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _data_proto_list data_proto_list_t;

STRUCT_PACKED
struct _aarq_apdu
{
    association_version_t assocVersion;
    data_proto_list_t dataProtoList;
} STRUCT_UNPACKED;
typedef struct _aarq_apdu aarq_apdu_t;

typedef uint16_t associate_result_t;
#define ACCEPTED 0U
#define REJECTED_PERMANENT 1U
#define REJECTED_TRANSIENT 2U
#define ACCEPTED_UNKNOWN_CONFIG 3U
#define REJECTED_NO_COMMON_PROTOCOL 4U
#define REJECTED_NO_COMMON_PARAMETER 5U
#define REJECTED_UNKNOWN 6U
#define REJECTED_UNAUTHORIZED 7U
#define REJECTED_UNSUPPORTED_ASSOC_VERSION 8U
STRUCT_PACKED
struct _aare_apdu
{
    associate_result_t result;
    data_proto_t selectedDataProto;
} STRUCT_UNPACKED;
typedef struct _aare_apdu aare_apdu_t;

typedef uint16_t release_request_reason_t;
#define RELEASE_REQUEST_REASON_NORMAL 0U
STRUCT_PACKED
struct _rlrq_apdu
{
    release_request_reason_t reason;
} STRUCT_UNPACKED;
typedef struct _rlrq_apdu rlrq_apdu_t;

typedef uint16_t release_response_reason_t;
#define RELEASE_RESPONSE_REASON_NORMAL 0U
STRUCT_PACKED
struct _rlre_apdu
{
    release_response_reason_t reason;
} STRUCT_UNPACKED;
typedef struct _rlre_apdu rlre_apdu_t;

typedef uint16_t abort_reason_t;
#define ABORT_REASON_UNDEFINED 0U
#define ABORT_REASON_BUFFER_OVERFLOW 1U
#define ABORT_REASON_RESPONSE_TIMEOUT 2U
#define ABORT_REASON_CONFIGURATION_TIMEOUT 3U
STRUCT_PACKED
struct _abrt_apdu
{
    abort_reason_t reason;
} STRUCT_UNPACKED;
typedef struct _abrt_apdu abrt_apdu_t;

typedef octet_string_t prst_apdu_t;
typedef uint16_t invoke_id_type_t;

STRUCT_PACKED
struct _event_report_argument_simple
{
    handle_t objectHandle;
    relative_time_t eventTime;
    oid_type_t eventType;
    any_t eventInfo;
} STRUCT_UNPACKED;
typedef struct _event_report_argument_simple event_report_argument_simple_t;

STRUCT_PACKED
struct _get_argument_simple
{
    handle_t objectHandle;
    attribute_id_list_t attributeIdList;
} STRUCT_UNPACKED;
typedef struct _get_argument_simple get_argument_simple_t;

typedef uint16_t modify_operator_t;
#define REPLACE 0U
#define ADD_VALUES 1U
#define REMOVE_VALUES 2U
#define SET_TO_DEFAULT 3U
STRUCT_PACKED
struct _attribute_mod_entry
{
    modify_operator_t modifyOperator;
    ava_type_t attribute;
} STRUCT_UNPACKED;
typedef struct _attribute_mod_entry attribute_mod_entry_t;

STRUCT_PACKED
struct _modification_list
{
    uint16_t count;
    uint16_t length;
    attribute_mod_entry_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _modification_list modification_list_t;

STRUCT_PACKED
struct _set_argument_simple
{
    handle_t objectHandle;
    modification_list_t modificationList;
} STRUCT_UNPACKED;
typedef struct _set_argument_simple set_argument_simple_t;

STRUCT_PACKED
struct _action_argument_simple
{
    handle_t objectHandle;
    oid_type_t actionType;
    any_t actionInfoArgs;
} STRUCT_UNPACKED;
typedef struct _action_argument_simple action_argument_simple_t;

STRUCT_PACKED
struct _event_report_result_simple
{
    handle_t objectHandle;
    relative_time_t currentTime;
    oid_type_t eventType;
    any_t eventReplyInfo;
} STRUCT_UNPACKED;
typedef struct _event_report_result_simple event_report_result_simple_t;

STRUCT_PACKED
struct _get_result_simple
{
    handle_t objectHandle;
    attribute_list_t attributeList;
} STRUCT_UNPACKED;
typedef struct _get_result_simple get_result_simple_t;

STRUCT_PACKED
struct _type_ver
{
    oid_type_t type;
    uint16_t version;
} STRUCT_UNPACKED;
typedef struct _type_ver type_ver_t;

STRUCT_PACKED
struct _type_ver_list
{
    uint16_t count;
    uint16_t length;
    type_ver_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _type_ver_list type_ver_list_t;

STRUCT_PACKED
struct _set_result_simple
{
    handle_t objectHandle;
    attribute_list_t attributeList;
} STRUCT_UNPACKED;
typedef struct _set_result_simple set_result_simple_t;

STRUCT_PACKED
struct _action_result_simple
{
    handle_t objectHandle;
    oid_type_t actionType;
    any_t actionInfoArgs;
} STRUCT_UNPACKED;
typedef struct _action_result_simple action_result_simple_t;

typedef uint16_t error_t;
#define NO_SUCH_OBJECT_INSTANCE 1U
#define ACCESS_DENIED 2U
#define NO_SUCH_ACTION 9U
#define INVALID_OBJECT_INSTANCE 17U
#define PROTOCOL_VIOLATION 23U
#define NOT_ALLOWED_BY_OBJECT 24U
#define ACTION_TIMED_OUT 25U
#define ACTION_ABORTED 26U
STRUCT_PACKED
struct _error_result
{
    error_t errorValue;
    any_t parameter;
} STRUCT_UNPACKED;
typedef struct _error_result error_result_t;

typedef uint16_t rorj_problem_t;
#define UNRECOGNIZED_APDU 0U
#define BADLY_STRUCTURED_APDU 2U
#define UNRECOGNIZED_OPERATION 101U
#define RESOURCE_LIMITATION 103U
#define UNEXPECTED_ERROR 303U
STRUCT_PACKED
struct _reject_result
{
    rorj_problem_t problem;
} STRUCT_UNPACKED;
typedef struct _reject_result reject_result_t;

STRUCT_PACKED
union _data_apdu_union
{
    event_report_argument_simple_t roivCmipEventReport;
    event_report_argument_simple_t roivCmipConfirmedEventReport;
    get_argument_simple_t roivCmipGet;
    set_argument_simple_t roivCmipSet;
    set_argument_simple_t roivCmipConfirmedSet;
    action_argument_simple_t roivCmipAction;
    action_argument_simple_t roivCmipConfirmedAction;
    event_report_result_simple_t rorsCmipConfirmedEventReport;
    get_result_simple_t rorsCmipGet;
    set_result_simple_t rorsCmipConfirmedSet;
    action_result_simple_t rorsCmipConfirmedAction;
    error_result_t roer;
    reject_result_t rorj;
} STRUCT_PACKED;
typedef union _data_apdu_union data_apdu_union_t;

STRUCT_PACKED
struct _data_apdu_struct
{
    uint16_t choice;
    uint16_t length;
#define ROIV_CMIP_EVENT_REPORT_CHOSEN 0x0100U
#define ROIV_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN 0x0101U
#define ROIV_CMIP_GET_CHOSEN 0x0103U
#define ROIV_CMIP_SET_CHOSEN 0x0104U
#define ROIV_CMIP_CONFIRMED_SET_CHOSEN 0x0105U
#define ROIV_CMIP_ACTION_CHOSEN 0x0106U
#define ROIV_CMIP_CONFIRMED_ACTION_CHOSEN 0x0107U
#define RORS_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN 0x0201U
#define RORS_CMIP_GET_CHOSEN 0x0203U
#define RORS_CMIP_CONFIRMED_SET_CHOSEN 0x0205U
#define RORS_CMIP_CONFIRMED_ACTION_CHOSEN 0x0207U
#define ROER_CHOSEN 0x0300U
#define RORJ_CHOSEN 0x0400U
    data_apdu_union_t u;
} STRUCT_UNPACKED;
typedef struct _data_apdu_struct data_apdu_struct_t;

STRUCT_PACKED
struct _data_apdu
{
    invoke_id_type_t invokeId;
    data_apdu_struct_t choice;
} STRUCT_UNPACKED;
typedef struct _data_apdu data_apdu_t;

STRUCT_PACKED
union _apdu_union
{
    aarq_apdu_t aarq;
    aare_apdu_t aare;
    rlrq_apdu_t rlrq;
    rlre_apdu_t rlre;
    abrt_apdu_t abrt;
    prst_apdu_t prst;
} STRUCT_UNPACKED;
typedef union _apdu_union apdu_union_t;

STRUCT_PACKED
struct _apdu
{
    uint16_t choice;
    uint16_t length;
#define AARQ_CHOSEN 0xE200U
#define AARE_CHOSEN 0xE300U
#define RLRQ_CHOSEN 0xE400U
#define RLRE_CHOSEN 0xE500U
#define ABRT_CHOSEN 0xE600U
#define PRST_CHOSEN 0xE700U
    apdu_union_t u;
} STRUCT_UNPACKED;
typedef struct _apdu apdu_t;

typedef uint32_t nomenclature_version_t;
#define NOM_VERSION1 0x80000000
typedef uint32_t functional_units_t;
#define FUN_UNITS_UNIDIRECTIONAL 0x80000000U
#define FUN_UNITS_HAVETESTCAP 0x40000000U
#define FUN_UNITS_CREATETESTASSOC 0x20000000U
typedef uint32_t system_type_t;
#define SYS_TYPE_MANAGER 0x80000000U
#define SYS_TYPE_AGENT 0x00800000U
typedef uint16_t config_id_t;
#define MANAGER_CONFIG_RESPONSE 0x0000U
#define STANDARD_CONFIG_START 0x0001U
#define STANDARD_CONFIG_END 0x3FFFU
#define EXTENDED_CONFIG_START 0x4000U
#define EXTENDED_CONFIG_END 0x7FFFU
#define RESERVED_START 0x8000U
#define RESERVED_END 0xFFFFU
typedef uint16_t data_req_mode_flags_t;
#define DATA_REQ_SUPP_STOP 0x8000U
#define DATA_REQ_SUPP_SCOPE_ALL 0x0800U
#define DATA_REQ_SUPP_SCOPE_CLASS 0x0400U
#define DATA_REQ_SUPP_SCOPE_HANDLE 0x0200U
#define DATA_REQ_SUPP_MODE_SINGLE_RSP 0x0080U
#define DATA_REQ_SUPP_MODE_TIME_PERIOD 0x0040U
#define DATA_REQ_SUPP_MODE_TIME_NO_LIMIT 0x0020U
#define DATA_REQ_SUPP_PERSON_ID 0x0010U
#define DATA_REQ_SUPP_INIT_AGENT 0x0001U
STRUCT_PACKED
struct _data_req_mode_capab
{
    data_req_mode_flags_t dataReqModeFlags;
    uint8_t dataReqInitAgentCount;
    uint8_t dataReqInitManagerCount;
} STRUCT_UNPACKED;
typedef struct _data_req_mode_capab data_req_mode_capab_t;
STRUCT_PACKED
struct _phd_association_information
{
    protocol_version_t protocolVersion;
    encoding_rules_t encodingRules;
    nomenclature_version_t nomenclatureVersion;
    functional_units_t functionalUnits;
    system_type_t systemType;
    octet_string_t systemId;
    uint16_t devConfigId;
    data_req_mode_capab_t dataReqModeCapab;
    attribute_list_t optionList;
} STRUCT_UNPACKED;
typedef struct _phd_association_information phd_association_information_t;

struct _manuf_spec_association_information
{
    uuid_ident_t dataProtoIdExt;
    any_t dataProtoInfoExt;
};
typedef struct _manuf_spec_association_information manuf_spec_association_information_t;

typedef uint16_t mds_time_cap_state_t;
#define MDS_TIME_CAPAB_REAL_TIME_CLOCK 0x8000U
#define MDS_TIME_CAPAB_SET_CLOCK 0x4000U
#define MDS_TIME_CAPAB_RELATIVE_TIME 0x2000U
#define MDS_TIME_CAPAB_HIGH_RES_RELATIVE_TIME 0x1000U
#define MDS_TIME_CAPAB_SYNC_ABS_TIME 0x0800U
#define MDS_TIME_CAPAB_SYNC_REL_TIME 0x0400U
#define MDS_TIME_CAPAB_SYNC_HI_RES_RELATIVE_TIME 0x0200U
#define MDS_TIME_STATE_ABS_TIME_SYNCED 0x0080U
#define MDS_TIME_STATE_REL_TIME_SYNCED 0x0040U
#define MDS_TIME_STATE_HI_RES_RELATIVE_TIME_SYNCED 0x0020U
#define MDS_TIME_MGR_SET_TIME 0x0010U
struct _mds_time_info
{
    mds_time_cap_state_t mdsTimeCapState;
    time_protocol_id_t timeSyncProtocol;
    relative_time_t timeSyncAccuracy;
    uint16_t timeResolutionAbsTime;
    uint16_t timeResolutionRelTime;
    uint32_t timeResolutionHighResTime;
};
typedef struct _mds_time_info mds_time_info_t;

typedef octet_string_t enum_printable_string_t;

typedef uint16_t person_id_t;
#define UNKNOWN_PERSON_ID 0xFFFFU
typedef uint16_t metric_spec_small_t;
#define MSS_AVAIL_INTERMITTENT 0x8000U
#define MSS_AVAIL_STORED_DATA 0x4000U
#define MSS_UPD_APERIODIC 0x2000U
#define MSS_MSMT_APERIODIC 0x1000U
#define MSS_MSMT_PHYS_EV_ID 0x0800U
#define MSS_MSMT_BTB_METRIC 0x0400U
#define MSS_ACC_MANAGER_INITIATED 0x0080U
#define MSS_ACC_AGENT_INITIATED 0x0040U
#define MSS_CAT_MANUAL 0x0008U
#define MSS_CAT_SETTING 0x0004U
#define MSS_CAT_CALCULATION 0x0002U
struct _metric_structure_small
{
    uint8_t msStruct;
#define MS_STRUCT_SIMPLE 0U
#define MS_STRUCT_COMPOUND 1U
#define MS_STRUCT_RESERVED 2U
#define MS_STRUCT_COMPOUND_FIX 3U
    uint8_t msCompNo;
};
typedef struct _metric_structure_small metric_structure_small_t;

struct _metric_id_list
{
    uint16_t count;
    uint16_t length;
    oid_type_t value[1U]; /* first element of the array */
};
typedef struct _metric_id_list metric_id_list_t;

struct _supplemental_type_list
{
    uint16_t count;
    uint16_t length;
    type_t value[1U]; /* first element of the array */
};
typedef struct _supplemental_type_list supplemental_type_list_t;

struct _observation_scan_list
{
    uint16_t count;
    uint16_t length;
    observation_scan_t value[1U]; /* first element of the array */
};
typedef struct _observation_scan_list observation_scan_list_t;

struct _scan_report_per_var
{
    uint16_t personId;
    observation_scan_list_t obsScanVar;
};
typedef struct _scan_report_per_var scan_report_per_var_t;

struct _scan_report_per_var_list
{
    uint16_t count;
    uint16_t length;
    scan_report_per_var_t value[1U]; /* first element of the array */
};
typedef struct _scan_report_per_var_list scan_report_per_var_list_t;

typedef uint16_t data_req_id_t;
#define DATA_REQ_ID_MANAGER_INITIATED_MIN 0x0000U
#define DATA_REQ_ID_MANAGER_INITIATED_MAX 0xEFFFU
#define DATA_REQ_ID_AGENT_INITIATED 0xF000U
struct _scan_report_info_mp_var
{
    data_req_id_t dataReqId;
    uint16_t scanReportNo;
    scan_report_per_var_t scanPerVar;
};
typedef struct _scan_report_info_mp_var scan_report_info_mp_var_t;

struct _observation_scan_fixed
{
    handle_t objectHandle;
    octet_string_t obsValData;
};
typedef struct _observation_scan_fixed observation_scan_fixed_t;

struct _observation_scan_fixed_list
{
    uint16_t count;
    uint16_t length;
    observation_scan_fixed_t value[1U]; /* first element of the array */
};
typedef struct _observation_scan_fixed_list observation_scan_fixed_list_t;

struct _scan_report_per_fixed
{
    uint16_t personId;
    observation_scan_fixed_list_t obsScanFix;
};
typedef struct _scan_report_per_fixed scan_report_per_fixed_t;

struct _scan_report_per_fixed_list
{
    uint16_t count;
    uint16_t length;
    scan_report_per_fixed_t value[1U]; /* first element of the array */
};
typedef struct _scan_report_per_fixed_list scan_report_per_fixed_list_t;

struct _scan_report_info_mp_fixed
{
    data_req_id_t dataReqId;
    uint16_t scanReportNo;
    scan_report_per_fixed_list_t scanPerFixed;
};
typedef struct _scan_report_info_mp_fixed scan_report_info_mp_fixed_t;

struct _scan_report_info_var
{
    data_req_id_t dataReqId;
    uint16_t scanReportNo;
    observation_scan_list_t obsScanVar;
};
typedef struct _scan_report_info_var scan_report_info_var_t;

struct _scan_report_info_fixed
{
    data_req_id_t dataReqId;
    uint16_t scanReportNo;
    observation_scan_fixed_list_t obsScanFixed;
};
typedef struct _scan_report_info_fixed scan_report_info_fixed_t;

typedef octet_string_t observation_scan_grouped_t;

struct _scan_report_info_grouped_list
{
    uint16_t count;
    uint16_t length;
    observation_scan_grouped_t value[1U]; /* first element of the array */
};
typedef struct _scan_report_info_grouped_list scan_report_info_grouped_list_t;

struct _scan_report_info_grouped
{
    uint16_t dataReqId;
    uint16_t scanReportNo;
    scan_report_info_grouped_list_t obsScanGrouped;
};
typedef struct _scan_report_info_grouped scan_report_info_grouped_t;

struct _scan_report_per_grouped
{
    person_id_t personId;
    observation_scan_grouped_t obsScanGrouped;
};
typedef struct _scan_report_per_grouped scan_report_per_grouped_t;

struct _scan_report_per_grouped_list
{
    uint16_t count;
    uint16_t length;
    scan_report_per_grouped_t value[1U]; /* first element of the array */
};
typedef struct _scan_report_per_grouped_list scan_report_per_grouped_list_t;

struct _scan_report_info_mp_grouped
{
    uint16_t dataReqId;
    uint16_t scanReportNo;
    scan_report_per_grouped_list_t scanPerGrouped;
};
typedef struct _scan_report_info_mp_grouped scan_report_info_mp_grouped_t;

STRUCT_PACKED
struct _config_object
{
    oid_type_t objectClass;
    handle_t objectHandle;
    attribute_list_t attributes;
} STRUCT_UNPACKED;
typedef struct _config_object config_object_t;

STRUCT_PACKED
struct _config_object_list
{
    uint16_t count;
    uint16_t length;
    config_object_t value[1U]; /* first element of the array */
} STRUCT_UNPACKED;
typedef struct _config_object_list config_object_list_t;

STRUCT_PACKED
struct _config_report
{
    config_id_t configReportId;
    config_object_list_t configObjList;
} STRUCT_UNPACKED;
typedef struct _config_report config_report_t;

typedef uint16_t config_result_t;
#define ACCEPTED_CONFIG 0x0000U
#define UNSUPPORTED_CONFIG 0x0001U
#define STANDARD_CONFIG_UNKNOWN 0x0002U
STRUCT_PACKED
struct _config_report_rsp
{
    config_id_t configReportId;
    config_result_t configResult;
} STRUCT_UNPACKED;
typedef struct _config_report_rsp config_report_rsp_t;

typedef uint16_t data_req_mode_t;
#define DATA_REQ_START_STOP 0x8000U
#define DATA_REQ_CONTINUATION 0x4000U
#define DATA_REQ_SCOPE_ALL 0x0800U
#define DATA_REQ_SCOPE_TYPE 0x0400U
#define DATA_REQ_SCOPE_HANDLE 0x0200U
#define DATA_REQ_MODE_SINGLE_RSP 0x0080U
#define DATA_REQ_MODE_TIME_PERIOD 0x0040U
#define DATA_REQ_MODE_TIME_NO_LIMIT 0x0020U
#define DATA_REQ_MODE_DATA_REQ_PERSON_ID 0x0008U
struct _handle_list
{
    uint16_t count;
    uint16_t length;
    handle_t value[1U]; /* first element of the array */
};
typedef struct _handle_list handle_list_t;

struct _data_request
{
    data_req_id_t dataReqId;
    data_req_mode_t dataReqMode;
    relative_time_t dataReqTime;
    uint16_t dataReqPersonId;
    oid_type_t dataReqClass;
    handle_list_t dataReqobjectHandleList;
};
typedef struct _data_request data_request_t;

typedef uint16_t data_req_result_t;
#define DATA_REQ_RESULT_NO_ERROR 0U
#define DATA_REQ_RESULT_UNSPECIFIC_ERROR 1U
#define DATA_REQ_RESULT_NO_STOP_SUPPORT 2U
#define DATA_REQ_RESULT_NO_SCOPE_ALL_SUPPORT 3U
#define DATA_REQ_RESULT_NO_SCOPE_CLASS_SUPPORT 4U
#define DATA_REQ_RESULT_NO_SCOPE_HANDLE_SUPPORT 5U
#define DATA_REQ_RESULT_NO_MODE_SINGLE_RSP_SUPPORT 6U
#define DATA_REQ_RESULT_NO_MODE_TIME_PERIOD_SUPPORT 7U
#define DATA_REQ_RESULT_NO_MODE_TIME_NO_LIMIT_SUPPORT 8U
#define DATA_REQ_RESULT_NO_PERSON_ID_SUPPORT 9U
#define DATA_REQ_RESULT_UNKNOWN_PERSON_ID 11U
#define DATA_REQ_RESULT_UNKNOWN_CLASS 12U
#define DATA_REQ_RESULT_UNKNOWN_HANDLE 13U
#define DATA_REQ_RESULT_UNSUPP_SCOPE 14U
#define DATA_REQ_RESULT_UNSUPP_MODE 15U
#define DATA_REQ_RESULT_INIT_MANAGER_OVERFLOW 16U
#define DATA_REQ_RESULT_CONTINUATION_NOT_SUPPORTED 17U
#define DATA_REQ_RESULT_INVALID_REQ_ID 18U
struct _data_response
{
    relative_time_t relTimeStamp;
    data_req_result_t dataReqResult;
    oid_type_t eventType;
    any_t eventInfo;
};
typedef struct _data_response data_response_t;

typedef float_type_t simple_nu_obs_value_t;

struct _simple_nu_obs_value_cmp
{
    uint16_t count;
    uint16_t length;
    simple_nu_obs_value_t value[1U]; /* first element of the array */
};
typedef struct _simple_nu_obs_value_cmp simple_nu_obs_value_cmp_t;

typedef sfloat_type_t basic_nu_obs_value_t;

struct _basic_nu_obs_value_cmp
{
    uint16_t count;
    uint16_t length;
    basic_nu_obs_value_t value[1U]; /* first element of the array */
};
typedef struct _basic_nu_obs_value_cmp basic_nu_obs_value_cmp_t;

#endif /* _IEEE11073_TYPES_H_ */
