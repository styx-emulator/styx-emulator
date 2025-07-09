/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017 NXP
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

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"
#include "usb_device_phdc.h"
#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"
#include "ieee11073_timer.h"
#include "ieee11073_types.h"
#include "ieee11073_agent.h"
#include <stdio.h>
#include <stdbool.h>
#include "usb_shim_agent.h"
#include "weighscale.h"
#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_common.h"
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
#include "fsl_sysmpu.h"
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

#if defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0)
#include "usb_phy.h"
#endif

#include "pin_mux.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void BOARD_InitHardware(void);
void USB_DeviceClockInit(void);
void USB_DeviceIsrEnable(void);
#if USB_DEVICE_CONFIG_USE_TASK
void USB_DeviceTaskFn(void *deviceHandle);
#endif

static void USB_DeviceApplicationInit(void);
static void APP_WeightScaleSendData(uint32_t handle, weightscale_measurement_struct_t *measurementData);
static usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event, void *param);
static usb_status_t USB_DeviceWeightScaleCallback(uint32_t handle, uint32_t event, void *param);
static void USB_DeviceApplicationTask(uint32_t handle);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) uint32_t s_RecvDataBuffer[(APDU_MAX_BUFFER_SIZE + 3) / 4];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_PhdcClassBuffer[4];
/*! @brief agent instance */
usb_shim_agent_struct_t g_shimAgent;

/*! @brief device class information */
usb_device_class_config_struct_t g_agentDeviceConfig[1U] = {{
    USB_DeviceWeightScaleCallback, (class_handle_t)NULL, &g_UsbDevicePhdcWeightScaleConfig,
}};

/*! @brief device class configuration information */
usb_device_class_config_list_struct_t g_agentDeviceConfigList = {
    g_agentDeviceConfig, USB_DeviceCallback, 1U,
};

/*! @brief scan report number */
volatile uint16_t scanReportNumber = 0U;
/*! @brief application event */
volatile uint8_t appEvent = APP_EVENT_UNDEFINED;
/*! @brief the message of measurement data */
weightscale_measurement_struct_t measurement = {
    {
        /* Simple-Nu-Observed-Value = 76.2 (kg) 76.0 (kg) */
        0x02FAU, 0x02F8U,
    },
    {
        /* Simple-Nu-Observed-Value = 24.3 (kg/m2) 24.2 (kg/m2) */
        0x00F3U, 0x00F2U,
    },
};

/*! @brief association request data to send */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t g_associationRequestData[ASSOCIATION_REQUEST_LENGTH] = {
    0xE2U, 0x00U,               /* APDU CHOICE Type (AarqApdu) */
    0x00U, 0x32U,               /* CHOICE.length = 50 */
    0x80U, 0x00U, 0x00U, 0x00U, /* assoc-version */
    0x00U, 0x01U, 0x00U, 0x2AU, /* data-proto-list.count = 1 | length = 42 */
    0x50U, 0x79U,               /* data-proto-id = 20601 */
    0x00U, 0x26U,               /* data-proto-info length = 38 */
    0x80U, 0x00U, 0x00U, 0x00U, /* protocolVersion */
    0xA0U, 0x00U,               /* encoding rules = MDER or PER */
    0x80U, 0x00U, 0x00U, 0x00U, /* nomenclatureVersion */
    0x00U, 0x00U, 0x00U, 0x00U, /* functionalUnits no Test Association capabilities */
    0x00U, 0x80U, 0x00U, 0x00U, /* systemType = sys-type-agent */
    0x00U, 0x08U,               /* system-id length = 8 and value (manufacturer- and device- specific) */
    0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x40U, 0x00U, /* dev-config-id extended configuration */
    0x00U, 0x01U,                                                         /* data-req-mode-flags */
    0x01U, 0x00U,              /* data-req-init-agent-count, data-req-init-manager-count */
    0x00U, 0x00U, 0x00U, 0x00U /* optionList.count = 0 | optionList.length = 0 */
};

/*! @brief remote operation invoke event report configuration data */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t g_roivEventRepostConfigurationData[EVENT_REPORT_CONFIGURATION_LENGTH] = {
    0xE7U, 0x00U, /* APDU CHOICE Type (PrstApdu) */
    0x00U, 0xA2U, /* CHOICE.length = 162 */
    0x00U, 0xA0U, /* OCTET STRING.length = 160 */
    0x12U, 0x35U, /* invoke-id = 0x1235 (start of DataApdu. MDER encoded.) */
    0x01U, 0x01U, /* CHOICE(Remote Operation Invoke | Confirmed Event Report) */
    0x00U, 0x9AU, /* CHOICE.length = 154 */
    0x00U, 0x00U, /* obj-handle = 0 (MDS object) */
    0xFFU, 0xFFU, 0xFFU,
    0xFFU,        /* event-time = 0xFFFFFFFF */
    0x0DU, 0x1CU, /* event-type = MDC_NOTI_CONFIG */
    0x00U, 0x90U, /* event-info.length = 144 (start of ConfigReport) */
    0x40U, 0x00U, /* config-report-id */
    0x00U, 0x03U, /* config-obj-list.count = 3 Measurement objects will be announced */
    0x00U, 0x8AU, /* config-obj-list.length = 138 */
    0x00U, 0x06U, /* obj-class = MDC_MOC_VMO_METRIC_NU */
    0x00U, 0x01U, /* obj-handle = 1  (->1st Measurement is body weight) */
    0x00U, 0x04U, /* attributes.count = 4 */
    0x00U, 0x24U, /* attributes.length = 36 */
    0x09U, 0x2FU, /* attribute-id = MDC_ATTR_ID_TYPE */
    0x00U, 0x04U, /* attribute-value.length = 4 */
    0x00U, 0x02U, 0xE1U,
    0x40U,        /* MDC_PART_SCADA | MDC_MASS_BODY_ACTUAL */
    0x0AU, 0x46U, /* attribute-id = MDC_ATTR_METRIC_SPEC_SMALL */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0xF0U, 0x40U, /* intermittent, stored data, upd & msmt aperiodic, agent init, measured */
    0x09U, 0x96U, /* attribute-id = MDC_ATTR_UNIT_CODE */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0x06U, 0xC3U, /* MDC_DIM_KILO_G */
    0x0AU, 0x55U, /* attribute-id = MDC_ATTR_ATTRIBUTE_VAL_MAP */
    0x00U, 0x0CU, /* attribute-value.length = 12 */
    0x00U, 0x02U, /* AttrValMap.count = 2 */
    0x00U, 0x08U, /* AttrValMap.length = 8 */
    0x0AU, 0x56U, 0x00U,
    0x04U, /* MDC_ATTR_NU_VAL_OBS_SIMP | value length = 4 */
    0x09U, 0x90U, 0x00U,
    0x08U,        /* MDC_ATTR_TIME_STAMP_ABS | value length = 8 */
    0x00U, 0x06U, /* obj-class = MDC_MOC_VMO_METRIC_NU */
    0x00U, 0x02U, /* obj-handle = 2 (-> 2nd Measurement is body height) */
    0x00U, 0x04U, /* attributes.count = 4 */
    0x00U, 0x24U, /* attributes.length = 36 */
    0x09U, 0x2FU, /* attribute-id = MDC_ATTR_ID_TYPE */
    0x00U, 0x04U, /* attribute-value.length = 4 */
    0x00U, 0x02U, 0xE1U,
    0x44U,        /* MDC_PART_SCADA | MDC_LEN_BODY_ACTUAL */
    0x0AU, 0x46U, /* attribute-id = MDC_ATTR_METRIC_SPEC_SMALL */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0xF0U, 0x48U, /* intermittent, stored data, upd & msmt aperiodic, agent init, manual */
    0x09U, 0x96U, /* attribute-id = MDC_ATTR_UNIT_CODE */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0x05U, 0x11U, /* MDC_DIM_CENTI_M */
    0x0AU, 0x55U, /* attribute-id = MDC_ATTR_ATTRIBUTE_VAL_MAP */
    0x00U, 0x0CU, /* attribute-value.length = 12 */
    0x00U, 0x02U, /* AttrValMap.count = 2 */
    0x00U, 0x08U, /* AttrValMap.length = 8 */
    0x0AU, 0x56U, 0x00U,
    0x04U, /* MDC_ATTR_NU_VAL_OBS_SIMP, 4 */
    0x09U, 0x90U, 0x00U,
    0x08U,        /* MDC_ATTR_TIME_STAMP_ABS, 8 */
    0x00U, 0x06U, /* obj-class = MDC_MOC_VMO_METRIC_NU */
    0x00U, 0x03U, /* obj-handle = 3 (-> 3rd Measurement is body mass index) */
    0x00U, 0x05U, /* attributes.count = 5 */
    0x00U, 0x2AU, /* attributes.length = 42 */
    0x09U, 0x2FU, /* attribute-id = MDC_ATTR_ID_TYPE */
    0x00U, 0x04U, /* attribute-value.length = 4 */
    0x00U, 0x02U, 0xE1U,
    0x50U,        /* MDC_PART_SCADA | MDC_RATIO_MASS_BODY_LEN_SQ */
    0x0AU, 0x46U, /* attribute-id = MDC_ATTR_METRIC_SPEC_SMALL */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0xF0U, 0x42U, /* intermittent, stored data, upd & msmt aperiodic, agent init, calculated */
    0x09U, 0x96U, /* attribute-id = MDC_ATTR_UNIT_CODE */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0x07U, 0xA0U, /* MDC_DIM_KG_PER_M_SQ */
    0x0AU, 0x47U, /* attribute-id = MDC_ATTR_SOURCE_HANDLE_REF */
    0x00U, 0x02U, /* attribute-value.length = 2 */
    0x00U, 0x01U, /* reference handle = 1 */
    0x0AU, 0x55U, /* attribute-id = MDC_ATTR_ATTRIBUTE_VAL_MAP */
    0x00U, 0x0CU, /* attribute-value.length = 12 */
    0x00U, 0x02U, /* AttrValMap.count = 2 */
    0x00U, 0x08U, /* AttrValMap.length = 8 */
    0x0AU, 0x56U, 0x00U,
    0x04U, /* MDC_ATTR_NU_VAL_OBS_SIMP, 4 */
    0x09U, 0x90U, 0x00U,
    0x08U /* MDC_ATTR_TIME_STAMP_ABS, 8 */
};

/*! @brief remote operation response | Get with all MDS attributes */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t g_rorsCmipGetData[EVENT_RESPONSE_GET_LENGTH] = {
    0xE7U, 0x00U, /* APDU CHOICE Type (PrstApdu) */
    0x00U, 0x6EU, /* CHOICE.length = 110 */
    0x00U, 0x6CU, /* OCTET STRING.length = 108 */
    0x12U, 0x34U, /* invoke-id = 0x1234 (mirrored from request) */
    0x02U, 0x03U, /* CHOICE (Remote Operation Response | Get) */
    0x00U, 0x66U, /* CHOICE.length = 102 */
    0x00U, 0x00U, /* handle = 0 (MDS object) */
    0x00U, 0x06U, /* attribute-list.count = 6 */
    0x00U, 0x60U, /* attribute-list.length = 96 */
    0x0AU, 0x5AU, /* attribute id = MDC_ATTR_SYS_TYPE_SPEC_LIST */
    0x00U, 0x08U, /* attribute-value.length = 8 */
    0x00U, 0x01U, /* TypeVerList count = 1 */
    0x00U, 0x04U, /* TypeVerList length = 4 */
    0x10U, 0x0FU, /* type = MDC_DEV_SPEC_PROFILE_SCALE */
    0x00U, 0x01U, /* version = version 1 of the specialization */
    0x09U, 0x28U, /* attribute-id = MDC_ATTR_ID_MODEL */
    0x00U, 0x1AU, /* attribute-value.length = 26 */
    0x00U, 0x0AU, /* string length = 10 | Freescale\0 */
    0x46U, 0x72U, 0x65U, 0x65U, 0x73U, 0x63U, 0x61U, 0x6CU, 0x65U, 0x00U, 0x00U, 0x0CU, /* string length = 12 |
                                                                                           WeightScale\0 */
    0x57U, 0x65U, 0x69U, 0x67U, 0x68U, 0x74U, 0x53U, 0x63U, 0x61U, 0x6CU, 0x65U, 0x00U, 0x09U,
    0x84U,                                                                /* attribute-id = MDC_ATTR_SYS_ID */
    0x00U, 0x0AU,                                                         /* attribute-value.length = 10 */
    0x00U, 0x08U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, /* octet string length = 8 | EUI-64 */
    0x0aU, 0x44U,                                                         /* attribute-id = MDC_ATTR_DEV_CONFIG_ID */
    0x00U, 0x02U,                                                         /* attribute-value.length = 2 */
    0x40U, 0x00U,                                           /* dev-config-id = 16384 (extended-config-start) */
    0x09U, 0x2DU,                                           /* attribute-id = MDC_ATTR_ID_PROD_SPECN */
    0x00U, 0x12U,                                           /* attribute-value.length = 18 */
    0x00U, 0x01U,                                           /* ProductionSpec.count = 1 */
    0x00U, 0x0EU,                                           /* ProductionSpec.length = 14 */
    0x00U, 0x01U,                                           /* ProdSpecEntry.spec-type = 1 (serial-number) */
    0x00U, 0x00U,                                           /* ProdSpecEntry.component-id = 0 */
    0x00U, 0x08U, 0x44U, 0x45U,                             /* string length = 8 | prodSpecEntry.prod-spec = DE124567 */
    0x31U, 0x32U, 0x34U, 0x35U, 0x36U, 0x37U, 0x09U, 0x87U, /* attribute-id =MDC_ATTR_TIME_ABS */
    0x00U, 0x08U,                                           /* attribute-value.length = 8 */
    0x20U, 0x07U, 0x02U, 0x01U,                             /* Absolute-Time-Stamp = 2007-02-01T12:05:0000 */
    0x12U, 0x05U, 0x00U, 0x00};

/*! @brief measurements to send */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t g_eventReportData[EVENT_REPORT_DATA_LENGTH] = {
    0xE7U, 0x00U,               /* APDU CHOICE Type (PrstApdu) */
    0x00U, 0x5AU,               /* CHOICE.length = 90 */
    0x00U, 0x58U,               /* OCTET STRING.length = 88 */
    0x12U, 0x36U,               /* invoke-id = 0x1236 */
    0x01U, 0x01U,               /* CHOICE(Remote Operation Invoke | Confirmed Event Report) */
    0x00U, 0x52U,               /* CHOICE.length = 82 */
    0x00U, 0x00U,               /* obj-handle = 0 (MDS object) */
    0x00U, 0x00U, 0x00U, 0x00U, /* event-time = 0 */
    0x0DU, 0x1DU,               /* event-type = MDC_NOTI_SCAN_REPORT_FIXED */
    0x00U, 0x48U,               /* event-info.length = 72 */
    0xF0U, 0x00U,               /* ScanReportInfoFixed.data-req-id = 0xF000 */
    0x00U, 0x00U,               /* ScanReportInfoFixed.scan-report-no = 0 */
    0x00U, 0x04U,               /* ScanReportInfoFixed.obs-scan-fixed.count = 4 */
    0x00U, 0x40U,               /* ScanReportInfoFixed.obs-scan-fixed.length = 64 */
    0x00U, 0x01U,               /* ScanReportInfoFixed.obs-scan-fixed.value[0].obj-handle = 1 */
    0x00U, 0x0CU,               /* ScanReportInfoFixed.obs-scan-fixed.value[0]. obs-val-data.length = 12 */
    0xFFU, 0x00U, 0x02U, 0xFAU, /* Simple-Nu-Observed-Value = 76.2 (kg) */
    0x20U, 0x07U, 0x12U, 0x06U, /* Absolute-Time-Stamp = 2007-12-06T12:10:0000 */
    0x12U, 0x10U, 0x00U, 0x00U, 0x00U, 0x03U, /* ScanReportInfoFixed.obs-scan-fixed.value[1].obj-handle = 3 */
    0x00U, 0x0CU,               /* ScanReportInfoFixed.obs-scan-fixed.value[1]. obs-val-data.length = 12 */
    0xFFU, 0x00U, 0x00U, 0xF3U, /* Simple-Nu-Observed-Value = 24.3 (kg/m2) */
    0x20U, 0x07U, 0x12U, 0x06U, /* Absolute-Time-Stamp = 2007-12-06T12:10:0000 */
    0x12U, 0x10U, 0x00U, 0x00U, 0x00U, 0x01U, /* ScanReportInfoFixed.obs-scan-fixed.value[0].obj-handle = 1 */
    0x00U, 0x0CU,               /* ScanReportInfoFixed.obs-scan-fixed.value[0]. obs-val-data.length = 12 */
    0xFFU, 0x00U, 0x02U, 0xF8U, /* Simple-Nu-Observed-Value = 76.0 (kg) */
    0x20U, 0x07U, 0x12U, 0x06U, /* Absolute-Time-Stamp = 2007-12-06T20:05:0000 */
    0x20U, 0x05U, 0x00U, 0x00U, 0x00U, 0x03U, /* ScanReportInfoFixed.obs-scan-fixed.value[1].obj-handle = 3 */
    0x00U, 0x0CU,               /* ScanReportInfoFixed.obs-scan-fixed.value[1]. obs-val-data.length = 12 */
    0xFFU, 0x00U, 0x00U, 0xF2U, /* Simple-Nu-Observed-Value = 24.2 (kg/m2) */
    0x20U, 0x07U, 0x12U, 0x06U, /* Absolute-Time-Stamp = 2007-12-06T20:05:0000 */
    0x20U, 0x05U, 0x00U, 0x00U};

/*******************************************************************************
 * Code
 ******************************************************************************/
#if (defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U))
void USB0_IRQHandler(void)
{
    USB_DeviceKhciIsrFunction(g_shimAgent.deviceHandle);
    /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
    exception return operation might vector to incorrect interrupt */
    __DSB();
}
#endif
void USB_DeviceClockInit(void)
{
#if defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U)
    SystemCoreClockUpdate();
    CLOCK_EnableUsbfs0Clock(kCLOCK_UsbSrcPll0, CLOCK_GetFreq(kCLOCK_PllFllSelClk));
/*
 * If the SOC has USB KHCI dedicated RAM, the RAM memory needs to be clear after
 * the KHCI clock is enabled. When the demo uses USB EHCI IP, the USB KHCI dedicated
 * RAM can not be used and the memory can't be accessed.
 */
#if (defined(FSL_FEATURE_USB_KHCI_USB_RAM) && (FSL_FEATURE_USB_KHCI_USB_RAM > 0U))
#if (defined(FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS) && (FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS > 0U))
    for (int i = 0; i < FSL_FEATURE_USB_KHCI_USB_RAM; i++)
    {
        ((uint8_t *)FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS)[i] = 0x00U;
    }
#endif /* FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS */
#endif /* FSL_FEATURE_USB_KHCI_USB_RAM */
#endif
}
void USB_DeviceIsrEnable(void)
{
    uint8_t irqNumber;
#if defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U)
    uint8_t usbDeviceKhciIrq[] = USB_IRQS;
    irqNumber = usbDeviceKhciIrq[CONTROLLER_ID - kUSB_ControllerKhci0];
#endif
/* Install isr, set priority, and enable IRQ. */
#if defined(__GIC_PRIO_BITS)
    GIC_SetPriority((IRQn_Type)irqNumber, USB_DEVICE_INTERRUPT_PRIORITY);
#else
    NVIC_SetPriority((IRQn_Type)irqNumber, USB_DEVICE_INTERRUPT_PRIORITY);
#endif
    EnableIRQ((IRQn_Type)irqNumber);
}
#if USB_DEVICE_CONFIG_USE_TASK
void USB_DeviceTaskFn(void *deviceHandle)
{
#if defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U)
    USB_DeviceKhciTaskFunction(deviceHandle);
#endif
}
#endif

/*!
 * @brief medical callback.
 * This function handles the callback of medical system.
 *
 * @param handle        the handle points to agent handle.
 * @param eventType     the event type.
 * @param data          the pointer to callback data.
 *
 * @return None.
 */
void AGENT_MedicalCallback(uint32_t handle, uint8_t eventType, uint8_t *data)
{
    switch (eventType)
    {
        case AGENT_EVENT_CONNECTED:
            scanReportNumber = 0U;
            appEvent = APP_EVENT_SEND_ASSOCIATION_REQUEST;
            break;
        case AGENT_EVENT_ACCEPTED_UNKNOWN_CONFIG_AARQ:
            appEvent = APP_EVENT_SEND_DEVICE_CONFIGURATION;
            break;
        case AGENT_EVENT_REJECTED_AARQ:
        case AGENT_EVENT_ACCEPTED_AARQ:
        case AGENT_EVENT_UNSUPPORTED_CONFIG:
        case AGENT_EVENT_ACCEPTED_CONFIG:
            break;
        case AGENT_EVENT_RECV_ROIV_CMIP_GET:
        {
/* The invokeID is mirrored from request */
#if (ENDIANNESS == USB_BIG_ENDIAN)
            g_rorsCmipGetData[7] = *data;
            g_rorsCmipGetData[6] = *((uint8_t *)(data + 1U));
#else
            g_rorsCmipGetData[6] = *data;
            g_rorsCmipGetData[7] = *((uint8_t *)(data + 1U));
#endif
            appEvent = APP_EVENT_SEND_MDS_OBJECT;
        }
        break;
        case AGENT_EVENT_RORS_CMIP_GET_SENT:
        case AGENT_EVENT_MEASUREMENT_SENT:
            /* update the measurement data */
            measurement.weight[0U]++;
            measurement.weight[1U]++;
            /* The weighs will be less than 100kg */
            measurement.weight[0U] %= 1000U;
            measurement.weight[1U] %= 1000U;
            measurement.bodyMassIndex[0U]++;
            measurement.bodyMassIndex[1U]++;
            /* The body mass index will be less than 50 kg/m2 */
            measurement.bodyMassIndex[0U] %= 500U;
            measurement.bodyMassIndex[1U] %= 500U;
            appEvent = APP_EVENT_SEND_MEASUREMENT_DATA;
            break;
        default:
            break;
    }
}

/*!
 * @brief send weight scale data.
 * This function is called to send the weight data to the host.
 *
 * @param handle           the handle points to agent handle.
 * @param measurement      measurement data to send.
 */
static void APP_WeightScaleSendData(uint32_t handle, weightscale_measurement_struct_t *measurementData)
{
    /* second offset */
    static uint8_t secondOffset = 0U;
    /* minute offset */
    static uint8_t minuteOffset[4U] = {0U, 0U, 5U, 5U};
    /* hour offset */
    static uint8_t hourOffset[4U] = {2U, 2U, 2U, 2U};
    /* update scan report number */
    uint8_t *scanReportTemp = (uint8_t *)&g_eventReportData[24U];
    USB_SHORT_TO_BIG_ENDIAN_ADDRESS(scanReportNumber, scanReportTemp);
    secondOffset++;
    /* update absolute time data */
    for (uint16_t timeOffset = 0U; timeOffset < 4U; timeOffset++)
    {
        absolute_time_t *absoluteTime = (absolute_time_t *)&g_eventReportData[38U + timeOffset * 16U];
        if (!(secondOffset % 10U))
        {
            /* update the time in second */
            secondOffset = 0U;
            absoluteTime->second += 7U;
        }
        else
        {
            absoluteTime->second += 1U;
        }
        if (0x60U <= absoluteTime->second)
        {
            /* update the time in minute */
            minuteOffset[timeOffset]++;
            absoluteTime->second = 0U;
            if (!(minuteOffset[timeOffset] % 10U))
            {
                minuteOffset[timeOffset] = 0U;
                absoluteTime->minute += 7U;
            }
            else
            {
                absoluteTime->minute += 1U;
            }
        }
        if (0x60U <= absoluteTime->minute)
        {
            /* update the time in hour */
            hourOffset[timeOffset]++;
            absoluteTime->minute = 0U;
            if (!(hourOffset[timeOffset] % 10U))
            {
                hourOffset[timeOffset] = 0U;
                absoluteTime->hour += 7U;
            }
            else
            {
                absoluteTime->hour += 1U;
            }
        }
        if (0x24 <= absoluteTime->hour)
        {
            absoluteTime->hour = 0U;
        }
    }
    for (uint8_t dataOffset = 0U; dataOffset < 4U; dataOffset++)
    {
        uint8_t dataIndex = (uint8_t)(dataOffset >> 1U);
        uint8_t *dataTemp = (uint8_t *)&g_eventReportData[36U + dataOffset * 16U];
        if ((dataOffset & 0x01U) == 0U)
        {
            /* update weight data */
            USB_SHORT_TO_BIG_ENDIAN_ADDRESS(measurementData->weight[dataIndex], dataTemp);
        }
        else
        {
            /* update BMI data */
            USB_SHORT_TO_BIG_ENDIAN_ADDRESS(measurementData->bodyMassIndex[dataIndex], dataTemp);
        }
    }
    if (kStatus_USB_Success == USB_ShimAgentSendData(handle, AGENT_SEND_DATA_QOS, (uint8_t *)(&g_eventReportData[0]),
                                                     EVENT_REPORT_DATA_LENGTH))
    {
        /* update the scan report number */
        scanReportNumber++;
    }
}

/*!
 * @brief device callback function.
 * This function handles the usb standard event. more information, please refer to usb spec chapter 9.
 *
 * @param handle          The USB device handle.
 * @param event           The USB device event type.
 * @param param           The parameter of the device specific request.
 *
 * @return kStatus_USB_Success or error.
 */
static usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event, void *param)
{
    usb_status_t error = kStatus_USB_Error;
    uint16_t *temp16 = (uint16_t *)param;
    uint8_t *temp8 = (uint8_t *)param;
    switch (event)
    {
        case kUSB_DeviceEventBusReset:
        {
            g_shimAgent.attach = 0U;
#if (defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U)) || \
    (defined(USB_DEVICE_CONFIG_LPCIP3511HS) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))
            /* Get USB speed to configure the device, including max packet size and interval of the endpoints. */
            if (kStatus_USB_Success == USB_DeviceClassGetSpeed(CONTROLLER_ID, &g_shimAgent.speed))
            {
                USB_DeviceSetSpeed(handle, g_shimAgent.speed);
            }
#endif
            /* save endpoint information */
            /* bulk out endpoint information */
            if (USB_SPEED_HIGH == g_shimAgent.speed)
            {
                g_shimAgent.bulkOutData.epMaxPacketSize = HS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE;
            }
            else
            {
                g_shimAgent.bulkOutData.epMaxPacketSize = FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE;
            }
            g_shimAgent.bulkOutData.epNumber = USB_PHDC_BULK_ENDPOINT_OUT;
            g_shimAgent.bulkOutData.transferCount = 0U;
            g_shimAgent.bulkOutData.recvData.transferSize = 0U;
            g_shimAgent.bulkOutData.recvData.buffer = NULL;
            /* bulk in endpoint information */
            g_shimAgent.bulkInData.epNumber = USB_PHDC_BULK_ENDPOINT_IN;
            g_shimAgent.bulkInData.seller = 0U;
            g_shimAgent.bulkInData.buyer = 0U;
            /* interrupt in endpoint information */
            g_shimAgent.interruptInData.epNumber = USB_PHDC_INTERRUPT_ENDPOINT_IN;
            g_shimAgent.interruptInData.seller = 0U;
            g_shimAgent.interruptInData.buyer = 0U;

            /* no endpoint has data */
            g_shimAgent.endpointsHaveData = 0U;
#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
            /* disable meta-data message preamble feature */
            g_shimAgent.isMetaDataMessagePreambleEnabled = 0U;
            /* initialize the number of transfer followed preamble message */
            g_shimAgent.numberTransferBulkOut = 0U;
            g_shimAgent.numberTransferBulkIn = 0U;
#endif
            appEvent = APP_EVENT_UNDEFINED;
            AGENT_SetAgentState(g_shimAgent.classHandle, AGENT_STATE_DISCONNECTED);
        }
        break;
        case kUSB_DeviceEventSetConfiguration:
            if (param)
            {
                g_shimAgent.attach = 1;
                g_shimAgent.currentConfig = *temp8;
            }
            /* send the first NULL data to establish a connection between the device and host */
            USB_ShimAgentSendData(g_shimAgent.classHandle, AGENT_SEND_DATA_QOS, NULL, 0U);
            /* prepare for the first receiving */
            USB_DevicePhdcRecv(g_shimAgent.classHandle, g_shimAgent.bulkOutData.epNumber, g_shimAgent.recvDataBuffer,
                               g_shimAgent.bulkOutData.epMaxPacketSize);
            break;
        case kUSB_DeviceEventSetInterface:
            if (g_shimAgent.attach)
            {
                uint8_t interface = (uint8_t)((*temp16 & 0xFF00U) >> 0x08U);
                uint8_t alternateSetting = (uint8_t)(*temp16 & 0x00FFU);
                if (interface < 1U)
                {
                    g_shimAgent.currentInterfaceAlternateSetting[interface] = alternateSetting;
                }
            }
            break;
        case kUSB_DeviceEventGetConfiguration:
            if (param)
            {
                /* Get the current configuration request */
                *temp8 = g_shimAgent.currentConfig;
                error = kStatus_USB_Success;
            }
            break;
        case kUSB_DeviceEventGetInterface:
            if (param)
            {
                uint8_t interface = (uint8_t)((*temp16 & 0xFF00U) >> 0x08U);
                if (interface < USB_PHDC_WEIGHT_SCALE_INTERFACE_COUNT)
                {
                    *temp16 = (*temp16 & 0xFF00U) | g_shimAgent.currentInterfaceAlternateSetting[interface];
                    error = kStatus_USB_Success;
                }
                else
                {
                    error = kStatus_USB_InvalidRequest;
                }
            }
            break;
        case kUSB_DeviceEventGetDeviceDescriptor:
            if (param)
            {
                error = USB_DeviceGetDeviceDescriptor(handle, (usb_device_get_device_descriptor_struct_t *)param);
            }
            break;
        case kUSB_DeviceEventGetConfigurationDescriptor:
            if (param)
            {
                error = USB_DeviceGetConfigurationDescriptor(handle,
                                                             (usb_device_get_configuration_descriptor_struct_t *)param);
            }
            break;
        case kUSB_DeviceEventGetStringDescriptor:
            if (param)
            {
                error = USB_DeviceGetStringDescriptor(handle, (usb_device_get_string_descriptor_struct_t *)param);
            }
            break;
        default:
            break;
    }
    return error;
}

/*!
 * @brief device weight scale callback function.
 * This function handles the PHDC class specified event.
 *
 * @param handle          The USB class  handle.
 * @param event           The USB device event type.
 * @param param           The parameter of the class specific event.
 *
 * @return kStatus_USB_Success or error.
 */
static usb_status_t USB_DeviceWeightScaleCallback(uint32_t handle, uint32_t event, void *param)
{
    usb_device_control_request_struct_t *request = (usb_device_control_request_struct_t *)param;
    usb_status_t error = kStatus_USB_Success;

    switch (event)
    {
        case kUSB_DevicePhdcEventInterruptInSendComplete:
        case kUSB_DevicePhdcEventBulkInSendComplete:
        {
            usb_device_endpoint_callback_message_struct_t *message =
                (usb_device_endpoint_callback_message_struct_t *)param;
            if ((NULL != message) && (message->length == USB_UNINITIALIZED_VAL_32))
            {
                error = kStatus_USB_Error;
            }
            else
            {
                error = USB_ShimAgentSendComplete(handle, event, param);
            }
        }
        break;
        case kUSB_DevicePhdcEventDataReceived:
            error = USB_ShimAgentRecvComplete(handle, param);
            break;
        case kUSB_DevicePhdcEventSetFeature:
#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
            /* Meta-data message preamble is enabled */
            g_shimAgent.isMetaDataMessagePreambleEnabled = 1U;
#else
            /* Respond the request with a stall */
            error = kStatus_USB_InvalidRequest;
#endif
            break;
        case kUSB_DevicePhdcEventClearFeature:
#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
            /* Meta-data message preamble is disabled */
            g_shimAgent.isMetaDataMessagePreambleEnabled = 0U;
#else
            /* Respond the request with a stall */
            error = kStatus_USB_InvalidRequest;
#endif
            break;
        case kUSB_DevicePhdcEventGetStatus:
            g_shimAgent.classBuffer[0] = ((uint8_t *)(&g_shimAgent.endpointsHaveData))[0];
            g_shimAgent.classBuffer[1] = ((uint8_t *)(&g_shimAgent.endpointsHaveData))[1];
            request->buffer = g_shimAgent.classBuffer;
            request->length = 2U;
            break;
        default:
            error = kStatus_USB_InvalidRequest;
            break;
    }
    return error;
}

/*!
 * @brief application initialization.
 * This function is the entry for the application (or other usage)
 *
 * @return None.
 */
static void USB_DeviceApplicationInit(void)
{
    USB_DeviceClockInit();
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
    SYSMPU_Enable(SYSMPU, 0);
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

    g_shimAgent.speed = USB_SPEED_FULL;
    g_shimAgent.attach = 0U;
    g_shimAgent.deviceHandle = NULL;
    g_shimAgent.recvDataBuffer = (uint8_t *)(&s_RecvDataBuffer[0]);
    g_shimAgent.classBuffer = s_PhdcClassBuffer;

    if (kStatus_USB_Success != USB_DeviceClassInit(CONTROLLER_ID, &g_agentDeviceConfigList, &g_shimAgent.deviceHandle))
    {
        usb_echo("USB device PHDC weighscale demo init failed\r\n");
    }
    else
    {
        usb_echo("USB device PHDC weighscale demo\r\n");
        g_shimAgent.classHandle = g_agentDeviceConfigList.config[0].classHandle;
        /* Initialize the Agent interface */
        AGENT_Init(g_shimAgent.classHandle);
    }
    /* Install isr, set priority, and enable IRQ. */
    USB_DeviceIsrEnable();

    USB_DeviceRun(g_shimAgent.deviceHandle);
}

static void USB_DeviceApplicationTask(uint32_t handle)
{
    switch (appEvent)
    {
        /* bulk in qos is 0x08 - Medium/Best latency, reliability - the time needed
        for a piece of information to send is from 20ms to 200ms, the device should
        wait at least 20ms before sending the data to the host */
        case APP_EVENT_SEND_ASSOCIATION_REQUEST:
            for (uint32_t i = 10000000U; i > 0U; i--)
            {
                if (APP_EVENT_SEND_ASSOCIATION_REQUEST != appEvent)
                {
                    return;
                }
            }
            appEvent = APP_EVENT_UNDEFINED;
            AGENT_SendAssociationRequest(handle, (uint8_t *)(&g_associationRequestData[0]), ASSOCIATION_REQUEST_LENGTH);
            break;
        case APP_EVENT_SEND_DEVICE_CONFIGURATION:
            appEvent = APP_EVENT_UNDEFINED;
            AGENT_SendConfig(handle, g_roivEventRepostConfigurationData, EVENT_REPORT_CONFIGURATION_LENGTH);
            break;
        case APP_EVENT_SEND_MDS_OBJECT:
        {
            appEvent = APP_EVENT_UNDEFINED;
            USB_ShimAgentSendData(handle, AGENT_SEND_DATA_QOS, (uint8_t *)(&g_rorsCmipGetData[0]),
                                  EVENT_RESPONSE_GET_LENGTH);
        }
        break;
        case APP_EVENT_SEND_MEASUREMENT_DATA:
            for (uint32_t i = 10000000U; i > 0U; i--)
            {
                if (APP_EVENT_SEND_MEASUREMENT_DATA != appEvent)
                {
                    return;
                }
            }
            appEvent = APP_EVENT_UNDEFINED;
            APP_WeightScaleSendData(handle, &measurement);
            break;
        default:
            break;
    }
}

#if defined(__CC_ARM) || defined(__GNUC__)
int main(void)
#else
void main(void)
#endif
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    USB_DeviceApplicationInit();
    while (1U)
    {
#if USB_DEVICE_CONFIG_USE_TASK
        USB_DeviceTaskFn(g_shimAgent.deviceHandle);
#endif
        USB_DeviceApplicationTask(g_shimAgent.classHandle);
    }
}
/* EOF */
