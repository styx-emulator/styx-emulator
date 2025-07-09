/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
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
 *
 */

#ifndef __EMVL1_CORE_H__
#define __EMVL1_CORE_H__

#include "fsl_smartcard.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @addtogroup emvl1 EMV L1 Stack (EMVL1)
 * @{
 */

/*! @file */

/*! @brief EMV L1 version
 * Current version: 2.1.0
 *
 * Change log:
 *  - Version 2.0.1
 *     - fixed protocol timers issues during emvl1 pre-certification tests.
 *     - fixed improper T0 commands response receiving (commands case3 & case4 affected)
 *       what causes long commands responses.
 *  - Version 2.0.2
 *     - Re-implemented function for sending commands in T=0
 *     - fixed wrong size of response in T=0
 *     - fixed problem with command cases 3 in T=1, expected wrong length of response
 *     - fixed wrong length of response in T=1
 *     - fixed usage application buffer for data payload and overhead associated with T=1 protocol
 *  - Version 2.1.0
 *     - Added abort transfer functionality
 */
#define FSL_EMVL1_VERSION (MAKE_VERSION(2, 1, 0))

/*! @brief For an unknown block length, wait for a maximum possible T1 block length. */
#define EMVL1_LEN_UNKNOWN_T1 (258u)
/*! @brief Maximum T1 block retransmit count */
#define EMVL1_T1_BLOCK_RETRANSMIT_MAX (3u)
/*! @brief Maximum number of continuous erroneous block receptions */
#define EMVL1_T1_BLOCK_RECEIVE_ERROR_MAX (2u)
/* Maximum transfer length = 3(prologue bytes for T=1) + 254(INF field size for T=1) + 1(EDC field size for T=1) */
/*! @brief Maximum transfer T0/T1 size */
#define EMVL1_MAX_TRANSFER_SIZE (258u)
/*! @brief Number of attempts to send and receive IFS(Information field size) response. */
#define EMVL1_IFS_ATTEMPTS (3u)

#define APDU_case1S 0
#define APDU_case2S 1
#define APDU_case3S 2
#define APDU_case4S 3

#define APDU_case2E 4
#define APDU_case3E 5
#define APDU_case4E 6
#define APDU_caseNone 0xFF

#define CLA_OFFSET 0
#define INS_OFFSET 1
#define P1_OFFSET 2
#define P2_OFFSET 3
#define P3_OFFSET 4

typedef struct
{
    uint8_t apdu_case;
    uint8_t CLA; /* sent command currently */
    uint8_t INS;
    uint8_t P1;
    uint8_t P2;
    uint8_t P3_LEN;
    uint8_t *exchange_buf; /* set to localTxBuf */
} t0_session_t;

/*! @brief Smart Card command case types */
typedef enum _smartcard_command_case
{
    kSCCommandCase1 = 1,
    kSCCommandCase2,
    kSCCommandCase3,
    kSCCommandCase4
} smartcard_command_case_t;

/*! @brief Smart Card T=1 block types */
typedef enum _smartcard_block_type
{
    kSCIBlock = 1,    /*!< I-Block for T=1 protocol*/
    kSCRBlock,        /*!< R-Block for T=1 protocol*/
    kSCSBlockRequest, /*!< S-Block Request for T=1 protocol*/
    kSCSBlockResponse /*!< S-Block Response for T=1 protocol*/
} smartcard_block_type_t;

/*! @brief Smart Card core error types */
typedef enum _smartcard_core_error
{
    kSCCoreSuccess = 0,                   /*!< Valid status bytes are received */
    kSCCoreTransportTxFail,               /*!< Transmitting command APDU failed */
    kSCCoreTransportRxFail,               /*!< Receiving response APDU failed */
    kSCCoreIncorrectStatusBytes,          /*!< Invalid status bytes received */
    kSCCoreGRPartOfReturnedDataCorrupted, /*!< Part of the returned data may be corrupted */
    kSCCoreGRLengthFieldIncorrect,        /*!< Length field incorrect */
    kSCCoreGRP1P2NonZero,                 /*!< P1 and P2 bytes sent in command APDU are non zero */
    kSCCoreGRNoPreciseDiagnosis,          /*!< No precise diagnosis can be done */
    kSCCoreGRIncorrectReceiveLength,      /*!< Incorrect GR receive length */
    kSCCoreCLANotSupported,               /*!< CLass byte sent in command APDU is not supported */
    kSCCoreINSInvalid,                    /*!< Instruction byte sent in command APDU is invalid */
    kSCCoreP1P2Invalid,                   /*!< P1 and P2 bytes sent in command APDU are invalid */
    kSCCoreP3Invalid,                     /*!< P3 byte sent in command APDU is invalid */
    kSCCoreCommandNotSupported,           /*!< Command APDU sent is not valid */
    kSCCoreUnknownProcByte,               /*!< The procedure bytes received are unknown */
    kSCCoreIOError,                       /*!< Any general IO error, e.g, didn't receive data */
    kSCCoreT1TxRetryExceeded,             /*!< Indicates whether Retry limit while sending T1 block has exceeded*/
    kSCCoreT1RxErrorExceeded,             /*!< Indicates whether Error limit while receiving T1 block has exceeded*/
    kSCCoreT1INFLengthInvalid,            /*!< The INF length byte received is invalid */
    kSCCoreT1AbortRequestReceived,        /*!< Abort Request received */
    kSCCoreInvalidInputParameter,         /*!< Invalid input parameter */
    kSCCoreOther,                         /*!< Other errors*/
    kSCCoreFail,                          /*!< Fail due to any reasons */
    kSCoreCardMuted,                      /*!< Resynch failed */
    kSCCoreResynchronised,                /*!< Err, but resynchronished */
    kSCCoreAPDUInvalidSize,               /*!< Apdu size error */
    kSCCoreTransferAborted                /*!< Transfer was aborted */
} smartcard_core_error_t;

/* typedefs */

/*! @brief Terminal Abstraction Layer (TAL) command handle-specific data structure */
typedef struct
{
    uint8_t *header; /*!< Apdu header */
    uint8_t *apdu;   /*!< Apdu pointer */
    uint16_t length; /*!< Command length */
} smartcard_tal_cmd_t;

/*! @brief Terminal Abstraction Layer (TAL) response handle-specific data structure */
typedef struct
{
    uint8_t *resp;   /*!< Response pointer */
    uint16_t length; /*!< Response length */
} smartcard_tal_resp_t;

/*! @brief Terminal Transport Layer (TTL) command handle-specific data structure */
typedef struct
{
    uint8_t ttype;     /*!< Transport type*/
    uint8_t *prolog;   /*!< Prologue pointer */
    uint8_t *inf;      /*!< Command pointer */
    uint8_t *epilogue; /*!< Epilogue pointer */
    uint16_t length;   /*!< Command length */
} smartcard_ttl_cmd_t;

/*! @brief Terminal Transport Layer (TTL) response handle-specific data structure */
typedef struct
{
    uint8_t *resp;   /*!< Response pointer */
    uint16_t length; /*!< Response length */
} smartcard_ttl_resp_t;

/*! @brief Terminal Transport Layer (TTL) parameters specific to the block sequence number handling */
typedef struct
{
    uint8_t rxISSN;     /*!< Receive Sequence Number for PCB-I block */
    uint8_t rxRSSN;     /*!< Receive Sequence Number for PCB R block */
    uint8_t txISSN;     /*!< Send Sequence Number for PCB I block */
    uint8_t txRSSN;     /*!< Send Sequence Number for PCB R block */
    uint8_t moreTx;     /*!< More bit for PCB for Transmission */
    uint8_t moreRx;     /*!< More bit for PCB for receiving */
#ifdef USE_NEW_T1_PRTOL /* For new T1 stack  in future */
    uint8_t card_nad;   /* Initialize at active,  emv card_nad = reader_nad = 0 */
    uint8_t reader_nad;
    uint8_t last_tx_Iblock_sn; /* Save the seq number of sent i-block */
    uint8_t next_rx_Iblock_sn; /* After sent iblock, the seq num of expected response i-block */
    uint8_t ifsc_last;         /* The last ifsc, before the ifsc updated */
    uint8_t reponsed_flag;     /* After card activation, if the first correct response is received, set to true */
#endif
} smartcard_ttl_params_t1_t;

/*! @brief Smart Card core parameters for a card instance */
typedef struct
{
    uint8_t EMVL1;                  /*!< EMVL1 or 7816-3 */
    uint8_t Case;                   /*!< Command case */
    smartcard_core_error_t errCode; /*!< Error code */
    bool ppsDone;                   /*!< Indicates whether the PPS was successfully executed or not */
    bool doWarmReset; /*!< Indicates whether warm reset was supposed to be performed after cold ATR parsing*/
    uint8_t localTxBuf[EMVL1_MAX_TRANSFER_SIZE]; /*!< Local buffer used for protocol handling and temporarily storage */
    smartcard_ttl_params_t1_t ttlParamsT1;       /*!< TTL parameters stored for a given command transaction */
    smartcard_xfer_t xfer;                       /*!< Smart Card transfer parameters structure */
    void *x_context;                             /*!< Smart Card driver handle */
} smartcard_core_params_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief This function parses the received ATR from the card and re-populates
 * the card specific data structure with the card parameters.
 * @param coreParams - Smart Card core parameters structure
 * @param buff - Pointer to a buffer memory
 * @param length - Length of buffer memory
 * @return - 0 if passed, an error code if failed.
 */
smartcard_core_error_t smartcard_parse_atr(smartcard_core_params_t *coreParams, uint8_t *buff, uint16_t length);

/*!
 * @brief This function receives an ATR from the card and performs various
 * checks and takes actions.
 * @param coreParams - Smart Card core parameters structure
 * @param buff - Pointer to a buffer memory
 * @param coldReset - Indicates if a cold reset to be performed
 * @param warmReset - Indicates if a warm reset to be performed
 * @param atrLength - Indicates length of received ATR.
 * @return - 0 if passed, an error code if failed.
 * @return kSCCoreTransferAborted if the transfer was aborted
 */
smartcard_core_error_t smartcard_reset_handle_atr(
    smartcard_core_params_t *coreParams, uint8_t *buff, uint8_t coldReset, uint8_t warmReset, uint32_t *atrLength);

/*!
 * @brief This function does Terminal Application Layer(TAL) command
 * mapping then invokes Terminal Transport Layer(TTL) to transfer the command.
 * As per ISO1786 or EMV specification, this function accepts an C-APDU and converts to
 * T-APDU. It also receives a R-TPDU and then converts to R-APDU for the upper layer.
 * @param coreParams - Smart Card core parameters structure
 * @param talCmdPtr - Pointer to the TAL command
 * @param talRespPtr - Pointer to the TAL command response
 * @return 0 if passed, an error code if failed.
 * @return kSCCoreTransferAborted if the transfer was aborted
 */
smartcard_core_error_t smartcard_tal_send_cmd(smartcard_core_params_t *coreParams,
                                              smartcard_tal_cmd_t *talCmdPtr,
                                              smartcard_tal_resp_t *talRespPtr);

/*!
 * @brief This function sends a PPS to the ICC and gets response.
 * @param coreParams - Smart Card core parameters structure
 * @param ppsRequest - Pointer to buffer containing PPS request
 * @param ppsResponse - Pointer to buffer containing PPS response
 * @param length - length of buffer memory
 * @return 0 if passed, an error if failed.
 * @return kSCCoreTransferAborted if the transfer was aborted
 */
smartcard_core_error_t smartcard_send_pps(smartcard_core_params_t *coreParams,
                                          uint8_t *ppsRequest,
                                          uint8_t *ppsResponse,
                                          uint16_t length);

/*!
 * @brief Sends a IFS to the ICC and gets response
 * @param coreParams - Smart Card core parameters structure
 * @param respLength - Number of received bytes
 * @return 0 if passed, an error code if failed.
 * @return kSCCoreTransferAborted if the transfer was aborted
 */
smartcard_core_error_t smartcard_send_ifs(smartcard_core_params_t *coreParams, uint32_t *respLength);

/*!
 * @brief This function checks the card status bytes as per specifications
 * @param coreParams - Smart Card core parameters structure
 * @param statusBytes - Pointer to buffer requested to check
 * @return 0 if a correct status found, an error code if not.
 */
smartcard_core_error_t smartcard_check_status(smartcard_core_params_t *coreParams, uint8_t *statusBytes);

/*!
 * @brief This function sets up Smart Card host in T=0 mode
 * @param coreParams - Smart Card core parameters structure
 * @return 0 if passed, an error code if failed.
 */
smartcard_core_error_t smartcard_setup_t0(smartcard_core_params_t *coreParams);

/*!
 * @brief This function sets up Smart Card host in T=1 mode
 * @param coreParams - Smart Card core parameters structure
 * @return 0 if passed, an error code if failed.
 */
smartcard_core_error_t smartcard_setup_t1(smartcard_core_params_t *coreParams);

/*@}*/
#if defined(__cplusplus)
}
#endif

/*! @}*/
#endif /* _EMVL1_CORE_H_ */
