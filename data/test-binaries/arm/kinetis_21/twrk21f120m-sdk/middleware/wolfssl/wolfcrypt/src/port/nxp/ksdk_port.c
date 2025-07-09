/* ksdk_port.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc. All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
#include "nxp/ksdk_port.h"

/* in case user set USE_FAST_MATH there */
#include <wolfssl/wolfcrypt/settings.h>
#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#include <wolfcrypt/src/misc.c>
#endif

/******************************************************************************/
/*************************** CAAM *********************************************/
/******************************************************************************/
#if defined(FREESCALE_USE_CAAM)
static caam_handle_t s_caamHandle = {.jobRing = kCAAM_JobRing0};
static caam_job_ring_interface_t s_jrif0;
static caam_job_ring_interface_t s_jrif1;
#endif /* FREESCALE_USE_CAAM */

/******************************************************************************/
/*************************** CAU3 *********************************************/
/******************************************************************************/
#if defined(FREESCALE_USE_CAU3)
static cau3_handle_t s_cau3Handle = {.taskDone = FREESCALE_CAU3_COMPLETION_SIGNAL, .keySlot = kCAU3_KeySlot0};
#endif

/******************************************************************************/
/**************************** DCP *********************************************/
/******************************************************************************/
#if defined(FREESCALE_USE_DCP)
static dcp_handle_t s_dcpHandle = {.channel = kDCP_Channel0, .keySlot = kDCP_KeySlot0};
#endif

/******************************************************************************/
/************************* Key slot management ********************************/
/******************************************************************************/
#if defined(FREESCALE_USE_CAU3) || defined(FREESCALE_USE_DCP)
static const void *s_wolfsslCtx[4] = {0};

static void crypto_attach_ctx_to_key_slot(const void *ctx, uint8_t keySlot)
{
    s_wolfsslCtx[keySlot] = ctx;
}

static void crypto_detach_ctx_from_key_slot(const void *ctx)
{
    for (int i = 0; i < 4; i++)
    {
        if (ctx == s_wolfsslCtx[i])
        {
            s_wolfsslCtx[i] = NULL;
            break;
        }
    }
}

static bool crypto_key_is_loaded(const void *ctx)
{
    bool ret = false;
    for (int i = 0; i < 4; i++)
    {
        if (ctx == s_wolfsslCtx[i])
        {
            ret = true;
            break;
        }
    }
    return ret;
}
#endif /* FREESCALE_USE_CAU3 || FREESCALE_USE_DCP */

/******************************************************************************/
/*********************** CRYPTO_InitHardware **********************************/
/******************************************************************************/
void CRYPTO_InitHardware(void)
{
#if defined(FREESCALE_USE_CAAM)
    caam_config_t caamConfig;

    CAAM_GetDefaultConfig(&caamConfig);
    caamConfig.jobRingInterface[0] = &s_jrif0;
    caamConfig.jobRingInterface[1] = &s_jrif1;
    CAAM_Init(CAAM, &caamConfig);
#elif defined(FREESCALE_USE_CAU3)
    /* Initialize CAU3 */
    CAU3_Init(CAU3);
    /* Get CAU3 ownership for this Host CPU */
    CAU3_LockSemaphore(CAU3);
#elif defined(FREESCALE_USE_DCP)
    /* Initialize DCP */
    dcp_config_t dcpConfig;

    DCP_GetDefaultConfig(&dcpConfig);
    DCP_Init(DCP, &dcpConfig);
#endif /* FREESCALE_USE_CAAM */

#ifdef FREESCALE_KSDK_2_0_TRNG
#include "fsl_trng.h"
    trng_config_t trngConfig;
    /* Initialize TRNG configuration structure to default.*/
    /*
     * trngConfig.lock = TRNG_USER_CONFIG_DEFAULT_LOCK;
     * trngConfig.clockMode = kTRNG_ClockModeRingOscillator;
     * trngConfig.ringOscDiv = TRNG_USER_CONFIG_DEFAULT_OSC_DIV;
     * trngConfig.sampleMode = kTRNG_SampleModeRaw;
     * trngConfig.entropyDelay = TRNG_USER_CONFIG_DEFAULT_ENTROPY_DELAY;
     * trngConfig.sampleSize = TRNG_USER_CONFIG_DEFAULT_SAMPLE_SIZE;
     * trngConfig.sparseBitLimit = TRNG_USER_CONFIG_DEFAULT_SPARSE_BIT_LIMIT;
     * trngConfig.retryCount = TRNG_USER_CONFIG_DEFAULT_RETRY_COUNT;
     * trngConfig.longRunMaxLimit = TRNG_USER_CONFIG_DEFAULT_RUN_MAX_LIMIT;
     * trngConfig.monobitLimit.maximum = TRNG_USER_CONFIG_DEFAULT_MONOBIT_MAXIMUM;
     * trngConfig.monobitLimit.minimum = TRNG_USER_CONFIG_DEFAULT_MONOBIT_MINIMUM;
     * trngConfig.runBit1Limit.maximum = TRNG_USER_CONFIG_DEFAULT_RUNBIT1_MAXIMUM;
     * trngConfig.runBit1Limit.minimum = TRNG_USER_CONFIG_DEFAULT_RUNBIT1_MINIMUM;
     * trngConfig.runBit2Limit.maximum = TRNG_USER_CONFIG_DEFAULT_RUNBIT2_MAXIMUM;
     * trngConfig.runBit2Limit.minimum = TRNG_USER_CONFIG_DEFAULT_RUNBIT2_MINIMUM;
     * trngConfig.runBit3Limit.maximum = TRNG_USER_CONFIG_DEFAULT_RUNBIT3_MAXIMUM;
     * trngConfig.runBit3Limit.minimum = TRNG_USER_CONFIG_DEFAULT_RUNBIT3_MINIMUM;
     * trngConfig.runBit4Limit.maximum = TRNG_USER_CONFIG_DEFAULT_RUNBIT4_MAXIMUM;
     * trngConfig.runBit4Limit.minimum = TRNG_USER_CONFIG_DEFAULT_RUNBIT4_MINIMUM;
     * trngConfig.runBit5Limit.maximum = TRNG_USER_CONFIG_DEFAULT_RUNBIT5_MAXIMUM;
     * trngConfig.runBit5Limit.minimum = TRNG_USER_CONFIG_DEFAULT_RUNBIT5_MINIMUM;
     * trngConfig.runBit6PlusLimit.maximum = TRNG_USER_CONFIG_DEFAULT_RUNBIT6PLUS_MAXIMUM;
     * trngConfig.runBit6PlusLimit.minimum = TRNG_USER_CONFIG_DEFAULT_RUNBIT6PLUS_MINIMUM;
     * trngConfig.pokerLimit.maximum = TRNG_USER_CONFIG_DEFAULT_POKER_MAXIMUM;
     * trngConfig.pokerLimit.minimum = TRNG_USER_CONFIG_DEFAULT_POKER_MINIMUM;
     * trngConfig.frequencyCountLimit.maximum = TRNG_USER_CONFIG_DEFAULT_FREQUENCY_MAXIMUM;
     * trngConfig.frequencyCountLimit.minimum = TRNG_USER_CONFIG_DEFAULT_FREQUENCY_MINIMUM;
     */
    TRNG_GetDefaultConfig(&trngConfig);
    /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
    trngConfig.sampleMode = kTRNG_SampleModeVonNeumann;
    /* Initialize TRNG */
#if defined(TRNG)
    TRNG_Init(TRNG, &trngConfig);
#else
    TRNG_Init(TRNG0, &trngConfig);
#endif
#elif defined(FREESCALE_KSDK_2_0_RNGA)
#include "fsl_rnga.h"
    RNGA_Init(RNG);
    RNGA_Seed(RNG, SIM->UIDL);
#endif
#ifdef FREESCALE_LTC
#include "fsl_ltc.h"
    LTC_Init(LTC_BASE);
#if defined(FSL_FEATURE_LTC_HAS_DPAMS) && FSL_FEATURE_LTC_HAS_DPAMS
    LTC_SetDpaMaskSeed(LTC_BASE, SIM->UIDL);
#endif
#endif
}

/******************************************************************************/
/******************************** AES *****************************************/
/******************************************************************************/
#include <wolfssl/wolfcrypt/aes.h>

#if defined(FREESCALE_CAAM_AES)
int wc_AesSetKey(Aes *aes, const byte *userKey, word32 keylen, const byte *iv, int dir)
{
    if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
        return BAD_FUNC_ARG;

    aes->rounds = keylen / 4 + 6;
    XMEMCPY(aes->key, userKey, keylen);

#ifdef WOLFSSL_AES_COUNTER
    aes->left = 0;
#endif /* WOLFSSL_AES_COUNTER */

    return wc_AesSetIV(aes, iv);
}

int wc_AesSetKeyDirect(Aes *aes, const byte *userKey, word32 keylen, const byte *iv, int dir)
{
    return wc_AesSetKey(aes, userKey, keylen, iv, dir);
}

int wc_AesCbcEncrypt(Aes *aes, byte *out, const byte *in, word32 sz)
{
    uint32_t keySize = 0;
    status_t status;
    byte *iv, *enc_key;

    iv = (byte *)aes->reg;
    enc_key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    status = CAAM_AES_EncryptCbc(CAAM, &s_caamHandle, in, out, sz, iv, enc_key, keySize);

    if (status == kStatus_Success)
    {
        /* store IV for next block */
        memcpy(iv, out + sz - 16, 16);
        return 0;
    }
    else
    {
        return -1;
    }
}

int wc_AesCbcDecrypt(Aes *aes, byte *out, const byte *in, word32 sz)
{
    uint32_t keySize = 0;
    status_t status;
    byte *iv, *dec_key;
    uint8_t tmp[16] = {0};

    iv = (byte *)aes->reg;
    dec_key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (sz >= 16)
    {
        memcpy(tmp, in + sz - 16, 16);
    }

    status = CAAM_AES_DecryptCbc(CAAM, &s_caamHandle, in, out, sz, iv, dec_key, keySize);

    if (status == kStatus_Success)
    {
        /* store IV for next block */
        memcpy(iv, tmp, 16);
        return 0;
    }
    else
    {
        return -1;
    }
}

void wc_AesCtrEncrypt(Aes *aes, byte *out, const byte *in, word32 sz)
{
    uint32_t keySize = 0;
    byte *iv, *enc_key;
    byte *tmp = (byte *)aes->tmp + AES_BLOCK_SIZE - aes->left;

    /* consume any unused bytes left in aes->tmp */
    while (aes->left && sz)
    {
        *(out++) = *(in++) ^ *(tmp++);
        aes->left--;
        sz--;
    }

    if (sz)
    {
        iv = (byte *)aes->reg;
        enc_key = (byte *)aes->key;

        switch (aes->rounds)
        {
            case 10:
                keySize = 16;
                break;
            case 12:
                keySize = 24;
                break;
            case 14:
                keySize = 32;
                break;
        }

        CAAM_AES_CryptCtr(CAAM, &s_caamHandle, in, out, sz, iv, enc_key, keySize, (byte *)aes->tmp,
                          (size_t *)&(aes->left));
    }
}

void wc_AesEncryptDirect(Aes *aes, byte *out, const byte *in)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    CAAM_AES_EncryptEcb(CAAM, &s_caamHandle, in, out, 16, key, keySize);
}

/* Allow direct access to one block decrypt */
void wc_AesDecryptDirect(Aes *aes, byte *out, const byte *in)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    CAAM_AES_DecryptEcb(CAAM, &s_caamHandle, in, out, 16, key, keySize);
}

int wc_AesGcmSetKey(Aes *aes, const byte *key, word32 len)
{
    int ret;
    byte iv[AES_BLOCK_SIZE];

    if (!((len == 16) || (len == 24) || (len == 32)))
        return BAD_FUNC_ARG;

    XMEMSET(iv, 0, AES_BLOCK_SIZE);
    ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

#ifdef WOLFSSL_AESNI
    /* AES-NI code generates its own H value. */
    if (haveAESNI)
        return ret;
#endif /* WOLFSSL_AESNI */

    return ret;
}

int wc_AesGcmEncrypt(Aes *aes,
                     byte *out,
                     const byte *in,
                     word32 sz,
                     const byte *iv,
                     word32 ivSz,
                     byte *authTag,
                     word32 authTagSz,
                     const byte *authIn,
                     word32 authInSz)
{
    byte *key;
    uint32_t keySize = 0;
    status_t status;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    status = CAAM_AES_EncryptTagGcm(CAAM, &s_caamHandle, in, out, sz, iv, ivSz, authIn, authInSz, key, keySize, authTag,
                                    authTagSz);
    if (status == kStatus_Success)
        return 0;
    else
        return AES_GCM_AUTH_E;
}

int wc_AesGcmDecrypt(Aes *aes,
                     byte *out,
                     const byte *in,
                     word32 sz,
                     const byte *iv,
                     word32 ivSz,
                     const byte *authTag,
                     word32 authTagSz,
                     const byte *authIn,
                     word32 authInSz)
{
    byte *key;
    uint32_t keySize = 0;
    status_t status;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    status = CAAM_AES_DecryptTagGcm(CAAM, &s_caamHandle, in, out, sz, iv, ivSz, authIn, authInSz, key, keySize, authTag,
                                    authTagSz);
    if (status == kStatus_Success)
        return 0;
    else
        return AES_GCM_AUTH_E;
}

void wc_AesCcmSetKey(Aes *aes, const byte *key, word32 keySz)
{
    byte nonce[AES_BLOCK_SIZE];

    if (!((keySz == 16) || (keySz == 24) || (keySz == 32)))
        return;

    XMEMSET(nonce, 0, sizeof(nonce));
    wc_AesSetKey(aes, key, keySz, nonce, AES_ENCRYPTION);
}

int wc_AesCcmEncrypt(Aes *aes,
                     byte *out,
                     const byte *in,
                     word32 inSz,
                     const byte *nonce,
                     word32 nonceSz,
                     byte *authTag,
                     word32 authTagSz,
                     const byte *authIn,
                     word32 authInSz)
{
    byte *key;
    uint32_t keySize = 0;
    status_t status;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    status = CAAM_AES_EncryptTagCcm(CAAM, &s_caamHandle, in, out, inSz, nonce, nonceSz, authIn, authInSz, key, keySize,
                                    authTag, authTagSz);
    if (kStatus_Success == status)
        return 0;
    else
        return BAD_FUNC_ARG;
}

int wc_AesCcmDecrypt(Aes *aes,
                     byte *out,
                     const byte *in,
                     word32 inSz,
                     const byte *nonce,
                     word32 nonceSz,
                     const byte *authTag,
                     word32 authTagSz,
                     const byte *authIn,
                     word32 authInSz)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    status_t retVal;
    retVal = CAAM_AES_DecryptTagCcm(CAAM, &s_caamHandle, in, out, inSz, nonce, nonceSz, authIn, authInSz, key, keySize,
                                    authTag, authTagSz);

    if (retVal == kStatus_Success)
        return 0;
    else
    {
        XMEMSET(out, 0, inSz);
        return AES_CCM_AUTH_E;
    }
}
#elif defined(FREESCALE_CAU3_AES)
int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen, const byte* iv, int dir)
{
    if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
        return BAD_FUNC_ARG;

    crypto_detach_ctx_from_key_slot(aes);

    aes->rounds = keylen / 4 + 6;
    XMEMCPY(aes->key, userKey, keylen);

#ifdef WOLFSSL_AES_COUNTER
    aes->left = 0;
#endif /* WOLFSSL_AES_COUNTER */

    return wc_AesSetIV(aes, iv);
}

int wc_AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                       const byte* iv, int dir)
{
    return wc_AesSetKey(aes, userKey, keylen, iv, dir);
}

void wc_AesEncryptDirect(Aes *aes, byte *out, const byte *in)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (!crypto_key_is_loaded(aes))
    {
        CAU3_AES_SetKey(CAU3, &s_cau3Handle, key, keySize);
        crypto_attach_ctx_to_key_slot(aes, s_cau3Handle.keySlot);
    }

    CAU3_AES_Encrypt(CAU3, &s_cau3Handle, in, out);
}

/* Allow direct access to one block decrypt */
void wc_AesDecryptDirect(Aes *aes, byte *out, const byte *in)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (!crypto_key_is_loaded(aes))
    {
        CAU3_AES_SetKey(CAU3, &s_cau3Handle, key, keySize);
        crypto_attach_ctx_to_key_slot(aes, s_cau3Handle.keySlot);
    }

    CAU3_AES_Decrypt(CAU3, &s_cau3Handle, in, out);
}

void wc_AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    wc_AesEncryptDirect(aes, outBlock, inBlock);
}

void wc_AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    wc_AesDecryptDirect(aes, outBlock, inBlock);
}

#elif defined(FREESCALE_DCP_AES)
int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen, const byte* iv, int dir)
{
    if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
        return BAD_FUNC_ARG;

    crypto_detach_ctx_from_key_slot(aes);

    aes->rounds = keylen / 4 + 6;
    XMEMCPY(aes->key, userKey, keylen);

#ifdef WOLFSSL_AES_COUNTER
    aes->left = 0;
#endif /* WOLFSSL_AES_COUNTER */

    return wc_AesSetIV(aes, iv);
}

int wc_AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                       const byte* iv, int dir)
{
    return wc_AesSetKey(aes, userKey, keylen, iv, dir);
}

int wc_AesCbcEncrypt(Aes *aes, byte *out, const byte *in, word32 sz)
{
    uint32_t keySize = 0;
    status_t status;
    byte *iv, *enc_key;

    iv = (byte *)aes->reg;
    enc_key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (!crypto_key_is_loaded(aes))
    {
        DCP_AES_SetKey(DCP, &s_dcpHandle, enc_key, keySize);
        crypto_attach_ctx_to_key_slot(aes, s_dcpHandle.keySlot);
    }

    status = DCP_AES_EncryptCbc(DCP, &s_dcpHandle, in, out, sz, iv);

    if (status == kStatus_Success)
    {
        /* store IV for next block */
        memcpy(iv, out + sz - 16, 16);
        return 0;
    }
    else
    {
        return -1;
    }
}

int wc_AesCbcDecrypt(Aes *aes, byte *out, const byte *in, word32 sz)
{
    uint32_t keySize = 0;
    status_t status;
    byte *iv, *dec_key;
    uint8_t tmp[16] = {0};

    iv = (byte *)aes->reg;
    dec_key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (sz >= 16)
    {
        memcpy(tmp, in + sz - 16, 16);
    }

    if (!crypto_key_is_loaded(aes))
    {
        DCP_AES_SetKey(DCP, &s_dcpHandle, dec_key, keySize);
        crypto_attach_ctx_to_key_slot(aes, s_dcpHandle.keySlot);
    }

    status = DCP_AES_DecryptCbc(DCP, &s_dcpHandle, in, out, sz, iv);

    if (status == kStatus_Success)
    {
        /* store IV for next block */
        memcpy(iv, tmp, 16);
        return 0;
    }
    else
    {
        return -1;
    }
}

void wc_AesEncryptDirect(Aes *aes, byte *out, const byte *in)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (!crypto_key_is_loaded(aes))
    {
        DCP_AES_SetKey(DCP, &s_dcpHandle, key, keySize);
        crypto_attach_ctx_to_key_slot(aes, s_dcpHandle.keySlot);
    }

    DCP_AES_EncryptEcb(DCP, &s_dcpHandle, in, out, 16);
}

/* Allow direct access to one block decrypt */
void wc_AesDecryptDirect(Aes *aes, byte *out, const byte *in)
{
    byte *key;
    uint32_t keySize = 0;

    key = (byte *)aes->key;

    switch (aes->rounds)
    {
        case 10:
            keySize = 16;
            break;
        case 12:
            keySize = 24;
            break;
        case 14:
            keySize = 32;
            break;
    }

    if (!crypto_key_is_loaded(aes))
    {
        DCP_AES_SetKey(DCP, &s_dcpHandle, key, keySize);
        crypto_attach_ctx_to_key_slot(aes, s_dcpHandle.keySlot);
    }

    DCP_AES_DecryptEcb(DCP, &s_dcpHandle, in, out, 16);
}

void wc_AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    wc_AesEncryptDirect(aes, outBlock, inBlock);
}

void wc_AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    wc_AesDecryptDirect(aes, outBlock, inBlock);
}
#endif /* FREESCALE_CAAM_AES */

/******************************************************************************/
/******************************** DES *****************************************/
/******************************************************************************/
#include <wolfssl/wolfcrypt/des3.h>

#if defined(FREESCALE_CAAM_DES)
int wc_Des_SetKey(Des *des, const byte *key, const byte *iv, int dir)
{
    byte *dkey = (byte *)des->key;

    XMEMCPY(dkey, key, 8);

    wc_Des_SetIV(des, iv);

    return 0;
}

int wc_Des_CbcEncrypt(Des *des, byte *out, const byte *in, word32 sz)
{
    status_t status;
    status = CAAM_DES_EncryptCbc(CAAM, &s_caamHandle, in, out, sz, (byte *)des->reg, (byte *)des->key);
    if (status == kStatus_Success)
        return 0;
    else
        return -1;
}

int wc_Des_CbcDecrypt(Des *des, byte *out, const byte *in, word32 sz)
{
    status_t status;
    status = CAAM_DES_DecryptCbc(CAAM, &s_caamHandle, in, out, sz, (byte *)des->reg, (byte *)des->key);
    if (status == kStatus_Success)
        return 0;
    else
        return -1;
}
#endif /* FREESCALE_CAAM_DES */

#if defined(FREESCALE_CAAM_DES3)
int wc_Des3_SetKey(Des3 *des, const byte *key, const byte *iv, int dir)
{
    int ret = 0;
    byte *dkey1 = (byte *)des->key[0];
    byte *dkey2 = (byte *)des->key[1];
    byte *dkey3 = (byte *)des->key[2];

    XMEMCPY(dkey1, key, 8);      /* set key 1 */
    XMEMCPY(dkey2, key + 8, 8);  /* set key 2 */
    XMEMCPY(dkey3, key + 16, 8); /* set key 3 */

    ret = wc_Des3_SetIV(des, iv);
    if (ret != 0)
        return ret;

    return ret;
}

int wc_Des3_CbcEncrypt(Des3 *des, byte *out, const byte *in, word32 sz)
{
    status_t status;
    status = CAAM_DES3_EncryptCbc(CAAM, &s_caamHandle, in, out, sz, (byte *)des->reg, (byte *)des->key[0],
                                  (byte *)des->key[1], (byte *)des->key[2]);
    if (status == kStatus_Success)
        return 0;
    else
        return -1;
}

int wc_Des3_CbcDecrypt(Des3 *des, byte *out, const byte *in, word32 sz)
{
    status_t status;
    status = CAAM_DES3_DecryptCbc(CAAM, &s_caamHandle, in, out, sz, (byte *)des->reg, (byte *)des->key[0],
                                  (byte *)des->key[1], (byte *)des->key[2]);
    if (status == kStatus_Success)
        return 0;
    else
        return -1;
}

#elif defined(FREESCALE_CAU3_DES3)
int wc_Des3_SetKey(Des3 *des, const byte *key, const byte *iv, int dir)
{
    int ret = 0;
    byte *dkey1 = (byte *)des->key[0];

    XMEMCPY(dkey1, key, 8);
    XMEMCPY(dkey1 + 8, key + 8, 8);
    XMEMCPY(dkey1 + 16, key + 16, 8);

    ret = CAU3_TDES_SetKey(CAU3, &s_cau3Handle, (byte*)des->key, 24);
    if (ret != kStatus_Success)
        return -1;

    crypto_attach_ctx_to_key_slot(des, s_cau3Handle.keySlot);

    ret = wc_Des3_SetIV(des, iv);
    if (ret != 0)
        return ret;

    return ret;
}

int wc_Des3_CbcEncrypt(Des3* des, byte* out, const byte* in, word32 sz)
{
    int i;
    int offset = 0;
    int len = sz;
    int ret = 0;

    byte *iv;
    byte temp_block[DES_BLOCK_SIZE];

    iv = (byte*)des->reg;

    if (!crypto_key_is_loaded(des))
    {
        ret = CAU3_TDES_SetKey(CAU3, &s_cau3Handle, (byte*)des->key, 24);
        if (ret != kStatus_Success)
            return -1;

        crypto_attach_ctx_to_key_slot(des, s_cau3Handle.keySlot);
    }

    while (len > 0)
    {
        XMEMCPY(temp_block, in + offset, DES_BLOCK_SIZE);

        /* XOR block with IV for CBC */
        for (i = 0; i < DES_BLOCK_SIZE; i++)
            temp_block[i] ^= iv[i];

        ret = CAU3_TDES_Encrypt(CAU3, &s_cau3Handle, temp_block, out + offset);
        if (ret != kStatus_Success)
            return -1;

        len    -= DES_BLOCK_SIZE;
        offset += DES_BLOCK_SIZE;

        /* store IV for next block */
        XMEMCPY(iv, out + offset - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }

    return ret;
}

int wc_Des3_CbcDecrypt(Des3* des, byte* out, const byte* in, word32 sz)
{
    int i;
    int offset = 0;
    int len = sz;
    int ret = 0;

    byte* iv;
    byte temp_block[DES_BLOCK_SIZE];

    iv = (byte*)des->reg;

    if (!crypto_key_is_loaded(des))
    {
        ret = CAU3_TDES_SetKey(CAU3, &s_cau3Handle, (byte*)des->key, 24);
        if (ret != kStatus_Success)
            return -1;

        crypto_attach_ctx_to_key_slot(des, s_cau3Handle.keySlot);
    }

    while (len > 0)
    {
        XMEMCPY(temp_block, in + offset, DES_BLOCK_SIZE);

        ret = CAU3_TDES_Decrypt(CAU3, &s_cau3Handle, in + offset, out + offset);
        if (ret != kStatus_Success)
            return -1;

        /* XOR block with IV for CBC */
        for (i = 0; i < DES_BLOCK_SIZE; i++)
            (out + offset)[i] ^= iv[i];

        /* store IV for next block */
        XMEMCPY(iv, temp_block, DES_BLOCK_SIZE);

        len    -= DES_BLOCK_SIZE;
        offset += DES_BLOCK_SIZE;
    }

    return ret;
}
#endif /* FREESCALE_CAAM_DES3 */

/******************************************************************************/
/***************************** SHA1 *******************************************/
/******************************************************************************/
#if defined(FREESCALE_CAAM_SHA)
#include <wolfssl/wolfcrypt/sha.h>

int wc_InitSha(Sha *sha)
{
    CAAM_HASH_Init(CAAM, &s_caamHandle, &sha->ctx, kCAAM_Sha1, NULL, 0);
    return 0;
}

int wc_ShaUpdate(Sha *sha, const byte *data, word32 len)
{
    CAAM_HASH_Update(&sha->ctx, data, len);
    return 0;
}

int wc_ShaFinal(Sha *sha, byte *hash)
{
    size_t hashlen = SHA_DIGEST_SIZE;
    CAAM_HASH_Finish(&sha->ctx, hash, &hashlen);
    return wc_InitSha(sha); /* reset state */
}

#elif defined(FREESCALE_CAU3_SHA)
#include <wolfssl/wolfcrypt/sha.h>

int wc_InitSha(Sha *sha)
{
    if (CAU3_HASH_Init(CAU3, &sha->ctx, kCAU3_Sha1) != kStatus_Success)
        return -1;

    return 0;
}

int wc_ShaUpdate(Sha *sha, const byte *data, word32 len)
{
    if (CAU3_HASH_Update(CAU3, &sha->ctx, data, len) != kStatus_Success)
        return -1;

    return 0;
}

int wc_ShaFinal(Sha *sha, byte *hash)
{
    size_t hashlen = SHA_DIGEST_SIZE;
    if (CAU3_HASH_Finish(CAU3, &sha->ctx, hash, &hashlen) != kStatus_Success)
        return -1;

    return wc_InitSha(sha); /* reset state */
}

#elif defined(FREESCALE_DCP_SHA)
#include <wolfssl/wolfcrypt/sha.h>

int wc_InitSha(Sha *sha)
{
    if (DCP_HASH_Init(DCP, &s_dcpHandle, &sha->ctx, kDCP_Sha1) != kStatus_Success)
        return -1;

    return 0;
}

int wc_ShaUpdate(Sha *sha, const byte *data, word32 len)
{
    if (DCP_HASH_Update(DCP, &sha->ctx, data, len) != kStatus_Success)
        return -1;

    return 0;
}

int wc_ShaFinal(Sha *sha, byte *hash)
{
    size_t hashlen = SHA_DIGEST_SIZE;
    if (DCP_HASH_Finish(DCP, &sha->ctx, hash, &hashlen) != kStatus_Success)
        return -1;

    return wc_InitSha(sha); /* reset state */
}
#endif /* FREESCALE_CAAM_SHA */

/******************************************************************************/
/***************************** SHA256 *****************************************/
/******************************************************************************/
#if defined(FREESCALE_CAAM_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

int wc_InitSha256(Sha256 *sha256)
{
    CAAM_HASH_Init(CAAM, &s_caamHandle, &sha256->ctx, kCAAM_Sha256, NULL, 0);
    return 0;
}

int wc_Sha256Update(Sha256 *sha256, const byte *data, word32 len)
{
    CAAM_HASH_Update(&sha256->ctx, data, len);
    return 0;
}

int wc_Sha256Final(Sha256 *sha256, byte *hash)
{
    size_t hashlen = SHA256_DIGEST_SIZE;
    CAAM_HASH_Finish(&sha256->ctx, hash, &hashlen);
    return wc_InitSha256(sha256); /* reset state */
}
#elif defined(FREESCALE_CAU3_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

int wc_InitSha256(Sha256 *sha256)
{
    if (CAU3_HASH_Init(CAU3, &sha256->ctx, kCAU3_Sha256) != kStatus_Success)
        return -1;

    return 0;
}

int wc_Sha256Update(Sha256 *sha256, const byte *data, word32 len)
{
    if (CAU3_HASH_Update(CAU3, &sha256->ctx, data, len) != kStatus_Success)
        return -1;

    return 0;
}

int wc_Sha256Final(Sha256 *sha256, byte *hash)
{
    size_t hashlen = SHA256_DIGEST_SIZE;
    if (CAU3_HASH_Finish(CAU3, &sha256->ctx, hash, &hashlen) != kStatus_Success)
        return -1;

    return wc_InitSha256(sha256); /* reset state */
}
#elif defined(FREESCALE_DCP_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

int wc_InitSha256(Sha256 *sha256)
{
    if (DCP_HASH_Init(DCP, &s_dcpHandle, &sha256->ctx, kDCP_Sha256) != kStatus_Success)
        return -1;

    return 0;
}

int wc_Sha256Update(Sha256 *sha256, const byte *data, word32 len)
{
    if (DCP_HASH_Update(DCP, &sha256->ctx, data, len) != kStatus_Success)
        return -1;

    return 0;
}

int wc_Sha256Final(Sha256 *sha256, byte *hash)
{
    size_t hashlen = SHA256_DIGEST_SIZE;
    if (DCP_HASH_Finish(DCP, &sha256->ctx, hash, &hashlen) != kStatus_Success)
        return -1;

    return wc_InitSha256(sha256); /* reset state */
}
#endif /* FREESCALE_CAAM_SHA256 */

/******************************************************************************/
/***************************** PKHA *******************************************/
/******************************************************************************/
#ifdef USE_FAST_MATH

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/tfm.h>
#include <wolfcrypt/src/asm.c> /* will define asm MACROS or C ones */

#if defined(FREESCALE_LTC_TFM)

#include "fsl_ltc.h"
#include <stdint.h>

/* Reverse array in memory (in place) */
static void ltc_reverse_array(uint8_t *src, size_t src_len)
{
    int i;

    for (i = 0; i < src_len / 2; i++)
    {
        uint8_t tmp;

        tmp = src[i];
        src[i] = src[src_len - 1 - i];
        src[src_len - 1 - i] = tmp;
    }
}

/* same as fp_to_unsigned_bin() with fp_reverse() skipped */
static void fp_to_unsigned_lsb_bin(fp_int *a, unsigned char *b)
{
    fp_int t;

    fp_init_copy(&t, a);

    (void)_fp_to_unsigned_bin(0, &t, b);
}

static void ltc_get_lsb_bin_from_mp_int(uint8_t *dst, mp_int *A, uint16_t *psz)
{
    uint16_t sz;

    sz = mp_unsigned_bin_size(A);
    fp_to_unsigned_lsb_bin(A, dst); /* result is lsbyte at lowest addr as required by LTC */
    *psz = sz;
}

/* these function are used by wolfSSL upper layers (like RSA) */

/* c = a * b */
void fp_mul(fp_int *A, fp_int *B, fp_int *C)
{
    int szA, szB;
    szA = fp_unsigned_bin_size(A);
    szB = fp_unsigned_bin_size(B);

    /* if unsigned mul can fit into LTC PKHA let's use it, otherwise call software mul */
    if ((szA <= LTC_MAX_INT_BYTES / 2) && (szB <= LTC_MAX_INT_BYTES / 2))
    {
        int neg;

        neg = (A->sign == B->sign) ? FP_ZPOS : FP_NEG;

        /* unsigned multiply */
        uint8_t *ptrA = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrB = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrC = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);

        if (ptrA && ptrB && ptrC)
        {
            uint16_t sizeA, sizeB;

            ltc_get_lsb_bin_from_mp_int(ptrA, A, &sizeA);
            ltc_get_lsb_bin_from_mp_int(ptrB, B, &sizeB);
            XMEMSET(ptrC, 0xFF, LTC_MAX_INT_BYTES);

            if (kStatus_Success != LTC_PKHA_ModMul(LTC_BASE, ptrA, sizeA, ptrB, sizeB, ptrC, LTC_MAX_INT_BYTES, ptrB,
                                                   &sizeB, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                                                   kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized))
            {
                return;
            }

            ltc_reverse_array(ptrB, sizeB);
            mp_read_unsigned_bin(C, ptrB, sizeB);
        }

        /* fix sign */
        C->sign = neg;
        if (ptrA)
        {
            XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrB)
        {
            XFREE(ptrB, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrC)
        {
            XFREE(ptrC, 0, DYNAMIC_TYPE_BIGINT);
        }
        return;
    }
    else
    {
        wolfcrypt_fp_mul(A, B, C);
    }
}

/* c = a mod b, 0 <= c < b  */
int fp_mod(fp_int *a, fp_int *b, fp_int *c)
{
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    int szA, szB;
    szA = fp_unsigned_bin_size(a);
    szB = fp_unsigned_bin_size(b);
    if ((szA <= LTC_MAX_INT_BYTES) && (szB <= LTC_MAX_INT_BYTES))
    {
#endif /* FREESCALE_LTC_TFM_RSA_4096_ENABLE */
        int res = FP_OKAY;
        int neg;

        uint8_t *ptrA = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrB = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrC = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);

        /* get sign for the result */
        neg = (a->sign == b->sign) ? FP_ZPOS : FP_NEG;

        /* get remainder of unsigned a divided by unsigned b */
        if (ptrA && ptrB && ptrC)
        {
            uint16_t sizeA, sizeB, sizeC;

            ltc_get_lsb_bin_from_mp_int(ptrA, a, &sizeA);
            ltc_get_lsb_bin_from_mp_int(ptrB, b, &sizeB);

            if (kStatus_Success ==
                LTC_PKHA_ModRed(LTC_BASE, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kLTC_PKHA_IntegerArith))
            {
                ltc_reverse_array(ptrC, sizeC);
                mp_read_unsigned_bin(c, ptrC, sizeC);
            }
            else
            {
                res = FP_VAL;
            }
        }
        else
        {
            res = FP_MEM;
        }

        /* fix sign */
        c->sign = neg;

        if (ptrA)
        {
            XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrB)
        {
            XFREE(ptrB, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrC)
        {
            XFREE(ptrC, 0, DYNAMIC_TYPE_BIGINT);
        }
        return res;
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    }
    else
    {
        return wolfcrypt_fp_mod(a, b, c);
    }
#endif /* FREESCALE_LTC_TFM_RSA_4096_ENABLE */
}

/* c = 1/a (mod b) for odd b only */
int fp_invmod(fp_int *a, fp_int *b, fp_int *c)
{
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    int szA, szB;
    szA = fp_unsigned_bin_size(a);
    szB = fp_unsigned_bin_size(b);
    if ((szA <= LTC_MAX_INT_BYTES) && (szB <= LTC_MAX_INT_BYTES))
    {
#endif
        int res = FP_OKAY;

        uint8_t *ptrA = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrB = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrC = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);

        if (ptrA && ptrB && ptrC)
        {
            uint16_t sizeA, sizeB, sizeC;

            ltc_get_lsb_bin_from_mp_int(ptrA, a, &sizeA);
            ltc_get_lsb_bin_from_mp_int(ptrB, b, &sizeB);

            if (kStatus_Success ==
                LTC_PKHA_ModInv(LTC_BASE, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kLTC_PKHA_IntegerArith))
            {
                ltc_reverse_array(ptrC, sizeC);
                mp_read_unsigned_bin(c, ptrC, sizeC);
            }
            else
            {
                res = FP_VAL;
            }
        }
        else
        {
            res = FP_MEM;
        }

        c->sign = a->sign;
        if (ptrA)
        {
            XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrB)
        {
            XFREE(ptrB, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrC)
        {
            XFREE(ptrC, 0, DYNAMIC_TYPE_BIGINT);
        }
        return res;
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    }
    else
    {
        return wolfcrypt_fp_invmod(a, b, c);
    }
#endif
}

/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    int szA, szB, szC;
    szA = fp_unsigned_bin_size(a);
    szB = fp_unsigned_bin_size(b);
    szC = fp_unsigned_bin_size(c);
    if ((szA <= LTC_MAX_INT_BYTES) && (szB <= LTC_MAX_INT_BYTES) && (szC <= LTC_MAX_INT_BYTES))
    {
#endif /* FREESCALE_LTC_TFM_RSA_4096_ENABLE */
        int res = FP_OKAY;
        fp_int t;

        uint8_t *ptrA = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrB = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrC = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrD = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);

        /* if A or B is negative, substracta abs(A) or abs(B) from modulus to get positive integer representation of the
         * same number */
        fp_init(&t);
        if (a->sign)
        {
            fp_add(a, c, &t);
            fp_copy(&t, a);
        }
        if (b->sign)
        {
            fp_add(b, c, &t);
            fp_copy(&t, b);
        }

        if (ptrA && ptrB && ptrC && ptrD)
        {
            uint16_t sizeA, sizeB, sizeC, sizeD;

            ltc_get_lsb_bin_from_mp_int(ptrA, a, &sizeA);
            ltc_get_lsb_bin_from_mp_int(ptrB, b, &sizeB);
            ltc_get_lsb_bin_from_mp_int(ptrC, c, &sizeC);

            /* (A*B)mod C = ((A mod C) * (B mod C)) mod C  */
            if (LTC_PKHA_CompareBigNum(ptrA, sizeA, ptrC, sizeC) >= 0)
            {
                if (kStatus_Success !=
                    LTC_PKHA_ModRed(LTC_BASE, ptrA, sizeA, ptrC, sizeC, ptrA, &sizeA, kLTC_PKHA_IntegerArith))
                {
                    res = FP_VAL;
                }
            }
            if ((FP_OKAY == res) && (LTC_PKHA_CompareBigNum(ptrB, sizeB, ptrC, sizeC) >= 0))
            {
                if (kStatus_Success !=
                    LTC_PKHA_ModRed(LTC_BASE, ptrB, sizeB, ptrC, sizeC, ptrB, &sizeB, kLTC_PKHA_IntegerArith))
                {
                    res = FP_VAL;
                }
            }

            if (FP_OKAY == res)
            {
                if (kStatus_Success != LTC_PKHA_ModMul(LTC_BASE, ptrA, sizeA, ptrB, sizeB, ptrC, sizeC, ptrD, &sizeD,
                                                       kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                                                       kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized))
                {
                    res = FP_VAL;
                }
            }

            if (FP_OKAY == res)
            {
                ltc_reverse_array(ptrD, sizeD);
                mp_read_unsigned_bin(d, ptrD, sizeD);
            }
        }
        else
        {
            res = FP_MEM;
        }

        if (ptrA)
        {
            XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrB)
        {
            XFREE(ptrB, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrC)
        {
            XFREE(ptrC, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrD)
        {
            XFREE(ptrD, 0, DYNAMIC_TYPE_BIGINT);
        }
        return res;
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    }
    else
    {
        return wolfcrypt_fp_mulmod(a, b, c, d);
    }
#endif /* FREESCALE_LTC_TFM_RSA_4096_ENABLE */
}

/* Y = G^X mod P */
int _fp_exptmod(fp_int *G, fp_int *X, fp_int *P, fp_int *Y)
{
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    int szA, szB, szC;
    fp_int tmp;
    int err;

    /* if G cannot fit into LTC_PKHA, reduce it */
    szA = fp_unsigned_bin_size(G);
    if (szA > LTC_MAX_INT_BYTES)
    {
        fp_init(&tmp);
        if ((err = fp_mod(G, P, &tmp)) != FP_OKAY)
        {
            return err;
        }
        G = &tmp;
        szA = fp_unsigned_bin_size(G);
    }

    szB = fp_unsigned_bin_size(X);
    szC = fp_unsigned_bin_size(P);

    if ((szA <= LTC_MAX_INT_BYTES) && (szB <= LTC_MAX_INT_BYTES) && (szC <= LTC_MAX_INT_BYTES))
    {
#endif
        int res = FP_OKAY;
        fp_int t;

        uint16_t sizeG, sizeX, sizeP;
        uint8_t *ptrG = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrX = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrP = (uint8_t *)XMALLOC(LTC_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);

        /* if G is negative, add modulus to convert to positive number for LTC */
        fp_init(&t);
        if (G->sign)
        {
            fp_add(G, P, &t);
            fp_copy(&t, G);
        }

        if (ptrG && ptrX && ptrP)
        {
            ltc_get_lsb_bin_from_mp_int(ptrG, G, &sizeG);
            ltc_get_lsb_bin_from_mp_int(ptrX, X, &sizeX);
            ltc_get_lsb_bin_from_mp_int(ptrP, P, &sizeP);

            /* if number if greater that modulo, we must first reduce due to LTC requirement on modular exponentiaton */
            /* it needs number less than modulus.  */
            /* we can take advantage of modular arithmetic rule that: A^B mod C = ( (A mod C)^B ) mod C
               and so we do first (A mod N) : LTC does not give size requirement on A versus N,
               and then the modular exponentiation.
             */
            /* if G >= P then */
            if (LTC_PKHA_CompareBigNum(ptrG, sizeG, ptrP, sizeP) >= 0)
            {
                res = (int)LTC_PKHA_ModRed(LTC_BASE, ptrG, sizeG, ptrP, sizeP, ptrG, &sizeG, kLTC_PKHA_IntegerArith);

                if (res != kStatus_Success)
                {
                    res = FP_VAL;
                }
            }

            if (FP_OKAY == res)
            {
                res = (int)LTC_PKHA_ModExp(LTC_BASE, ptrG, sizeG, ptrP, sizeP, ptrX, sizeX, ptrP, &sizeP,
                                           kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);

                if (res != kStatus_Success)
                {
                    res = FP_VAL;
                }
                else
                {
                    ltc_reverse_array(ptrP, sizeP);
                    mp_read_unsigned_bin(Y, ptrP, sizeP);
                }
            }
        }
        else
        {
            res = FP_MEM;
        }

        if (ptrG)
        {
            XFREE(ptrG, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrX)
        {
            XFREE(ptrX, 0, DYNAMIC_TYPE_BIGINT);
        }
        if (ptrP)
        {
            XFREE(ptrP, 0, DYNAMIC_TYPE_BIGINT);
        }
        return res;
#if defined(FREESCALE_LTC_TFM_RSA_4096_ENABLE)
    }
    else
    {
        return _wolfcrypt_fp_exptmod(G, X, P, Y);
    }
#endif
}

#elif defined(FREESCALE_CAAM_TFM)

static void caam_get_bin_from_mp_int(uint8_t *dst, mp_int *A, size_t *psz)
{
    int sz;

    sz = mp_unsigned_bin_size(A);
    fp_to_unsigned_bin(A, dst);
    *psz = sz;
}

/* these function are used by wolfSSL upper layers (like RSA) */

/* c = a * b */
void fp_mul(fp_int *A, fp_int *B, fp_int *C)
{
    int szA, szB;
    szA = fp_unsigned_bin_size(A);
    szB = fp_unsigned_bin_size(B);

    /*
     * Should be "if ((sizeA + sizeB) <= sizeN)", but if the multiplication result
     * would be maximum CAAM number (the same value as the modulus N below),
     * zero would be returned instead, which is wrong value.
     */
    if ((szA + szB) < CAAM_MAX_INT_BYTES)
    {
        int neg;

        neg = (A->sign == B->sign) ? FP_ZPOS : FP_NEG;

        /* unsigned multiply */
        uint8_t *ptrA = (uint8_t *)XMALLOC(CAAM_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
        uint8_t *ptrB = ptrA + CAAM_MAX_INT_BYTES;
        uint8_t *ptrC = ptrB + CAAM_MAX_INT_BYTES;

        if (ptrA)
        {
            size_t sizeA, sizeB;

            caam_get_bin_from_mp_int(ptrA, A, &sizeA);
            caam_get_bin_from_mp_int(ptrB, B, &sizeB);
            XMEMSET(ptrC, 0xFF, CAAM_MAX_INT_BYTES);

            if (kStatus_Success != CAAM_PKHA_ModMul(CAAM, &s_caamHandle, ptrA, sizeA, ptrB, sizeB, ptrC,
                                                    CAAM_MAX_INT_BYTES, ptrB, &sizeB, kCAAM_PKHA_IntegerArith,
                                                    kCAAM_PKHA_NormalValue, kCAAM_PKHA_NormalValue,
                                                    kCAAM_PKHA_TimingEqualized))
            {
                return;
            }

            mp_read_unsigned_bin(C, ptrB, sizeB);
        }

        /* fix sign */
        C->sign = neg;
        if (ptrA)
        {
            XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
        }
        return;
    }
    else
    {
        wolfcrypt_fp_mul(A, B, C);
    }
}

/* c = a mod b, 0 <= c < b  */
int fp_mod(fp_int *a, fp_int *b, fp_int *c)
{
    int res = FP_OKAY;
    int neg;

    uint8_t *ptrA = (uint8_t *)XMALLOC(CAAM_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAAM_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAAM_MAX_INT_BYTES;

    /* get sign for the result */
    neg = (a->sign == b->sign) ? FP_ZPOS : FP_NEG;

    /* get remainder of unsigned a divided by unsigned b */
    if (ptrA)
    {
        size_t sizeA, sizeB, sizeC;

        caam_get_bin_from_mp_int(ptrA, a, &sizeA);
        caam_get_bin_from_mp_int(ptrB, b, &sizeB);

        if (kStatus_Success ==
            CAAM_PKHA_ModRed(CAAM, &s_caamHandle, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kCAAM_PKHA_IntegerArith))
        {
            mp_read_unsigned_bin(c, ptrC, sizeC);
        }
        else
        {
            res = FP_VAL;
        }
    }
    else
    {
        res = FP_MEM;
    }

    /* fix sign */
    c->sign = neg;

    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

/* c = 1/a (mod b) for odd b only */
int fp_invmod(fp_int *a, fp_int *b, fp_int *c)
{
    int res = FP_OKAY;

    uint8_t *ptrA = (uint8_t *)XMALLOC(CAAM_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAAM_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAAM_MAX_INT_BYTES;

    if (ptrA)
    {
        size_t sizeA, sizeB, sizeC;

        caam_get_bin_from_mp_int(ptrA, a, &sizeA);
        caam_get_bin_from_mp_int(ptrB, b, &sizeB);

        if (kStatus_Success ==
            CAAM_PKHA_ModInv(CAAM, &s_caamHandle, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kCAAM_PKHA_IntegerArith))
        {
            mp_read_unsigned_bin(c, ptrC, sizeC);
        }
        else
        {
            res = FP_VAL;
        }
    }
    else
    {
        res = FP_MEM;
    }

    c->sign = a->sign;
    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
    int res = FP_OKAY;
    fp_int t;

    uint8_t *ptrA = (uint8_t *)XMALLOC(CAAM_MAX_INT_BYTES * 4, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAAM_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAAM_MAX_INT_BYTES;
    uint8_t *ptrD = ptrC + CAAM_MAX_INT_BYTES;

    /* if A or B is negative, substracta abs(A) or abs(B) from modulus to get positive integer representation of the
     * same number */
    fp_init(&t);
    if (a->sign)
    {
        fp_add(a, c, &t);
        fp_copy(&t, a);
    }
    if (b->sign)
    {
        fp_add(b, c, &t);
        fp_copy(&t, b);
    }

    if (ptrA)
    {
        size_t sizeA, sizeB, sizeC, sizeD;

        caam_get_bin_from_mp_int(ptrA, a, &sizeA);
        caam_get_bin_from_mp_int(ptrB, b, &sizeB);
        caam_get_bin_from_mp_int(ptrC, c, &sizeC);

        /* (A*B)mod C = ((A mod C) * (B mod C)) mod C  */
        if (CAAM_PKHA_CompareBigNum(ptrA, sizeA, ptrC, sizeC) >= 0)
        {
            if (kStatus_Success !=
                CAAM_PKHA_ModRed(CAAM, &s_caamHandle, ptrA, sizeA, ptrC, sizeC, ptrA, &sizeA, kCAAM_PKHA_IntegerArith))
            {
                res = FP_VAL;
            }
        }
        if ((FP_OKAY == res) && (CAAM_PKHA_CompareBigNum(ptrB, sizeB, ptrC, sizeC) >= 0))
        {
            if (kStatus_Success !=
                CAAM_PKHA_ModRed(CAAM, &s_caamHandle, ptrB, sizeB, ptrC, sizeC, ptrB, &sizeB, kCAAM_PKHA_IntegerArith))
            {
                res = FP_VAL;
            }
        }

        if (FP_OKAY == res)
        {
            if (kStatus_Success != CAAM_PKHA_ModMul(CAAM, &s_caamHandle, ptrA, sizeA, ptrB, sizeB, ptrC, sizeC, ptrD,
                                                    &sizeD, kCAAM_PKHA_IntegerArith, kCAAM_PKHA_NormalValue,
                                                    kCAAM_PKHA_NormalValue, kCAAM_PKHA_TimingEqualized))
            {
                res = FP_VAL;
            }
        }

        if (FP_OKAY == res)
        {
            mp_read_unsigned_bin(d, ptrD, sizeD);
        }
    }
    else
    {
        res = FP_MEM;
    }

    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

/* Y = G^X mod P */
int _fp_exptmod(fp_int *G, fp_int *X, fp_int *P, fp_int *Y)
{
    int res = FP_OKAY;
    fp_int t;

    size_t sizeG, sizeX, sizeP;
    uint8_t *ptrG = (uint8_t *)XMALLOC(CAAM_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrX = ptrG + CAAM_MAX_INT_BYTES;
    uint8_t *ptrP = ptrX + CAAM_MAX_INT_BYTES;

    /* if G is negative, add modulus to convert to positive number for CAAM */
    fp_init(&t);
    if (G->sign)
    {
        fp_add(G, P, &t);
        fp_copy(&t, G);
    }

    if (ptrG)
    {
        caam_get_bin_from_mp_int(ptrG, G, &sizeG);
        caam_get_bin_from_mp_int(ptrX, X, &sizeX);
        caam_get_bin_from_mp_int(ptrP, P, &sizeP);

        /* if number if greater that modulo, we must first reduce due to CAAM requirement on modular exponentiaton
         */
        /* it needs number less than modulus.  */
        /* we can take advantage of modular arithmetic rule that: A^B mod C = ( (A mod C)^B ) mod C
           and so we do first (A mod N) : CAAM does not give size requirement on A versus N,
           and then the modular exponentiation.
         */
        /* if G >= P then */
        if (CAAM_PKHA_CompareBigNum(ptrG, sizeG, ptrP, sizeP) >= 0)
        {
            res = (int)CAAM_PKHA_ModRed(CAAM, &s_caamHandle, ptrG, sizeG, ptrP, sizeP, ptrG, &sizeG,
                                        kCAAM_PKHA_IntegerArith);

            if (res != kStatus_Success)
            {
                res = FP_VAL;
            }
        }

        if (FP_OKAY == res)
        {
            res = (int)CAAM_PKHA_ModExp(CAAM, &s_caamHandle, ptrG, sizeG, ptrP, sizeP, ptrX, sizeX, ptrP, &sizeP,
                                        kCAAM_PKHA_IntegerArith, kCAAM_PKHA_NormalValue, kCAAM_PKHA_TimingEqualized);

            if (res != kStatus_Success)
            {
                res = FP_VAL;
            }
            else
            {
                mp_read_unsigned_bin(Y, ptrP, sizeP);
            }
        }
    }
    else
    {
        res = FP_MEM;
    }

    if (ptrG)
    {
        XFREE(ptrG, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

#elif defined(FREESCALE_CAU3_TFM)

/* Reverse array in memory (in place) */
static void cau3_reverse_array(uint8_t *src, size_t src_len)
{
    int i;

    for (i = 0; i < src_len / 2; i++)
    {
        uint8_t tmp;

        tmp = src[i];
        src[i] = src[src_len - 1 - i];
        src[src_len - 1 - i] = tmp;
    }
}

/* same as fp_to_unsigned_bin() with fp_reverse() skipped */
static void fp_to_unsigned_lsb_bin(fp_int *a, unsigned char *b)
{
    fp_int t;

    fp_init_copy(&t, a);

    (void)_fp_to_unsigned_bin(0, &t, b);
}

static void cau3_get_lsb_bin_from_mp_int(uint8_t *dst, mp_int *A, size_t *psz)
{
    size_t sz;

    sz = mp_unsigned_bin_size(A);
    fp_to_unsigned_lsb_bin(A, dst); /* result is lsbyte at lowest addr as required by CAU3 */
    *psz = sz;
}

/* these function are used by wolfSSL upper layers (like RSA) */

/* c = a * b */
void fp_mul(fp_int *A, fp_int *B, fp_int *C)
{

    int neg;

    neg = (A->sign == B->sign) ? FP_ZPOS : FP_NEG;

    /* unsigned multiply */
    uint8_t *ptrA = (uint8_t *)XMALLOC(CAU3_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAU3_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAU3_MAX_INT_BYTES;

    if (ptrA)
    {
        size_t sizeA, sizeB;

        cau3_get_lsb_bin_from_mp_int(ptrA, A, &sizeA);
        cau3_get_lsb_bin_from_mp_int(ptrB, B, &sizeB);
        XMEMSET(ptrC, 0xFF, CAU3_MAX_INT_BYTES);

        if (kStatus_Success != CAU3_PKHA_ModMul(CAU3, ptrA, sizeA, ptrB, sizeB, ptrC, CAU3_MAX_INT_BYTES, ptrB,
                                                &sizeB, kCAU3_PKHA_IntegerArith, kCAU3_PKHA_NormalValue,
                                                kCAU3_PKHA_NormalValue, kCAU3_PKHA_TimingEqualized))
        {
            return;
        }

        cau3_reverse_array(ptrB, sizeB);
        mp_read_unsigned_bin(C, ptrB, sizeB);
    }

    /* fix sign */
    C->sign = neg;
    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return;
}

/* c = a mod b, 0 <= c < b  */
int fp_mod(fp_int *a, fp_int *b, fp_int *c)
{
    int res = FP_OKAY;
    int neg;

    uint8_t *ptrA = (uint8_t *)XMALLOC(CAU3_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAU3_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAU3_MAX_INT_BYTES;

    /* get sign for the result */
    neg = (a->sign == b->sign) ? FP_ZPOS : FP_NEG;

    /* get remainder of unsigned a divided by unsigned b */
    if (ptrA)
    {
        size_t sizeA, sizeB, sizeC;

        cau3_get_lsb_bin_from_mp_int(ptrA, a, &sizeA);
        cau3_get_lsb_bin_from_mp_int(ptrB, b, &sizeB);

        if (kStatus_Success ==
            CAU3_PKHA_ModRed(CAU3, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kCAU3_PKHA_IntegerArith))
        {
            cau3_reverse_array(ptrC, sizeC);
            mp_read_unsigned_bin(c, ptrC, sizeC);
        }
        else
        {
            res = FP_VAL;
        }
    }
    else
    {
        res = FP_MEM;
    }

    /* fix sign */
    c->sign = neg;

    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

/* c = 1/a (mod b) for odd b only */
int fp_invmod(fp_int *a, fp_int *b, fp_int *c)
{
    int res = FP_OKAY;

    uint8_t *ptrA = (uint8_t *)XMALLOC(CAU3_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAU3_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAU3_MAX_INT_BYTES;

    if (ptrA)
    {
        size_t sizeA, sizeB, sizeC;

        cau3_get_lsb_bin_from_mp_int(ptrA, a, &sizeA);
        cau3_get_lsb_bin_from_mp_int(ptrB, b, &sizeB);

        if (kStatus_Success ==
            CAU3_PKHA_ModInv(CAU3, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kCAU3_PKHA_IntegerArith))
        {
            cau3_reverse_array(ptrC, sizeC);
            mp_read_unsigned_bin(c, ptrC, sizeC);
        }
        else
        {
            res = FP_VAL;
        }
    }
    else
    {
        res = FP_MEM;
    }

    c->sign = a->sign;
    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
    int res = FP_OKAY;
    fp_int t;

    uint8_t *ptrA = (uint8_t *)XMALLOC(CAU3_MAX_INT_BYTES * 4, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrB = ptrA + CAU3_MAX_INT_BYTES;
    uint8_t *ptrC = ptrB + CAU3_MAX_INT_BYTES;
    uint8_t *ptrD = ptrC + CAU3_MAX_INT_BYTES;

    /* if A or B is negative, substracta abs(A) or abs(B) from modulus to get positive integer representation of the
     * same number */
    fp_init(&t);
    if (a->sign)
    {
        fp_add(a, c, &t);
        fp_copy(&t, a);
    }
    if (b->sign)
    {
        fp_add(b, c, &t);
        fp_copy(&t, b);
    }

    if (ptrA)
    {
        size_t sizeA, sizeB, sizeC, sizeD;

        cau3_get_lsb_bin_from_mp_int(ptrA, a, &sizeA);
        cau3_get_lsb_bin_from_mp_int(ptrB, b, &sizeB);
        cau3_get_lsb_bin_from_mp_int(ptrC, c, &sizeC);

        /* (A*B)mod C = ((A mod C) * (B mod C)) mod C  */
        if (CAU3_PKHA_CompareBigNum(ptrA, sizeA, ptrC, sizeC) >= 0)
        {
            if (kStatus_Success !=
                CAU3_PKHA_ModRed(CAU3, ptrA, sizeA, ptrC, sizeC, ptrA, &sizeA, kCAU3_PKHA_IntegerArith))
            {
                res = FP_VAL;
            }
        }
        if ((FP_OKAY == res) && (CAU3_PKHA_CompareBigNum(ptrB, sizeB, ptrC, sizeC) >= 0))
        {
            if (kStatus_Success !=
                CAU3_PKHA_ModRed(CAU3, ptrB, sizeB, ptrC, sizeC, ptrB, &sizeB, kCAU3_PKHA_IntegerArith))
            {
                res = FP_VAL;
            }
        }

        if (FP_OKAY == res)
        {
            if (kStatus_Success != CAU3_PKHA_ModMul(CAU3, ptrA, sizeA, ptrB, sizeB, ptrC, sizeC, ptrD, &sizeD,
                                                    kCAU3_PKHA_IntegerArith, kCAU3_PKHA_NormalValue,
                                                    kCAU3_PKHA_NormalValue, kCAU3_PKHA_TimingEqualized))
            {
                res = FP_VAL;
            }
        }

        if (FP_OKAY == res)
        {
            cau3_reverse_array(ptrD, sizeD);
            mp_read_unsigned_bin(d, ptrD, sizeD);
        }
    }
    else
    {
        res = FP_MEM;
    }

    if (ptrA)
    {
        XFREE(ptrA, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}

/* Y = G^X mod P */
int _fp_exptmod(fp_int *G, fp_int *X, fp_int *P, fp_int *Y)
{
    int res = FP_OKAY;
    fp_int t;

    size_t sizeG, sizeX, sizeP;
    uint8_t *ptrG = (uint8_t *)XMALLOC(CAU3_MAX_INT_BYTES * 3, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *ptrX = ptrG + CAU3_MAX_INT_BYTES;
    uint8_t *ptrP = ptrX + CAU3_MAX_INT_BYTES;

    /* if G is negative, add modulus to convert to positive number for CAU3 */
    fp_init(&t);
    if (G->sign)
    {
        fp_add(G, P, &t);
        fp_copy(&t, G);
    }

    if (ptrG)
    {
        cau3_get_lsb_bin_from_mp_int(ptrG, G, &sizeG);
        cau3_get_lsb_bin_from_mp_int(ptrX, X, &sizeX);
        cau3_get_lsb_bin_from_mp_int(ptrP, P, &sizeP);

        /* if number if greater that modulo, we must first reduce due to CAU3 requirement on modular exponentiaton */
        /* it needs number less than modulus.  */
        /* we can take advantage of modular arithmetic rule that: A^B mod C = ( (A mod C)^B ) mod C
           and so we do first (A mod N) : CAU3 does not give size requirement on A versus N,
           and then the modular exponentiation.
         */
        /* if G >= P then */
        if (CAU3_PKHA_CompareBigNum(ptrG, sizeG, ptrP, sizeP) >= 0)
        {
            res = (int)CAU3_PKHA_ModRed(CAU3, ptrG, sizeG, ptrP, sizeP, ptrG, &sizeG, kCAU3_PKHA_IntegerArith);

            if (res != kStatus_Success)
            {
                res = FP_VAL;
            }
        }

        if (FP_OKAY == res)
        {
            res = (int)CAU3_PKHA_ModExp(CAU3, ptrG, sizeG, ptrP, sizeP, ptrX, sizeX, ptrP, &sizeP,
                                        kCAU3_PKHA_IntegerArith, kCAU3_PKHA_NormalValue, kCAU3_PKHA_TimingEqualized);

            if (res != kStatus_Success)
            {
                res = FP_VAL;
            }
            else
            {
                cau3_reverse_array(ptrP, sizeP);
                mp_read_unsigned_bin(Y, ptrP, sizeP);
            }
        }
    }
    else
    {
        res = FP_MEM;
    }

    if (ptrG)
    {
        XFREE(ptrG, 0, DYNAMIC_TYPE_BIGINT);
    }
    return res;
}
#endif /* FREESCALE_CAAM_TFM */
#endif /* USE_FAST_MATH */

/******************************************************************************/
/****************************** ECC *******************************************/
/******************************************************************************/
#ifdef FREESCALE_LTC_ECC
#include <stdint.h>
#include "fsl_ltc.h"
#include <wolfssl/wolfcrypt/error-crypt.h>

/* convert from mp_int to LTC integer, as array of bytes of size sz.
 * if mp_int has less bytes than sz, add zero bytes at most significant byte positions.
 * This is when for example modulus is 32 bytes (P-256 curve)
 * and mp_int has only 31 bytes, we add leading zeroes
 * so that result array has 32 bytes, same as modulus (sz).
 */
static void ltc_get_from_mp_int(uint8_t *dst, mp_int *a, int sz)
{
    int szbin;
    int offset;

    /* check how many bytes are in the mp_int */
    szbin = mp_unsigned_bin_size(a);

    /* compute offset from dst */
    offset = sz - szbin;
    if (offset < 0)
        offset = 0;
    if (offset > sz)
        offset = sz;

    /* add leading zeroes */
    if (offset)
        memset(dst, 0, offset);

    /* convert mp_int to array of bytes */
    mp_to_unsigned_bin(a, dst + offset);

    /* reverse array for LTC direct use */
    ltc_reverse_array(dst, sz);
}

/* ECC specs in lsbyte at lowest address format for direct use by LTC PKHA driver functions */
#if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
#define ECC192
#endif
#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
#define ECC224
#endif
#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
#define ECC256
#endif
#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
#define ECC384
#endif

/* P-256 */
#ifdef ECC256
const uint8_t ltc_ecc256_modulus[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ltc_ecc256_r2modn[32] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFB, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00};
const uint8_t ltc_ecc256_aCurveParam[32] = {0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ltc_ecc256_bCurveParam[32] = {0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B, 0xF6, 0xB0, 0x53,
                                            0xCC, 0xB0, 0x06, 0x1D, 0x65, 0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD,
                                            0xEB, 0xB3, 0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A};
#endif

#ifdef ECC192
const uint8_t ltc_ecc192_modulus[24] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ltc_ecc192_r2modn[24] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t ltc_ecc192_aCurveParam[24] = {0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ltc_ecc192_bCurveParam[24] = {0xB1, 0xB9, 0x46, 0xC1, 0xEC, 0xDE, 0xB8, 0xFE, 0x49, 0x30, 0x24, 0x72,
                                            0xAB, 0xE9, 0xA7, 0x0F, 0xE7, 0x80, 0x9C, 0xE5, 0x19, 0x05, 0x21, 0x64};
#endif

#ifdef ECC224
const uint8_t ltc_ecc224_modulus[28] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ltc_ecc224_r2modn[28] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
const uint8_t ltc_ecc224_aCurveParam[28] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ltc_ecc224_bCurveParam[28] = {0xB4, 0xFF, 0x55, 0x23, 0x43, 0x39, 0x0B, 0x27, 0xBA, 0xD8,
                                            0xBF, 0xD7, 0xB7, 0xB0, 0x44, 0x50, 0x56, 0x32, 0x41, 0xF5,
                                            0xAB, 0xB3, 0x04, 0x0C, 0x85, 0x0A, 0x05, 0xB4};
#endif

#ifdef ECC384
const uint8_t ltc_ecc384_modulus[48] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t ltc_ecc384_r2modn[48] = {0x01, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                       0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
                                       0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t ltc_ecc384_aCurveParam[48] = {0xfc, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t ltc_ecc384_bCurveParam[48] = {0xef, 0x2a, 0xec, 0xd3, 0xed, 0xc8, 0x85, 0x2a, 0x9d, 0xd1, 0x2e, 0x8a,
                                            0x8d, 0x39, 0x56, 0xc6, 0x5a, 0x87, 0x13, 0x50, 0x8f, 0x08, 0x14, 0x03,
                                            0x12, 0x41, 0x81, 0xfe, 0x6e, 0x9c, 0x1d, 0x18, 0x19, 0x2d, 0xf8, 0xe3,
                                            0x6b, 0x05, 0x8e, 0x98, 0xe4, 0xe7, 0x3e, 0xe2, 0xa7, 0x2f, 0x31, 0xb3};
#endif

static int ltc_get_ecc_specs(
    const uint8_t **modulus, const uint8_t **r2modn, const uint8_t **aCurveParam, const uint8_t **bCurveParam, int size)
{
    if (32 == size)
    {
        *modulus = ltc_ecc256_modulus;
        *r2modn = ltc_ecc256_r2modn;
        *aCurveParam = ltc_ecc256_aCurveParam;
        *bCurveParam = ltc_ecc256_bCurveParam;
    }
#ifdef ECC224
    else if (28 == size)
    {
        *modulus = ltc_ecc224_modulus;
        *r2modn = ltc_ecc224_r2modn;
        *aCurveParam = ltc_ecc224_aCurveParam;
        *bCurveParam = ltc_ecc224_bCurveParam;
    }
#endif
#ifdef ECC192
    else if (24 == size)
    {
        *modulus = ltc_ecc192_modulus;
        *r2modn = ltc_ecc192_r2modn;
        *aCurveParam = ltc_ecc192_aCurveParam;
        *bCurveParam = ltc_ecc192_bCurveParam;
    }
#endif
#ifdef HAVE_ECC384
    else if (48 == size)
    {
        *modulus = ltc_ecc384_modulus;
        *r2modn = ltc_ecc384_r2modn;
        *aCurveParam = ltc_ecc384_aCurveParam;
        *bCurveParam = ltc_ecc384_bCurveParam;
    }
#endif
    else
    {
        return -1;
    }
    return 0;
}

/**
   Perform a point multiplication  (timing resistant)
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
            (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
int wc_ecc_mulmod_ex(mp_int *k, ecc_point *G, ecc_point *R, mp_int *a, mp_int *modulus, int map, void *heap)
{
    ltc_pkha_ecc_point_t B;
    uint8_t size;
    int szModulus;
    int szkbin;
    bool point_of_infinity;
    status_t status;

    uint8_t Gxbin[LTC_MAX_ECC_BITS / 8];
    uint8_t Gybin[LTC_MAX_ECC_BITS / 8];
    uint8_t kbin[LTC_MAX_INT_BYTES];

    const uint8_t *modbin;
    const uint8_t *aCurveParam;
    const uint8_t *bCurveParam;
    const uint8_t *r2modn;

    if (k == NULL || G == NULL || R == NULL || modulus == NULL)
        return ECC_BAD_ARG_E;

    szModulus = mp_unsigned_bin_size(modulus);
    szkbin = mp_unsigned_bin_size(k);

    ltc_get_from_mp_int(kbin, k, szkbin);
    ltc_get_from_mp_int(Gxbin, G->x, szModulus);
    ltc_get_from_mp_int(Gybin, G->y, szModulus);

    size = szModulus;
    /* find LTC friendly parameters for the selected curve */
    if (0 != ltc_get_ecc_specs(&modbin, &r2modn, &aCurveParam, &bCurveParam, size))
    {
        return ECC_BAD_ARG_E;
    }

    B.X = &Gxbin[0];
    B.Y = &Gybin[0];

    status = LTC_PKHA_ECC_PointMul(LTC_BASE, &B, kbin, szkbin, modbin, r2modn, aCurveParam, bCurveParam, size,
                                   kLTC_PKHA_TimingEqualized, kLTC_PKHA_IntegerArith, &B, &point_of_infinity);
    if (status != kStatus_Success)
        return FP_VAL;

    ltc_reverse_array(Gxbin, size);
    ltc_reverse_array(Gybin, size);
    mp_read_unsigned_bin(R->x, Gxbin, size);
    mp_read_unsigned_bin(R->y, Gybin, size);
    /* if k is negative, we compute the multiplication with abs(-k)
     * with result (x, y) and modify the result to (x, -y)
     */
    R->y->sign = k->sign;
    mp_set(R->z, 1);
    return MP_OKAY;
}

int wc_ecc_point_add(ecc_point *mG, ecc_point *mQ, ecc_point *mR, mp_int *m)
{
    int err;
    ltc_pkha_ecc_point_t A, B;
    int size;
    status_t status;

    uint8_t Gxbin[LTC_MAX_ECC_BITS / 8];
    uint8_t Gybin[LTC_MAX_ECC_BITS / 8];
    uint8_t Qxbin[LTC_MAX_ECC_BITS / 8];
    uint8_t Qybin[LTC_MAX_ECC_BITS / 8];
    const uint8_t *modbin;
    const uint8_t *aCurveParam;
    const uint8_t *bCurveParam;
    const uint8_t *r2modn;

    size = mp_unsigned_bin_size(m);
    /* find LTC friendly parameters for the selected curve */
    if (0 != ltc_get_ecc_specs(&modbin, &r2modn, &aCurveParam, &bCurveParam, size))
    {
        err = ECC_BAD_ARG_E;
    }
    else
    {
        ltc_get_from_mp_int(Gxbin, mG->x, size);
        ltc_get_from_mp_int(Gybin, mG->y, size);
        ltc_get_from_mp_int(Qxbin, mQ->x, size);
        ltc_get_from_mp_int(Qybin, mQ->y, size);

        A.X = Gxbin;
        A.Y = Gybin;

        B.X = Qxbin;
        B.Y = Qybin;

        status = LTC_PKHA_ECC_PointAdd(LTC_BASE, &A, &B, modbin, r2modn, aCurveParam, bCurveParam, size,
                                       kLTC_PKHA_IntegerArith, &A);
        if (status != kStatus_Success)
        {
            err = FP_VAL;
        }
        else
        {
            ltc_reverse_array(Gxbin, size);
            ltc_reverse_array(Gybin, size);
            mp_read_unsigned_bin(mR->x, Gxbin, size);
            mp_read_unsigned_bin(mR->y, Gybin, size);
            mp_set(mR->z, 1);
            err = MP_OKAY;
        }
    }
    return err;
}

#if defined(HAVE_ED25519) || defined(HAVE_CURVE25519)
/* Weierstrass parameters of prime 2^255 - 19 */
static const uint8_t modbin[32] = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

static const uint8_t r2mod[32] = {
    0xa4, 0x05,
}; /* precomputed R2modN for the curve25519 */

/* invThree = ModInv(3,modbin) in LSB first */
static const uint8_t invThree[32] = {0x49, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                                     0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                                     0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

/*
 *
 * finds square root in finite field when modulus congruent to 5 modulo 8
 * this is fixed to curve25519 modulus 2^255 - 19 which is congruent to 5 modulo 8
 *
 * This function solves equation: res^2 = a mod (2^255 - 19)
 *
p = prime
p % 8 must be 5

v = ModularArithmetic.powmod(2*a, (p-5)/8, p)
i = (2*a*v**2) % p
r1 = 1*a*v*(i - 1) % p
r2 = -1*a*v*(i - 1) % p
puts "Gy=0x#{r2.to_s(16)}"
 */
status_t LTC_PKHA_Prime25519SquareRootMod(const uint8_t *A, size_t sizeA, uint8_t *res, size_t *szRes, int sign)
{
    status_t status;
    const uint8_t curve25519_param[] = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f};

    uint8_t twoA[sizeof(modbin)] = {0};
    uint8_t V[sizeof(modbin)] = {0};
    uint8_t I[sizeof(modbin)] = {0};
    uint8_t VV[sizeof(modbin)] = {0};
    uint16_t szTwoA = 0;
    uint16_t szV = 0;
    uint16_t szVV = 0;
    uint16_t szI = 0;
    uint16_t szRes16 = 0;
    uint8_t one = 1;

    /* twoA = 2*A % p */
    status =
        LTC_PKHA_ModAdd(LTC_BASE, A, sizeA, A, sizeA, modbin, sizeof(modbin), twoA, &szTwoA, kLTC_PKHA_IntegerArith);

    /* V = ModularArithmetic.powmod(twoA, (p-5)/8, p) */
    if (status == kStatus_Success)
    {
        status =
            LTC_PKHA_ModExp(LTC_BASE, twoA, szTwoA, modbin, sizeof(modbin), curve25519_param, sizeof(curve25519_param),
                            V, &szV, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* VV = V*V % p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, V, szV, V, szV, modbin, sizeof(modbin), VV, &szVV, kLTC_PKHA_IntegerArith,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* I = twoA * VV = 2*A*V*V % p */
    if (status == kStatus_Success)
    {
        status =
            LTC_PKHA_ModMul(LTC_BASE, twoA, szTwoA, VV, szVV, modbin, sizeof(modbin), I, &szI, kLTC_PKHA_IntegerArith,
                            kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* I = I - 1 */
    memset(VV, 0xff, sizeof(VV)); /* just temp for maximum integer - for non-modular substract */
    if (0 <= LTC_PKHA_CompareBigNum(I, szI, &one, sizeof(one)))
    {
        if (status == kStatus_Success)
        {
            status = LTC_PKHA_ModSub1(LTC_BASE, I, szI, &one, sizeof(one), VV, sizeof(VV), I, &szI);
        }
    }
    else
    {
        if (status == kStatus_Success)
        {
            status = LTC_PKHA_ModSub1(LTC_BASE, modbin, sizeof(modbin), &one, sizeof(one), VV, sizeof(VV), I, &szI);
        }
    }
    if (status == kStatus_Success)
    {
        /* res = a*v  mod p */
        status =
            LTC_PKHA_ModMul(LTC_BASE, A, sizeA, V, szV, modbin, sizeof(modbin), res, &szRes16, kLTC_PKHA_IntegerArith,
                            kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* res = res * (i-1) mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, res, szRes16, I, szI, modbin, sizeof(modbin), res, &szRes16,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    /* if X mod 2 != X_0 then we need the -X
     *
     * X mod 2 get from LSB bit0
     */
    if ((status == kStatus_Success) && ((bool)sign != (bool)(res[0] & 0x01u)))
    {
        status = LTC_PKHA_ModSub1(LTC_BASE, modbin, sizeof(modbin), res, szRes16, VV, sizeof(VV), res,
                                  &szRes16); /* -a = p - a */
    }

    if (status == kStatus_Success)
    {
        *szRes = szRes16;
    }

    return status;
}
#endif

#ifdef HAVE_CURVE25519

/* for LTC we need Weierstrass format of curve25519 parameters
         * these two are base point X and Y.
         * in LSB first format (native for LTC)
         */
static ECPoint ecBasePoint = {
    {0x5a, 0x24, 0xad, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a},
    {0xd9, 0xd3, 0xce, 0x7e, 0xa2, 0xc5, 0xe9, 0x29, 0xb2, 0x61, 0x7c, 0x6d, 0x7e, 0x4d, 0x3d, 0x92, 0x4c, 0xd1, 0x48,
     0x77, 0x2c, 0xdd, 0x1e, 0xe0, 0xb4, 0x86, 0xa0, 0xb8, 0xa1, 0x19, 0xae, 0x20},
};

ECPoint *wc_curve25519_GetBasePoint(void)
{
    return &ecBasePoint;
}

static const uint8_t aCurveParam[CURVE25519_KEYSIZE] = {
    0x44, 0xa1, 0x14, 0x49, 0x98, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a};

static const uint8_t bCurveParam[CURVE25519_KEYSIZE] = {
    0x64, 0xc8, 0x10, 0x77, 0x9c, 0x5e, 0x0b, 0x26, 0xb4, 0x97, 0xd0, 0x5e, 0x42, 0x7b, 0x09, 0xed,
    0x25, 0xb4, 0x97, 0xd0, 0x5e, 0x42, 0x7b, 0x09, 0xed, 0x25, 0xb4, 0x97, 0xd0, 0x5e, 0x42, 0x7b};

/* transform a point on Montgomery curve to a point on Weierstrass curve */
status_t LTC_PKHA_Curve25519ToWeierstrass(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut)
{
    /* offset X point (in Montgomery) so that it becomes Weierstrass */
    const uint8_t offset[] = {0x51, 0x24, 0xad, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                              0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                              0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a};
    uint16_t sizeRes = 0;
    status_t status;
    status = LTC_PKHA_ModAdd(LTC_BASE, ltcPointIn->X, CURVE25519_KEYSIZE, offset, sizeof(offset), modbin,
                             CURVE25519_KEYSIZE, ltcPointOut->X, &sizeRes, kLTC_PKHA_IntegerArith);

    if (status == kStatus_Success)
    {
        if (ltcPointOut->Y != ltcPointIn->Y)
        {
            XMEMCPY(ltcPointOut->Y, ltcPointIn->Y, CURVE25519_KEYSIZE);
        }
    }

    return status;
}

/* transform a point on Weierstrass curve to a point on Montgomery curve */
status_t LTC_PKHA_WeierstrassToCurve25519(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut)
{
    status_t status;
    uint16_t resultSize = 0;
    uint8_t three = 0x03;

    status = LTC_PKHA_ModMul(LTC_BASE, &three, sizeof(three), ltcPointIn->X, CURVE25519_KEYSIZE, modbin,
                             CURVE25519_KEYSIZE, ltcPointOut->X, &resultSize, kLTC_PKHA_IntegerArith,
                             kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);

    if (status == kStatus_Success)
    {
        static const uint8_t A[] = {0x06, 0x6d, 0x07};
        if (LTC_PKHA_CompareBigNum(ltcPointOut->X, resultSize, A, sizeof(A)))
        {
            status = LTC_PKHA_ModSub1(LTC_BASE, ltcPointOut->X, resultSize, A, sizeof(A), modbin, CURVE25519_KEYSIZE,
                                      ltcPointOut->X, &resultSize);
        }
        else
        {
            status = LTC_PKHA_ModSub2(LTC_BASE, ltcPointOut->X, resultSize, A, sizeof(A), modbin, CURVE25519_KEYSIZE,
                                      ltcPointOut->X, &resultSize);
        }
    }

    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, invThree, CURVE25519_KEYSIZE, ltcPointOut->X, resultSize, modbin,
                                 CURVE25519_KEYSIZE, ltcPointOut->X, &resultSize, kLTC_PKHA_IntegerArith,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    if (status == kStatus_Success)
    {
        if (ltcPointOut->Y != ltcPointIn->Y)
        {
            XMEMCPY(ltcPointOut->Y, ltcPointIn->Y, CURVE25519_KEYSIZE);
        }
    }

    return status;
}

/* Y = square root (X^3 + 486662*X^2 + X) */
status_t LTC_PKHA_Curve25519ComputeY(ltc_pkha_ecc_point_t *ltcPoint)
{
    uint8_t three = 3;
    uint8_t A[] = {0x06, 0x6d, 0x07};
    uint8_t U[CURVE25519_KEYSIZE] = {0};
    uint8_t X2[CURVE25519_KEYSIZE] = {0};
    uint16_t sizeU = 0;
    uint16_t sizeX2 = 0;
    size_t szRes = 0;
    status_t status;

    /* X^3 */
    status = LTC_PKHA_ModExp(LTC_BASE, ltcPoint->X, CURVE25519_KEYSIZE, modbin, CURVE25519_KEYSIZE, &three, 1, U,
                             &sizeU, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);

    /* X^2 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, ltcPoint->X, CURVE25519_KEYSIZE, ltcPoint->X, CURVE25519_KEYSIZE, modbin,
                                 CURVE25519_KEYSIZE, X2, &sizeX2, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* 486662*X^2 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, A, sizeof(A), X2, sizeX2, modbin, CURVE25519_KEYSIZE, X2, &sizeX2,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    /* X^3 + 486662*X^2 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, U, sizeU, X2, sizeX2, modbin, CURVE25519_KEYSIZE, U, &sizeU,
                                 kLTC_PKHA_IntegerArith);
    }

    /* U = X^3 + 486662*X^2 + X */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, U, sizeU, ltcPoint->X, CURVE25519_KEYSIZE, modbin, CURVE25519_KEYSIZE, U,
                                 &sizeU, kLTC_PKHA_IntegerArith);
    }

    /* Y = modular square root of U (U is Y^2) */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_Prime25519SquareRootMod(U, sizeU, ltcPoint->Y, &szRes, 1);
    }

    return status;
}

/* Q = n*P */
/* if type is set, the input point p is in Montgomery curve coordinates, so there is a map to Weierstrass curve */
/* q output point is always in Montgomery curve coordinates */
int wc_curve25519(ECPoint *q, byte *n, ECPoint *p, fsl_ltc_ecc_coordinate_system_t type)
{
    status_t status;
    ltc_pkha_ecc_point_t ltcPoint;
    ltc_pkha_ecc_point_t ltcPointOut;
    ECPoint pIn = {{0}};

    XMEMCPY(&pIn, p, sizeof(*p));
    ltcPoint.X = &pIn.point[0];
    ltcPoint.Y = &pIn.pointY[0];

    /* if input point P is on Curve25519 Montgomery curve, transform it to Weierstrass equivalent */
    if (type == kLTC_Curve25519)
    {
        LTC_PKHA_Curve25519ToWeierstrass(&ltcPoint, &ltcPoint);
    }

    ltcPointOut.X = &q->point[0];
    ltcPointOut.Y = &q->pointY[0];
    /* modbin, r2mod, aCurveParam, bCurveParam are Weierstrass equivalent with Curve25519 */
    status = LTC_PKHA_ECC_PointMul(LTC_BASE, &ltcPoint, n, CURVE25519_KEYSIZE, modbin, r2mod, aCurveParam, bCurveParam,
                                   CURVE25519_KEYSIZE, kLTC_PKHA_TimingEqualized, kLTC_PKHA_IntegerArith, &ltcPointOut,
                                   NULL);

    /* now need to map from Weierstrass form to Montgomery form */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_WeierstrassToCurve25519(&ltcPointOut, &ltcPointOut);
    }

    if (status == kStatus_Success)
        return 0;
    else
        return IS_POINT_E;
}

#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>

/* a and d are Edwards curve parameters -1 and -121665/121666 prime is 2^255 - 19.
 *
 *
 *
 * https://en.wikipedia.org/wiki/Montgomery_curve#Equivalence_with_Edward_curves
 */

/* d parameter of ed25519 */
static const uint8_t d_coefEd25519[] = {0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41,
                                        0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40,
                                        0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52};

/* Montgomery curve parameter A for a Montgomery curve equivalent with ed25519 */
static const uint8_t A_coefEd25519[] = {0x06, 0x6d, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* Montgomery curve parameter B for a Montgomery curve equivalent with ed25519 */
static const uint8_t B_coefEd25519[] = {0xe5, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

/* these are pre-computed constants used in computations */

/* = 3*B */
static const uint8_t threeB_coefEd25519[] = {0xd5, 0xb8, 0xe9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

/* = -A */
static const uint8_t minus_A_coefEd25519[] = {0xe7, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

/* = 1/B */
static const uint8_t invB_coefEd25519[] = {0xc4, 0xa1, 0x29, 0x7b, 0x8d, 0x2c, 0x85, 0x22, 0xd5, 0x89, 0xaf,
                                           0xaf, 0x6c, 0xfd, 0xe3, 0xff, 0xd9, 0x85, 0x21, 0xa2, 0xe1, 0x2f,
                                           0xce, 0x1c, 0x63, 0x00, 0x24, 0x75, 0xc4, 0x24, 0x7f, 0x6b};

/* = 1/(3*B) */
static const uint8_t A_mul_invThreeB_coefEd25519[] = {0xb9, 0x3e, 0xe4, 0xad, 0xa1, 0x37, 0xa7, 0x93, 0x1c, 0xa4, 0x35,
                                                      0xe0, 0x0c, 0x57, 0xbd, 0xaa, 0x6e, 0x51, 0x94, 0x3e, 0x14, 0xe0,
                                                      0xcb, 0xec, 0xbd, 0xff, 0xe7, 0xb1, 0x27, 0x92, 0x00, 0x63};

/* Weierstrass curve parameter a for a Weierstrass curve equivalent with ed25519 */
static const uint8_t a_coefEd25519[] = {0x2d, 0x17, 0xbc, 0xf8, 0x8e, 0xe1, 0x71, 0xac, 0xf7, 0x2a, 0xa5,
                                        0x0c, 0x5d, 0xb6, 0xb8, 0x6b, 0xd6, 0x3d, 0x7b, 0x61, 0x0d, 0xe1,
                                        0x97, 0x31, 0xe6, 0xbe, 0xb9, 0xa5, 0xd3, 0xac, 0x4e, 0x5d};

/* Weierstrass curve parameter b for a Weierstrass curve equivalent with ed25519 */
static const uint8_t b_coefEd25519[] = {0xa4, 0xb2, 0x64, 0xf3, 0xc1, 0xeb, 0x04, 0x90, 0x32, 0xbc, 0x9f,
                                        0x6b, 0x97, 0x31, 0x48, 0xf5, 0xd5, 0x80, 0x57, 0x10, 0x06, 0xdb,
                                        0x0d, 0x55, 0xe0, 0xb3, 0xd0, 0xcf, 0x9b, 0xb2, 0x11, 0x1d};

/* Ed25519 basepoint B mapped to Weierstrass equivalent */
static uint8_t Wx_Ed25519[ED25519_KEY_SIZE] = {0x35, 0xef, 0x5a, 0x02, 0x9b, 0xc8, 0x55, 0xca, 0x9a, 0x7c, 0x61,
                                               0x0d, 0xdf, 0x3f, 0xc1, 0xa9, 0x18, 0x06, 0xc2, 0xf1, 0x02, 0x8f,
                                               0x0b, 0xf0, 0x39, 0x03, 0x2c, 0xd0, 0x0f, 0xdd, 0x78, 0x2a};
static uint8_t Wy_Ed25519[ED25519_KEY_SIZE] = {0x14, 0x1d, 0x2c, 0xf6, 0xf3, 0x30, 0x78, 0x9b, 0x65, 0x31, 0x71,
                                               0x80, 0x61, 0xd0, 0x6f, 0xcf, 0x23, 0x83, 0x79, 0x63, 0xa5, 0x3b,
                                               0x48, 0xbe, 0x2e, 0xa2, 0x1d, 0xc7, 0xa5, 0x44, 0xc6, 0x29};

static const ltc_pkha_ecc_point_t basepointEd25519 = {
    Wx_Ed25519, Wy_Ed25519,
};

const ltc_pkha_ecc_point_t *LTC_PKHA_Ed25519_BasePoint(void)
{
    return &basepointEd25519;
}

/* input point is on Weierstrass curve, typeOut determines the coordinates system of output point (either Weierstrass or
 * Ed25519) */
status_t LTC_PKHA_Ed25519_PointMul(const ltc_pkha_ecc_point_t *ltcPointIn,
                                   const uint8_t *N,
                                   size_t sizeN,
                                   ltc_pkha_ecc_point_t *ltcPointOut,
                                   fsl_ltc_ecc_coordinate_system_t typeOut)
{
    uint16_t szN = (uint16_t)sizeN;
    status_t status;
    /* input on W, output in W, W parameters of ECC curve are Ed25519 curve parameters mapped to Weierstrass curve */
    status =
        LTC_PKHA_ECC_PointMul(LTC_BASE, ltcPointIn, N, szN, modbin, r2mod, a_coefEd25519, b_coefEd25519,
                              ED25519_KEY_SIZE, kLTC_PKHA_TimingEqualized, kLTC_PKHA_IntegerArith, ltcPointOut, NULL);

    /* Weierstrass coordinates to Ed25519 coordinates */
    if ((status == kStatus_Success) && (typeOut == kLTC_Ed25519))
    {
        status = LTC_PKHA_WeierstrassToEd25519(ltcPointOut, ltcPointOut);
    }
    return status;
}

status_t LTC_PKHA_Ed25519ToWeierstrass(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut)
{
    status_t status;
    uint8_t Mx[ED25519_KEY_SIZE] = {0};
    uint8_t My[ED25519_KEY_SIZE] = {0};
    uint8_t temp[ED25519_KEY_SIZE] = {0};
    uint8_t temp2[ED25519_KEY_SIZE] = {0};
    uint8_t max[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t *Ex;
    const uint8_t *Ey;
    uint8_t *Gx;
    uint8_t *Gy;
    uint16_t szMx = 0;
    uint16_t szGx = 0;
    uint16_t szMy = 0;
    uint16_t szGy = 0;
    uint16_t szTemp = 0;
    uint16_t szTemp2 = 0;
    uint8_t one = 1;

    Ex = ltcPointIn->X;
    Ey = ltcPointIn->Y;
    Gx = ltcPointOut->X;
    Gy = ltcPointOut->Y;
    /* # (Ex, Ey) on Ed (a_ed, d) to (x, y) on M (A,B)
    Mx = (1 + Ey) * ModularArithmetic.invert(1 - Ey, prime) % prime
    My = (1 + Ey) * ModularArithmetic.invert((1 - Ey)*Ex, prime) % prime */

    /* Gx = ((Mx * ModularArithmetic.invert(B, prime)) + (A * ModularArithmetic.invert(3*B, prime))) % prime
    Gy = (My * ModularArithmetic.invert(B, prime)) % prime */

    /* temp = 1 + Ey */
    status = LTC_PKHA_ModAdd(LTC_BASE, Ey, ED25519_KEY_SIZE, &one, sizeof(one), modbin, sizeof(modbin), temp, &szTemp,
                             kLTC_PKHA_IntegerArith);

    /* temp2 = 1 - Ey = 1 + (p - Ey) */
    if (status == kStatus_Success)
    {
        status =
            LTC_PKHA_ModSub1(LTC_BASE, modbin, sizeof(modbin), Ey, ED25519_KEY_SIZE, max, sizeof(max), temp2, &szTemp2);
    }
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, temp2, szTemp2, &one, sizeof(one), modbin, sizeof(modbin), temp2, &szTemp2,
                                 kLTC_PKHA_IntegerArith);
    }

    /* Mx = ModInv(temp2,prime) */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModInv(LTC_BASE, temp2, szTemp2, modbin, sizeof(modbin), Mx, &szMx, kLTC_PKHA_IntegerArith);
    }

    /* Mx = Mx * temp */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, Mx, szMx, temp, szTemp, modbin, ED25519_KEY_SIZE, Mx, &szMx,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    /* My = temp2 * Ex */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, Ex, ED25519_KEY_SIZE, temp2, szTemp2, modbin, ED25519_KEY_SIZE, My, &szMy,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    /* My = ModInv(My, prime) */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModInv(LTC_BASE, My, szMy, modbin, sizeof(modbin), My, &szMy, kLTC_PKHA_IntegerArith);
    }
    /* My = My * temp */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, My, szMy, temp, szTemp, modbin, ED25519_KEY_SIZE, My, &szMy,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    /* Gx = Mx * invB_coefEd25519 + A_mul_invThreeB_coefEd25519 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, Mx, szMx, invB_coefEd25519, sizeof(invB_coefEd25519), modbin,
                                 ED25519_KEY_SIZE, Gx, &szGx, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, Gx, szGx, A_mul_invThreeB_coefEd25519, sizeof(A_mul_invThreeB_coefEd25519),
                                 modbin, sizeof(modbin), Gx, &szGx, kLTC_PKHA_IntegerArith);
    }

    /* Gy = My * invB_coefEd25519 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, My, szMy, invB_coefEd25519, sizeof(invB_coefEd25519), modbin,
                                 ED25519_KEY_SIZE, Gy, &szGy, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    return status;
}

/*
# (Gx, Gy) on W to (Ex, Ey) on E
My = (B*Gy) % prime
Mx = ((3*B*Gx-A)*ModularArithmetic.invert(3, prime)) % prime
Ex = Mx*ModularArithmetic.invert(My, prime) % prime
Ey = (Mx - 1)*ModularArithmetic.invert(Mx + 1, prime) % prime
*/
status_t LTC_PKHA_WeierstrassToEd25519(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut)
{
    status_t status;
    uint8_t Mx[ED25519_KEY_SIZE] = {0};
    uint8_t My[ED25519_KEY_SIZE] = {0};
    uint8_t temp[ED25519_KEY_SIZE] = {0};
    const uint8_t *Gx;
    const uint8_t *Gy;
    uint8_t *Ex;
    uint8_t *Ey;
    uint16_t szMx = 0;
    uint16_t szEx = 0;
    uint16_t szMy = 0;
    uint16_t szEy = 0;
    uint16_t szTemp = 0;
    uint8_t one = 1;

    Gx = ltcPointIn->X;
    Gy = ltcPointIn->Y;
    Ex = ltcPointOut->X;
    Ey = ltcPointOut->Y;

    /* My = (B*Gy) % prime  */
    status = LTC_PKHA_ModMul(LTC_BASE, B_coefEd25519, sizeof(B_coefEd25519), Gy, ED25519_KEY_SIZE, modbin,
                             ED25519_KEY_SIZE, My, &szMy, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                             kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);

    /* temp = 3*B*Gx mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, threeB_coefEd25519, sizeof(threeB_coefEd25519), Gx, ED25519_KEY_SIZE, modbin,
                                 ED25519_KEY_SIZE, temp, &szTemp, kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }
    /* temp = (temp - A) mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, temp, szTemp, minus_A_coefEd25519, sizeof(minus_A_coefEd25519), modbin,
                                 sizeof(modbin), temp, &szTemp, kLTC_PKHA_IntegerArith);
    }
    /* Mx = (temp/3) mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, temp, szTemp, invThree, sizeof(invThree), modbin, sizeof(modbin), Mx, &szMx,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }
    /* temp = 1/My mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModInv(LTC_BASE, My, szMy, modbin, sizeof(modbin), temp, &szTemp, kLTC_PKHA_IntegerArith);
    }
    /* Ex = Mx * temp mod p */
    if (status == kStatus_Success)
    {
        status =
            LTC_PKHA_ModMul(LTC_BASE, temp, szTemp, Mx, szMx, modbin, sizeof(modbin), Ex, &szEx, kLTC_PKHA_IntegerArith,
                            kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* temp = Mx + 1 mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, Mx, szMx, &one, sizeof(one), modbin, sizeof(modbin), temp, &szTemp,
                                 kLTC_PKHA_IntegerArith);
    }
    /* temp = 1/temp mod p */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModInv(LTC_BASE, temp, szTemp, modbin, sizeof(modbin), temp, &szTemp, kLTC_PKHA_IntegerArith);
    }
    /* Mx = (Mx - 1) mod p */
    if (status == kStatus_Success)
    {
        if (LTC_PKHA_CompareBigNum(Mx, szMx, &one, sizeof(one)) >= 0)
        {
            status = LTC_PKHA_ModSub1(LTC_BASE, Mx, szMx, &one, sizeof(one), modbin, sizeof(modbin), Mx, &szMx);
        }
        else
        {
            /* Mx is zero, so it is modulus, thus we do modulus - 1 */
            XMEMCPY(Mx, modbin, sizeof(modbin));
            Mx[0]--;
        }
    }
    /* Ey = Mx * temp mod p */
    if (status == kStatus_Success)
    {
        status =
            LTC_PKHA_ModMul(LTC_BASE, temp, szTemp, Mx, szMx, modbin, sizeof(modbin), Ey, &szEy, kLTC_PKHA_IntegerArith,
                            kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    return status;
}

status_t LTC_PKHA_Ed25519_PointDecompress(const uint8_t *pubkey, size_t pubKeySize, ltc_pkha_ecc_point_t *ltcPointOut)
{
    status_t status;
    uint8_t one = 1;

    /* pubkey contains the Y coordinate and a sign of X
     */

    /* x^2 = ((y^2 - 1) / (d*y^2 +1)) mod p */

    /* decode Y from pubkey */
    XMEMCPY(ltcPointOut->Y, pubkey, pubKeySize);
    ltcPointOut->Y[pubKeySize - 1] &= ~0x80u;
    int sign = (int)(bool)(pubkey[pubKeySize - 1] & 0x80u);

    uint8_t U[ED25519_KEY_SIZE] = {0};
    uint8_t V[ED25519_KEY_SIZE] = {0};
    uint8_t *X = ltcPointOut->X;
    uint8_t *Y = ltcPointOut->Y;
    uint16_t szU = 0;
    uint16_t szV = 0;
    size_t szRes = 0;

    /* decode X from pubkey */

    /* U = y * y mod p */
    status = LTC_PKHA_ModMul(LTC_BASE, Y, ED25519_KEY_SIZE, Y, ED25519_KEY_SIZE, modbin, ED25519_KEY_SIZE, U, &szU,
                             kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                             kLTC_PKHA_TimingEqualized);
    XMEMCPY(V, U, szU);
    szV = szU;

    /* U = U - 1 = y^2 - 1 */
    if (status == kStatus_Success)
    {
        if (LTC_PKHA_CompareBigNum(U, szU, &one, sizeof(one)) >= 0)
        {
            status = LTC_PKHA_ModSub1(LTC_BASE, U, szU, &one, sizeof(one), modbin, sizeof(modbin), U, &szU);
        }
        else
        {
            /* U is zero, so it is modulus, thus we do modulus - 1 */
            XMEMCPY(U, modbin, sizeof(modbin));
            U[0]--;
        }
    }

    /* V = d*y*y + 1 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, V, szV, d_coefEd25519, ED25519_KEY_SIZE, modbin, ED25519_KEY_SIZE, V, &szV,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, V, szV, &one, sizeof(one), modbin, sizeof(modbin), V, &szV,
                                 kLTC_PKHA_IntegerArith);
    }

    /* U = U / V (mod p) */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModInv(LTC_BASE, V, szV, modbin, sizeof(modbin), V, &szV, kLTC_PKHA_IntegerArith);
    }
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, V, szV, U, szU, modbin, ED25519_KEY_SIZE, U, &szU, kLTC_PKHA_IntegerArith,
                                 kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);
    }

    /* get square root */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_Prime25519SquareRootMod(U, szU, X, &szRes, sign);
    }

    return status;
}

/* LSByte first of Ed25519 parameter l = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t l_coefEdDSA[] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                      0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/*
Input:
  s[0]+256*s[1]+...+256^63*s[63] = s

Output:
  s[0]+256*s[1]+...+256^31*s[31] = s mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
  Overwrites s in place.
*/
status_t LTC_PKHA_sc_reduce(uint8_t *a)
{
    uint16_t szA = 0;
    return LTC_PKHA_ModRed(LTC_BASE, a, 64, l_coefEdDSA, sizeof(l_coefEdDSA), a, &szA, kLTC_PKHA_IntegerArith);
}

/*
Input:
  a[0]+256*a[1]+...+256^31*a[31] = a
  b[0]+256*b[1]+...+256^31*b[31] = b
  c[0]+256*c[1]+...+256^31*c[31] = c

Output:
  s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
*/
status_t LTC_PKHA_sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c)
{
    uint16_t szS = 0;
    uint16_t szB = 0;
    uint8_t tempB[32] = {0};
    status_t status;

    /* Assume only b can be larger than modulus. It is called durind wc_ed25519_sign_msg() where hram (=a) and nonce(=c)
     * have been reduced by LTC_PKHA_sc_reduce()
     * Thus reducing b only.
     */
    status = LTC_PKHA_ModRed(LTC_BASE, b, 32, l_coefEdDSA, sizeof(l_coefEdDSA), tempB, &szB, kLTC_PKHA_IntegerArith);

    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModMul(LTC_BASE, a, 32, tempB, szB, l_coefEdDSA, sizeof(l_coefEdDSA), s, &szS,
                                 kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_NormalValue,
                                 kLTC_PKHA_TimingEqualized);
    }

    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModAdd(LTC_BASE, s, szS, c, 32, l_coefEdDSA, 32, s, &szS, kLTC_PKHA_IntegerArith);
    }

    return status;
}

/*
r = a * A + b * B
where A is public key point, B is basepoint
where a = a[0]+256*a[1]+...+256^31 a[31].
and b = b[0]+256*b[1]+...+256^31 b[31].
B is the Ed25519 base point (x,4/5) with x positive.
*/
status_t LTC_PKHA_SignatureForVerify(uint8_t *rcheck, const unsigned char *a, const unsigned char *b, ed25519_key *key)
{
    /* To verify a signature on a message M, first split the signature
       into two 32-octet halves.  Decode the first half as a point R,
       and the second half as an integer s, in the range 0 <= s < q.  If
       the decoding fails, the signature is invalid. */

    /* Check the group equation 8s B = 8 R + 8k A. */

    /*
       Uses a fast single-signature verification SB = R + H(R,A,M)A becomes
       SB - H(R,A,M)A saving decompression of R
    */
    uint8_t X0[ED25519_PUB_KEY_SIZE] = {0};
    uint8_t X1[ED25519_PUB_KEY_SIZE] = {0};
    uint8_t Y0[ED25519_PUB_KEY_SIZE] = {0};
    uint8_t Y1[ED25519_PUB_KEY_SIZE] = {0};
    uint8_t max[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    ltc_pkha_ecc_point_t ltc0;
    ltc_pkha_ecc_point_t ltc1;
    ltc_pkha_ecc_point_t pubKey;
    status_t status;

    ltc0.X = X0;
    ltc1.X = X1;
    ltc0.Y = Y0;
    ltc1.Y = Y1;
    pubKey.X = key->pointX;
    pubKey.Y = key->pointY;

    /* ltc0 = b*B */
    status = LTC_PKHA_Ed25519_PointMul(LTC_PKHA_Ed25519_BasePoint(), b, ED25519_KEY_SIZE, &ltc0,
                                       kLTC_Weierstrass /* result in W */);

    /* ltc1 = a*A */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_Ed25519ToWeierstrass(&pubKey, &ltc1);
    }
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_Ed25519_PointMul(&ltc1, a, ED25519_KEY_SIZE, &ltc1, kLTC_Weierstrass /* result in W */);
    }

    /* The equality for the negative of a point P, in affine coordinates, is -P = -(x,y) = (x, -y) */
    uint16_t szY = 32;

    /* R = b*B - a*A */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ModSub1(LTC_BASE, modbin, sizeof(modbin), ltc1.Y, szY, max, sizeof(max), ltc1.Y, &szY);
    }
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_ECC_PointAdd(LTC_BASE, &ltc0, &ltc1, modbin, r2mod, a_coefEd25519, b_coefEd25519,
                                       ED25519_KEY_SIZE, kLTC_PKHA_IntegerArith, &ltc0);
    }
    /* map to Ed25519 */
    if (status == kStatus_Success)
    {
        status = LTC_PKHA_WeierstrassToEd25519(&ltc0, &ltc0);
    }
    if (((uint32_t)ltc0.X[0]) & 0x01u)
    {
        ltc0.Y[ED25519_KEY_SIZE - 1] |= 0x80u;
    }

    XMEMCPY(rcheck, ltc0.Y, ED25519_KEY_SIZE);
    return status;
}

status_t LTC_PKHA_Ed25519_Compress(const ltc_pkha_ecc_point_t *ltcPointIn, uint8_t *p)
{
    /* compress */
    /* get sign of X per https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
     * To form the encoding of the point, copy the least
       significant bit of the x-coordinate to the most significant bit of
       the final octet
     */
    XMEMCPY(p, ltcPointIn->Y, ED25519_KEY_SIZE);
    if (((uint32_t)ltcPointIn->X[0]) & 0x01u)
    {
        p[ED25519_KEY_SIZE - 1] |= 0x80u;
    }
    return kStatus_Success;
}

#endif

#elif defined(FREESCALE_CAAM_ECC)
/* convert from mp_int to CAAM integer, as array of bytes of size sz.
 * if mp_int has less bytes than sz, add zero bytes at most significant byte positions.
 * This is when for example modulus is 32 bytes (P-256 curve)
 * and mp_int has only 31 bytes, we add leading zeroes
 * so that result array has 32 bytes, same as modulus (sz).
 */
static void caam_get_from_mp_int(uint8_t *dst, mp_int *a, int sz)
{
    int szbin;
    int offset;

    /* check how many bytes are in the mp_int */
    szbin = mp_unsigned_bin_size(a);

    /* compute offset from dst */
    offset = sz - szbin;
    if (offset < 0)
        offset = 0;
    if (offset > sz)
        offset = sz;

    /* add leading zeroes */
    if (offset)
        memset(dst, 0, offset);

    /* convert mp_int to array of bytes */
    mp_to_unsigned_bin(a, dst + offset);
}

/* ECC specs in msbyte at lowest address format for direct use by CAAM PKHA driver functions */
#if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
#define ECC192
#endif
#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
#define ECC224
#endif
#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
#define ECC256
#endif
#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
#define ECC384
#endif

/* P-256 */
#ifdef ECC256
static uint8_t caam_ecc256_modulus[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t caam_ecc256_r2modn[32] = {0x00, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
static uint8_t caam_ecc256_aCurveParam[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
static uint8_t caam_ecc256_bCurveParam[32] = {0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD,
                                             0x55, 0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53,
                                             0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};
#endif

#ifdef ECC192
static uint8_t caam_ecc192_modulus[24] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t caam_ecc192_r2modn[24] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t caam_ecc192_aCurveParam[24] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
static uint8_t caam_ecc192_bCurveParam[24] = {0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB,
                                             0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1};
#endif

#ifdef ECC224
static uint8_t caam_ecc224_modulus[28] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t caam_ecc224_r2modn[28] = {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t caam_ecc224_aCurveParam[28] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
static uint8_t caam_ecc224_bCurveParam[28] = {0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41,
                                             0x32, 0x56, 0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA,
                                             0x27, 0x0B, 0x39, 0x43, 0x23, 0x55, 0xFF, 0xB4};
#endif

#ifdef ECC384
static uint8_t caam_ecc384_modulus[48] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};
static uint8_t caam_ecc384_r2modn[48] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                                        0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x01};
static uint8_t caam_ecc384_aCurveParam[48] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc};
static uint8_t caam_ecc384_bCurveParam[48] = {0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b,
                                             0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
                                             0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d,
                                             0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef};
#endif

static int caam_get_ecc_specs(
    const uint8_t **modulus, const uint8_t **r2modn, const uint8_t **aCurveParam, const uint8_t **bCurveParam, int size)
{
    if (32 == size)
    {
        *modulus = caam_ecc256_modulus;
        *r2modn = caam_ecc256_r2modn;
        *aCurveParam = caam_ecc256_aCurveParam;
        *bCurveParam = caam_ecc256_bCurveParam;
    }
#ifdef ECC224
    else if (28 == size)
    {
        *modulus = caam_ecc224_modulus;
        *r2modn = caam_ecc224_r2modn;
        *aCurveParam = caam_ecc224_aCurveParam;
        *bCurveParam = caam_ecc224_bCurveParam;
    }
#endif
#ifdef ECC192
    else if (24 == size)
    {
        *modulus = caam_ecc192_modulus;
        *r2modn = caam_ecc192_r2modn;
        *aCurveParam = caam_ecc192_aCurveParam;
        *bCurveParam = caam_ecc192_bCurveParam;
    }
#endif
#ifdef HAVE_ECC384
    else if (48 == size)
    {
        *modulus = caam_ecc384_modulus;
        *r2modn = caam_ecc384_r2modn;
        *aCurveParam = caam_ecc384_aCurveParam;
        *bCurveParam = caam_ecc384_bCurveParam;
    }
#endif
    else
    {
        return -1;
    }
    return 0;
}

/**
   Perform a point multiplication  (timing resistant)
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
            (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
int wc_ecc_mulmod_ex(mp_int *k, ecc_point *G, ecc_point *R, mp_int *a, mp_int *modulus, int map, void *heap)
{
    caam_pkha_ecc_point_t B;
    uint8_t size;
    int szModulus;
    int szkbin;
    status_t status;

    uint8_t Gxbin[CAAM_MAX_ECC_BITS / 8];
    uint8_t Gybin[CAAM_MAX_ECC_BITS / 8];
    uint8_t kbin[CAAM_MAX_ECC_BITS];

    const uint8_t *modbin;
    const uint8_t *aCurveParam;
    const uint8_t *bCurveParam;
    const uint8_t *r2modn;

    if (k == NULL || G == NULL || R == NULL || modulus == NULL)
        return ECC_BAD_ARG_E;

    szModulus = mp_unsigned_bin_size(modulus);
    szkbin = mp_unsigned_bin_size(k);

    caam_get_from_mp_int(kbin, k, szkbin);
    caam_get_from_mp_int(Gxbin, G->x, szModulus);
    caam_get_from_mp_int(Gybin, G->y, szModulus);

    size = szModulus;
    /* find CAAM friendly parameters for the selected curve */
    if (0 != caam_get_ecc_specs(&modbin, &r2modn, &aCurveParam, &bCurveParam, size))
    {
        return ECC_BAD_ARG_E;
    }

    B.X = &Gxbin[0];
    B.Y = &Gybin[0];

    status = CAAM_PKHA_ECC_PointMul(CAAM, &s_caamHandle, &B, kbin, szkbin, modbin, r2modn, aCurveParam, bCurveParam,
                                    size, kCAAM_PKHA_TimingEqualized, kCAAM_PKHA_IntegerArith, &B);
    if (status != kStatus_Success)
        return FP_VAL;

    mp_read_unsigned_bin(R->x, Gxbin, size);
    mp_read_unsigned_bin(R->y, Gybin, size);
    /* if k is negative, we compute the multiplication with abs(-k)
     * with result (x, y) and modify the result to (x, -y)
     */
    R->y->sign = k->sign;
    mp_set(R->z, 1);
    return MP_OKAY;
}

int wc_ecc_point_add(ecc_point *mG, ecc_point *mQ, ecc_point *mR, mp_int *m)
{
    int err;
    caam_pkha_ecc_point_t A, B;
    int size;
    status_t status;

    uint8_t Gxbin[CAAM_MAX_ECC_BITS / 8];
    uint8_t Gybin[CAAM_MAX_ECC_BITS / 8];
    uint8_t Qxbin[CAAM_MAX_ECC_BITS / 8];
    uint8_t Qybin[CAAM_MAX_ECC_BITS / 8];
    const uint8_t *modbin;
    const uint8_t *aCurveParam;
    const uint8_t *bCurveParam;
    const uint8_t *r2modn;

    size = mp_unsigned_bin_size(m);
    /* find CAAM friendly parameters for the selected curve */
    if (0 != caam_get_ecc_specs(&modbin, &r2modn, &aCurveParam, &bCurveParam, size))
    {
        err = ECC_BAD_ARG_E;
    }
    else
    {
        caam_get_from_mp_int(Gxbin, mG->x, size);
        caam_get_from_mp_int(Gybin, mG->y, size);
        caam_get_from_mp_int(Qxbin, mQ->x, size);
        caam_get_from_mp_int(Qybin, mQ->y, size);

        A.X = Gxbin;
        A.Y = Gybin;

        B.X = Qxbin;
        B.Y = Qybin;

        status = CAAM_PKHA_ECC_PointAdd(CAAM, &s_caamHandle, &A, &B, modbin, r2modn, aCurveParam, bCurveParam, size,
                                        kCAAM_PKHA_IntegerArith, &A);
        if (status != kStatus_Success)
        {
            err = FP_VAL;
        }
        else
        {
            mp_read_unsigned_bin(mR->x, Gxbin, size);
            mp_read_unsigned_bin(mR->y, Gybin, size);
            mp_set(mR->z, 1);
            err = MP_OKAY;
        }
    }
    return err;
}

#elif defined(FREESCALE_CAU3_ECC)

/* convert from mp_int to CAU3 integer, as array of bytes of size sz.
 * if mp_int has less bytes than sz, add zero bytes at most significant byte positions.
 * This is when for example modulus is 32 bytes (P-256 curve)
 * and mp_int has only 31 bytes, we add leading zeroes
 * so that result array has 32 bytes, same as modulus (sz).
 */
static void cau3_get_from_mp_int(uint8_t *dst, mp_int *a, int sz)
{
    int szbin;
    int offset;

    /* check how many bytes are in the mp_int */
    szbin = mp_unsigned_bin_size(a);

    /* compute offset from dst */
    offset = sz - szbin;
    if (offset < 0)
        offset = 0;
    if (offset > sz)
        offset = sz;

    /* add leading zeroes */
    if (offset)
        memset(dst, 0, offset);

    /* convert mp_int to array of bytes */
    mp_to_unsigned_bin(a, dst + offset);

    /* reverse array for cau3 direct use */
    cau3_reverse_array(dst, sz);
}

/* ECC specs in lsbyte at lowest address format for direct use by CAU3 PKHA driver functions */
#if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
#define ECC192
#endif
#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
#define ECC224
#endif
#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
#define ECC256
#endif
#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
#define ECC384
#endif

/* P-256 */
#ifdef ECC256
const uint8_t cau3_ecc256_modulus[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t cau3_ecc256_r2modn[32] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFB, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00};
const uint8_t cau3_ecc256_aCurveParam[32] = {0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t cau3_ecc256_bCurveParam[32] = {0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B, 0xF6, 0xB0, 0x53,
                                            0xCC, 0xB0, 0x06, 0x1D, 0x65, 0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD,
                                            0xEB, 0xB3, 0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A};
#endif

#ifdef ECC192
const uint8_t cau3_ecc192_modulus[24] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t cau3_ecc192_r2modn[24] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t cau3_ecc192_aCurveParam[24] = {0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t cau3_ecc192_bCurveParam[24] = {0xB1, 0xB9, 0x46, 0xC1, 0xEC, 0xDE, 0xB8, 0xFE, 0x49, 0x30, 0x24, 0x72,
                                            0xAB, 0xE9, 0xA7, 0x0F, 0xE7, 0x80, 0x9C, 0xE5, 0x19, 0x05, 0x21, 0x64};
#endif

#ifdef ECC224
const uint8_t cau3_ecc224_modulus[28] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t cau3_ecc224_r2modn[28] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
const uint8_t cau3_ecc224_aCurveParam[28] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t cau3_ecc224_bCurveParam[28] = {0xB4, 0xFF, 0x55, 0x23, 0x43, 0x39, 0x0B, 0x27, 0xBA, 0xD8,
                                            0xBF, 0xD7, 0xB7, 0xB0, 0x44, 0x50, 0x56, 0x32, 0x41, 0xF5,
                                            0xAB, 0xB3, 0x04, 0x0C, 0x85, 0x0A, 0x05, 0xB4};
#endif

#ifdef ECC384
const uint8_t cau3_ecc384_modulus[48] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t cau3_ecc384_r2modn[48] = {0x01, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                       0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
                                       0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t cau3_ecc384_aCurveParam[48] = {0xfc, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t cau3_ecc384_bCurveParam[48] = {0xef, 0x2a, 0xec, 0xd3, 0xed, 0xc8, 0x85, 0x2a, 0x9d, 0xd1, 0x2e, 0x8a,
                                            0x8d, 0x39, 0x56, 0xc6, 0x5a, 0x87, 0x13, 0x50, 0x8f, 0x08, 0x14, 0x03,
                                            0x12, 0x41, 0x81, 0xfe, 0x6e, 0x9c, 0x1d, 0x18, 0x19, 0x2d, 0xf8, 0xe3,
                                            0x6b, 0x05, 0x8e, 0x98, 0xe4, 0xe7, 0x3e, 0xe2, 0xa7, 0x2f, 0x31, 0xb3};
#endif

static int cau3_get_ecc_specs(
    const uint8_t **modulus, const uint8_t **r2modn, const uint8_t **aCurveParam, const uint8_t **bCurveParam, int size)
{
    if (32 == size)
    {
        *modulus = cau3_ecc256_modulus;
        *r2modn = cau3_ecc256_r2modn;
        *aCurveParam = cau3_ecc256_aCurveParam;
        *bCurveParam = cau3_ecc256_bCurveParam;
    }
#ifdef ECC224
    else if (28 == size)
    {
        *modulus = cau3_ecc224_modulus;
        *r2modn = cau3_ecc224_r2modn;
        *aCurveParam = cau3_ecc224_aCurveParam;
        *bCurveParam = cau3_ecc224_bCurveParam;
    }
#endif
#ifdef ECC192
    else if (24 == size)
    {
        *modulus = cau3_ecc192_modulus;
        *r2modn = cau3_ecc192_r2modn;
        *aCurveParam = cau3_ecc192_aCurveParam;
        *bCurveParam = cau3_ecc192_bCurveParam;
    }
#endif
#ifdef HAVE_ECC384
    else if (48 == size)
    {
        *modulus = cau3_ecc384_modulus;
        *r2modn = cau3_ecc384_r2modn;
        *aCurveParam = cau3_ecc384_aCurveParam;
        *bCurveParam = cau3_ecc384_bCurveParam;
    }
#endif
    else
    {
        return -1;
    }
    return 0;
}

/**
   Perform a point multiplication  (timing resistant)
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
            (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
int wc_ecc_mulmod_ex(mp_int *k, ecc_point *G, ecc_point *R, mp_int *a, mp_int *modulus, int map, void *heap)
{
    cau3_pkha_ecc_point_t B;
    uint8_t size;
    int szModulus;
    int szkbin;
    status_t status;
    int err;

    /* Allocate 2 elements with size of (CAU3_MAX_ECC_BITS / 8) plus kbin with size of CAU3_MAX_INT_BYTES */
    uint8_t *Gxbin = (uint8_t *)XMALLOC((2 * (CAU3_MAX_ECC_BITS / 8)) + CAU3_MAX_INT_BYTES, 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *Gybin = Gxbin + (CAU3_MAX_ECC_BITS / 8);
    uint8_t *kbin = Gybin + (CAU3_MAX_ECC_BITS / 8);

    if (k == NULL || G == NULL || R == NULL || modulus == NULL)
        return ECC_BAD_ARG_E;

    if (Gxbin)
    {
        const uint8_t *modbin;
        const uint8_t *aCurveParam;
        const uint8_t *bCurveParam;
        const uint8_t *r2modn;

        szModulus = mp_unsigned_bin_size(modulus);
        szkbin = mp_unsigned_bin_size(k);

        cau3_get_from_mp_int(kbin, k, szkbin);
        cau3_get_from_mp_int(Gxbin, G->x, szModulus);
        cau3_get_from_mp_int(Gybin, G->y, szModulus);

        size = szModulus;
        /* find CAU3 friendly parameters for the selected curve */
        if (0 != cau3_get_ecc_specs(&modbin, &r2modn, &aCurveParam, &bCurveParam, size))
        {
            err =  ECC_BAD_ARG_E;
        }
        else
        {
            B.X = &Gxbin[0];
            B.Y = &Gybin[0];

            status = CAU3_PKHA_ECC_PointMul(CAU3, &B, kbin, szkbin, modbin, r2modn, aCurveParam, bCurveParam, size,
                                            kCAU3_PKHA_TimingEqualized, kCAU3_PKHA_IntegerArith, &B);
            if (status != kStatus_Success)
            {
                err = FP_VAL;
            }
            else
            {
                cau3_reverse_array(Gxbin, size);
                cau3_reverse_array(Gybin, size);
                mp_read_unsigned_bin(R->x, Gxbin, size);
                mp_read_unsigned_bin(R->y, Gybin, size);
                /* if k is negative, we compute the multiplication with abs(-k)
                 * with result (x, y) and modify the result to (x, -y)
                 */
                R->y->sign = k->sign;
                mp_set(R->z, 1);
                err = MP_OKAY;
            }
        }
    }
    else
    {
        return FP_MEM;
    }

    if (Gxbin)
    {
        XFREE(Gxbin, 0, DYNAMIC_TYPE_BIGINT);
    }

    return err;
}

int wc_ecc_point_add(ecc_point *mG, ecc_point *mQ, ecc_point *mR, mp_int *m)
{
    int err;
    cau3_pkha_ecc_point_t A, B;
    int size;
    status_t status;

    uint8_t *Gxbin = (uint8_t *)XMALLOC(4 * (CAU3_MAX_ECC_BITS / 8), 0, DYNAMIC_TYPE_BIGINT);
    uint8_t *Gybin = Gxbin + (CAU3_MAX_ECC_BITS / 8);
    uint8_t *Qxbin = Gybin + (CAU3_MAX_ECC_BITS / 8);
    uint8_t *Qybin = Qxbin + (CAU3_MAX_ECC_BITS / 8);

    if (Gxbin)
    {
        const uint8_t *modbin;
        const uint8_t *aCurveParam;
        const uint8_t *bCurveParam;
        const uint8_t *r2modn;

        size = mp_unsigned_bin_size(m);
        /* find CAU3 friendly parameters for the selected curve */
        if (0 != cau3_get_ecc_specs(&modbin, &r2modn, &aCurveParam, &bCurveParam, size))
        {
            err = ECC_BAD_ARG_E;
        }
        else
        {
            cau3_get_from_mp_int(Gxbin, mG->x, size);
            cau3_get_from_mp_int(Gybin, mG->y, size);
            cau3_get_from_mp_int(Qxbin, mQ->x, size);
            cau3_get_from_mp_int(Qybin, mQ->y, size);

            A.X = Gxbin;
            A.Y = Gybin;

            B.X = Qxbin;
            B.Y = Qybin;

            status = CAU3_PKHA_ECC_PointAdd(CAU3, &A, &B, modbin, r2modn, aCurveParam, bCurveParam, size,
                                            kCAU3_PKHA_IntegerArith, &A);
            if (status != kStatus_Success)
            {
                err = FP_VAL;
            }
            else
            {
                cau3_reverse_array(Gxbin, size);
                cau3_reverse_array(Gybin, size);
                mp_read_unsigned_bin(mR->x, Gxbin, size);
                mp_read_unsigned_bin(mR->y, Gybin, size);
                mp_set(mR->z, 1);
                err = MP_OKAY;
            }
        }
    }
    else
    {
        err = FP_MEM;
    }

    if (Gxbin)
    {
        XFREE(Gxbin, 0, DYNAMIC_TYPE_BIGINT);
    }

    return err;
}

#endif /* FREESCALE_LTC_ECC */

/******************************************************************************/
/***************************** RANDOM *****************************************/
/******************************************************************************/
#if defined(FREESCALE_CAAM)
int wc_GenerateSeed(OS_Seed *os, byte *output, word32 sz)
{
    status_t status;
    status = CAAM_RNG_GetRandomData(CAAM, &s_caamHandle, kCAAM_RngStateHandle0, output, sz, kCAAM_RngDataAny, NULL);
    if (status == kStatus_Success)
    {
        return (0);
    }
    else
    {
        return RAN_BLOCK_E;
    }
}
#endif /* FREESCALE_CAAM */
