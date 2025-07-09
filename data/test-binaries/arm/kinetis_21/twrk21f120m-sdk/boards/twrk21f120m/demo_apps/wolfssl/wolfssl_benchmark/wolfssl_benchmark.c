/* benchmark.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */

/* wolfCrypt benchmark */

#include "nxp/ksdk_port.h"
#include "fsl_device_registers.h"
#include "board.h"

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/* Macro to disable benchmark */
#ifndef NO_CRYPT_BENCHMARK

#include <string.h>

#ifdef FREESCALE_MQX
    #include <mqx.h>
    #if MQX_USE_IO_OLD
        #include <fio.h>
    #else
        #include <nio.h>
    #endif
#else
    #include <stdio.h>
#endif

#ifdef FREESCALE_KSDK_BM
#include "fsl_debug_console.h"
#define bench_printf PRINTF
#else
#define bench_printf printf
#endif

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/hc128.h>
#include <wolfssl/wolfcrypt/rabbit.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/cmac.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_IDEA
    #include <wolfssl/wolfcrypt/idea.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

#include <wolfssl/wolfcrypt/dh.h>
#ifdef HAVE_CAVIUM
    #include "cavium_sysdep.h"
    #include "cavium_common.h"
    #include "cavium_ioctl.h"
#endif
#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
#endif
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_WNR
    const char* wnrConfigFile = "wnr-example.conf";
#endif

#if defined(WOLFSSL_MDK_ARM)
    extern FILE * wolfSSL_fopen(const char *fname, const char *mode) ;
    #define fopen wolfSSL_fopen
#endif

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM)
    #define HAVE_GET_CYCLES
    static INLINE word64 get_intel_cycles(void);
    static word64 total_cycles;
    #define BEGIN_INTEL_CYCLES total_cycles = get_intel_cycles();
    #define END_INTEL_CYCLES   total_cycles = get_intel_cycles() - total_cycles;
    #define SHOW_INTEL_CYCLES  bench_printf(" Cycles per byte = %6.2f", \
                               (float)total_cycles / (numBlocks*sizeof(plain)));
#else
    #define BEGIN_INTEL_CYCLES
    #define END_INTEL_CYCLES
    #define SHOW_INTEL_CYCLES
#endif

/* let's use buffers, we have them */
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
    #define USE_CERT_BUFFERS_2048
#endif

#if defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048) || defined(USE_CERT_BUFFERS_4096) \
                                   || !defined(NO_DH)
    /* include test cert and key buffers for use with NO_FILESYSTEM */
        #include <wolfssl/certs_test.h>
#endif


#ifdef HAVE_BLAKE2
    #include <wolfssl/wolfcrypt/blake2.h>
    void bench_blake2(void);
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif

#ifdef USE_WOLFSSL_MEMORY
    #include "wolfssl/wolfcrypt/mem_track.h"
#endif

#include "fsl_common.h"
#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define CORE_CLK_FREQ CLOCK_GetFreq(kCLOCK_CoreSysClk)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void bench_des(void);
void bench_idea(void);
void bench_arc4(void);
void bench_hc128(void);
void bench_rabbit(void);
void bench_chacha(void);
void bench_chacha20_poly1305_aead(void);
void bench_aes(int);
void bench_aesgcm(void);
void bench_aesccm(void);
void bench_aesctr(void);
void bench_poly1305(void);
void bench_camellia(void);

void bench_md5(void);
void bench_sha(void);
void bench_sha256(void);
void bench_sha384(void);
void bench_sha512(void);
void bench_ripemd(void);
void bench_cmac(void);

void bench_rsa(void);
void bench_rsaKeyGen(void);
void bench_dh(void);
#ifdef HAVE_ECC
void bench_eccKeyGen(void);
void bench_eccKeyAgree(void);
    #ifdef HAVE_ECC_ENCRYPT
    void bench_eccEncrypt(void);
    #endif
#endif
#ifdef HAVE_CURVE25519
    void bench_curve25519KeyGen(void);
    #ifdef HAVE_CURVE25519_SHARED_SECRET
        void bench_curve25519KeyAgree(void);
    #endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
void bench_ed25519KeyGen(void);
void bench_ed25519KeySign(void);
#endif
#ifdef HAVE_NTRU
void bench_ntru(void);
void bench_ntruKeyGen(void);
#endif
void bench_rng(void);

float current_time(int);

/*******************************************************************************
 * Code
 ******************************************************************************/
#ifdef HAVE_CAVIUM

static int OpenNitroxDevice(int dma_mode,int dev_id)
{
   Csp1CoreAssignment core_assign;
   Uint32             device;

   if (CspInitialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
      return -1;
   if (Csp1GetDevType(&device))
      return -1;
   if (device != NPX_DEVICE) {
      if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
                (Uint32 *)&core_assign)!= 0)
         return -1;
   }
   CspShutdown(CAVIUM_DEV_ID);

   return CspInitialize(dma_mode, dev_id);
}

#endif

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    WOLFSSL_API int wolfSSL_Debugging_ON();
#endif

#if !defined(NO_RSA) || !defined(NO_DH) \
                        || defined(WOLFSSL_KEYGEN) || defined(HAVE_ECC) \
                        || defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
    #define HAVE_LOCAL_RNG
    static WC_RNG rng;
#endif

/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    static byte plain [1024];
#else
    static byte plain [1024*1024];
#endif


/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    static byte cipher[1024];
#else
    static byte cipher[1024*1024];
#endif


static const XGEN_ALIGN byte key[] =
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
};

static const XGEN_ALIGN byte iv[] =
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
};

static int bench_print_features(void)
{
    char *text;
    bench_printf("fsys=%lu\r\n", ((CORE_CLK_FREQ)));
    bench_printf("Using following implementations:\r\n");
#if defined(FREESCALE_LTC_SHA)
    text = "LTC HW accelerated";
#elif defined(FREESCALE_MMCAU_SHA)
    text = "MMCAU HW accelerated";
#elif defined(FREESCALE_LPC_SHA)
    text = "LPC HW accelerated";
#elif defined(FREESCALE_CAAM_SHA)
    text = "CAAM HW accelerated";
#elif defined(FREESCALE_CAU3_SHA)
    text = "CAU3 HW accelerated";
#elif defined(FREESCALE_DCP_SHA)
    text = "DCP HW accelerated";
#else
    text = "Software implementation";
#endif
    bench_printf("  SHA: %s\r\n", text);
#if defined(FREESCALE_LTC)
    text = "LTC HW accelerated";
#elif defined(FREESCALE_MMCAU)
    text = "MMCAU HW accelerated";
#elif defined(FREESCALE_LPC_AES)
    text = "LPC HW accelerated";
#elif defined(FREESCALE_CAAM_AES)
    text = "CAAM HW accelerated";
#elif defined(FREESCALE_CAU3_AES)
    text = "CAU3 HW accelerated";
#elif defined(FREESCALE_DCP_AES)
    text = "CAU3 HW accelerated";
#else
    text = "Software implementation";
#endif
    bench_printf("  AES: %s\r\n", text);
#if defined(FREESCALE_LTC_AES_GCM)
    text = "LTC HW accelerated";
#elif defined(FREESCALE_MMCAU)
    text = "MMCAU HW accelerated";
#elif defined(FREESCALE_LPC_AES_GCM)
    text = "LPC HW accelerated";
#elif defined(FREESCALE_CAAM_AES_GCM)
    text = "CAAM HW accelerated";
#elif defined(FREESCALE_CAU3_AES)
    text = "CAU3 HW accelerated";
#else
    text = "Software implementation";
#endif
    bench_printf("  AES GCM: %s\r\n", text);
#if defined(FREESCALE_LTC_DES)
    text = "LTC HW accelerated";
#elif defined(FREESCALE_MMCAU)
    text = "MMCAU HW accelerated";
#elif defined(FREESCALE_CAAM_DES)
    text = "CAAM HW accelerated";
#elif defined(FREESCALE_CAU3_DES3)
    text = "CAU3 HW accelerated";
#else
    text = "Software implementation";
#endif
    bench_printf("  DES: %s\r\n", text);
#if defined(FREESCALE_LTC_TFM)
    text = "LTC HW accelerated";
#elif defined(FREESCALE_CAAM_TFM)
    text = "CAAM HW accelerated";
#elif defined(FREESCALE_CAU3_TFM)
    text = "CAU3 HW accelerated";
#else
    text = "Software implementation";
#endif
    bench_printf("  Asymmetric encryption: %s\r\n\n", text);
    return 0;
}

/* so embedded projects can pull in tests on their own */
#if !defined(NO_MAIN_DRIVER)

int main(int argc, char** argv)

{
    (void)argc;
    (void)argv;
#else
int benchmark_test(void *args)
{
#endif
    int retval;
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    CRYPTO_InitHardware();

#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    InitMemoryTracker();
#endif

    wolfCrypt_Init();

    retval = bench_print_features();

    #if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
        wolfSSL_Debugging_ON();
    #endif

    (void)plain;
    (void)cipher;
    (void)key;
    (void)iv;

	#ifdef HAVE_CAVIUM
    int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
    if (ret != 0) {
        bench_printf("Cavium OpenNitroxDevice failed\r\n");
        exit(-1);
    }
    #endif /* HAVE_CAVIUM */

    #ifdef HAVE_WNR
    if (wc_InitNetRandom(wnrConfigFile, NULL, 5000) != 0) {
        bench_printf("Whitewood netRandom config init failed\r\n");
        exit(-1);
    }
    #endif /* HAVE_WNR */

#if defined(HAVE_LOCAL_RNG)
    {
        int rngRet = wc_InitRng(&rng);
        if (rngRet < 0) {
            bench_printf("InitRNG failed\r\n");
            return rngRet;
        }
    }
#endif

    bench_rng();
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    bench_aes(0);
    bench_aes(1);
#endif
#ifdef HAVE_AESGCM
    bench_aesgcm();
#endif
#ifdef WOLFSSL_AES_COUNTER
    bench_aesctr();
#endif
#ifdef HAVE_AESCCM
    bench_aesccm();
#endif
#endif /* !NO_AES */

#ifdef HAVE_CAMELLIA
    bench_camellia();
#endif
#ifndef NO_RC4
    bench_arc4();
#endif
#ifdef HAVE_HC128
    bench_hc128();
#endif
#ifndef NO_RABBIT
    bench_rabbit();
#endif
#ifdef HAVE_CHACHA
    bench_chacha();
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    bench_chacha20_poly1305_aead();
#endif
#ifndef NO_DES3
    bench_des();
#endif
#ifdef HAVE_IDEA
    bench_idea();
#endif

    bench_printf("\r\n");

#ifndef NO_MD5
    bench_md5();
#endif
#ifdef HAVE_POLY1305
    bench_poly1305();
#endif
#ifndef NO_SHA
    bench_sha();
#endif
#ifndef NO_SHA256
    bench_sha256();
#endif
#ifdef WOLFSSL_SHA384
    bench_sha384();
#endif
#ifdef WOLFSSL_SHA512
    bench_sha512();
#endif
#ifdef WOLFSSL_RIPEMD
    bench_ripemd();
#endif
#ifdef HAVE_BLAKE2
    bench_blake2();
#endif
#ifdef WOLFSSL_CMAC
    bench_cmac();
#endif

    bench_printf("\r\n");

#ifndef NO_RSA
    bench_rsa();
#endif

#ifndef NO_DH
    bench_dh();
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
    bench_rsaKeyGen();
#endif

#ifdef HAVE_NTRU
    bench_ntru();
    bench_ntruKeyGen();
#endif

#ifdef HAVE_ECC
    bench_eccKeyGen();
    bench_eccKeyAgree();
    #ifdef HAVE_ECC_ENCRYPT
        bench_eccEncrypt();
    #endif
    #if defined(FP_ECC)
        wc_ecc_fp_free();
    #endif
#endif

#ifdef HAVE_CURVE25519
    bench_curve25519KeyGen();
    #ifdef HAVE_CURVE25519_SHARED_SECRET
        bench_curve25519KeyAgree();
    #endif
#endif

#ifdef HAVE_ED25519
    bench_ed25519KeyGen();
    bench_ed25519KeySign();
#endif

#if defined(HAVE_LOCAL_RNG)
    wc_FreeRng(&rng);
#endif

#ifdef HAVE_WNR
    if (wc_FreeNetRandom() < 0) {
        bench_printf("Failed to free netRandom context\r\n");
        exit(-1);
    }
#endif

#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    ShowMemoryTracker();
#endif
    if (0 == retval)
    {
        while (1)
        {
        }
    }
    return 0;
}


#ifdef BENCH_EMBEDDED
enum BenchmarkBounds {
    numBlocks  = 25, /* how many kB to test (en/de)cryption */
    ntimes     = 1,
    genTimes   = 5,  /* public key iterations */
    agreeTimes = 5
};
static const char blockType[] = "kB";   /* used in bench_printf output */
#else
enum BenchmarkBounds {
    numBlocks  = 50,  /* how many megs to test (en/de)cryption */
    ntimes     = 100,
    genTimes   = 100,
    agreeTimes = 100
};
static const char blockType[] = "megs"; /* used in bench_printf output */
#endif

void bench_rng(void)
{
    int    ret, i;
    float start, total, persec;
    int pos, len, remain;
#ifndef HAVE_LOCAL_RNG
    WC_RNG rng;
#endif

#ifndef HAVE_LOCAL_RNG
    ret = wc_InitRng(&rng);
    if (ret < 0) {
        bench_printf("InitRNG failed\r\n");
        return;
    }
#endif

    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        /* Split request to handle large RNG request */
        pos = 0;
        remain = (int)sizeof(plain);
        while (remain > 0) {
            len = remain;
            if (len > RNG_MAX_BLOCK_LEN)
                len = RNG_MAX_BLOCK_LEN;
            ret = wc_RNG_GenerateBlock(&rng, &plain[pos], len);
            if (ret < 0) {
                bench_printf("wc_RNG_GenerateBlock failed %d\r\n", ret);
                break;
            }
            remain -= len;
            pos += len;
        }
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif
    bench_printf("RNG      %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");

#ifndef HAVE_LOCAL_RNG
    wc_FreeRng(&rng);
#endif
}


#ifndef NO_AES

#ifdef HAVE_AES_CBC
void bench_aes(int show)
{
    Aes    enc;
    float start, total, persec;
    int    i;
    int    ret;

#ifdef HAVE_CAVIUM
    if (wc_AesInitCavium(&enc, CAVIUM_DEV_ID) != 0) {
        bench_printf("aes init cavium failed\r\n");
        return;
    }
#endif

    ret = wc_AesSetKey(&enc, key, 16, iv, AES_ENCRYPTION);
    if (ret != 0) {
        bench_printf("AesSetKey failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCbcEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    if (show) {
        bench_printf("AES enc  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
        SHOW_INTEL_CYCLES
        bench_printf("\r\n");
    }
#ifdef HAVE_CAVIUM
    wc_AesFreeCavium(&enc);
    if (wc_AesInitCavium(&enc, CAVIUM_DEV_ID) != 0) {
        bench_printf("aes init cavium failed\r\n");
        return;
    }
#endif

    ret = wc_AesSetKey(&enc, key, 16, iv, AES_DECRYPTION);
    if (ret != 0) {
        bench_printf("AesSetKey failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCbcDecrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    if (show) {
        bench_printf("AES dec  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
        SHOW_INTEL_CYCLES
        bench_printf("\r\n");
    }
#ifdef HAVE_CAVIUM
    wc_AesFreeCavium(&enc);
#endif
}
#endif /* HAVE_AES_CBC */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    static byte additional[13];
    static byte tag[16];
#endif


#ifdef HAVE_AESGCM
void bench_aesgcm(void)
{
    Aes    enc;
    float start, total, persec;
    int    i;

    wc_AesGcmSetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                        tag, 16, additional, 13);

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("AES-GCM  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");

#if 0
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesGcmDecrypt(&enc, plain, cipher, sizeof(cipher), iv, 12,
                        tag, 16, additional, 13);

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("AES-GCM Decrypt %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
#endif
}
#endif /* HAVE_AESGCM */


#ifdef WOLFSSL_AES_COUNTER
void bench_aesctr(void)
{
    Aes    enc;
    float start, total, persec;
    int    i;

    wc_AesSetKeyDirect(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCtrEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("AES-CTR  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* WOLFSSL_AES_COUNTER */


#ifdef HAVE_AESCCM
void bench_aesccm(void)
{
    Aes    enc;
    float start, total, persec;
    int    i;

    wc_AesCcmSetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                        tag, 16, additional, 13);

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("AES-CCM  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */


#ifdef HAVE_POLY1305
void bench_poly1305()
{
    Poly1305    enc;
    byte   mac[16];
    float start, total, persec;
    int    i;
    int    ret;


    ret = wc_Poly1305SetKey(&enc, key, 32);
    if (ret != 0) {
        bench_printf("Poly1305SetKey failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Poly1305Update(&enc, plain, sizeof(plain));

    wc_Poly1305Final(&enc, mac);
    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("POLY1305 %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* HAVE_POLY1305 */


#ifdef HAVE_CAMELLIA
void bench_camellia(void)
{
    Camellia cam;
    float start, total, persec;
    int    i, ret;

    ret = wc_CamelliaSetKey(&cam, key, 16, iv);
    if (ret != 0) {
        bench_printf("CamelliaSetKey failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_CamelliaCbcEncrypt(&cam, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("Camellia %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif


#ifndef NO_DES3
void bench_des(void)
{
    Des3   enc;
    float start, total, persec;
    int    i, ret;

#ifdef HAVE_CAVIUM
    if (wc_Des3_InitCavium(&enc, CAVIUM_DEV_ID) != 0)
        bench_printf("des3 init cavium failed\r\n");
#endif
    ret = wc_Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
        bench_printf("Des3_SetKey failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Des3_CbcEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("3DES     %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
#ifdef HAVE_CAVIUM
    wc_Des3_FreeCavium(&enc);
#endif
}
#endif


#ifdef HAVE_IDEA
void bench_idea(void)
{
    Idea   enc;
    float start, total, persec;
    int    i, ret;

    ret = wc_IdeaSetKey(&enc, key, IDEA_KEY_SIZE, iv, IDEA_ENCRYPTION);
    if (ret != 0) {
        bench_printf("Des3_SetKey failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_IdeaCbcEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("IDEA     %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* HAVE_IDEA */


#ifndef NO_RC4
void bench_arc4(void)
{
    Arc4   enc;
    float start, total, persec;
    int    i;

#ifdef HAVE_CAVIUM
    if (wc_Arc4InitCavium(&enc, CAVIUM_DEV_ID) != 0)
        bench_printf("arc4 init cavium failed\r\n");
#endif

    wc_Arc4SetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Arc4Process(&enc, cipher, plain, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("ARC4     %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
#ifdef HAVE_CAVIUM
    wc_Arc4FreeCavium(&enc);
#endif
}
#endif


#ifdef HAVE_HC128
void bench_hc128(void)
{
    HC128  enc;
    float start, total, persec;
    int    i;

    wc_Hc128_SetKey(&enc, key, iv);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Hc128_Process(&enc, cipher, plain, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("HC128    %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* HAVE_HC128 */


#ifndef NO_RABBIT
void bench_rabbit(void)
{
    Rabbit  enc;
    float start, total, persec;
    int    i;

    wc_RabbitSetKey(&enc, key, iv);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_RabbitProcess(&enc, cipher, plain, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("RABBIT   %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* NO_RABBIT */


#ifdef HAVE_CHACHA
void bench_chacha(void)
{
    ChaCha enc;
    float start, total, persec;
    int    i;

    wc_Chacha_SetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for (i = 0; i < numBlocks; i++) {
        wc_Chacha_SetIV(&enc, iv, 0);
        wc_Chacha_Process(&enc, cipher, plain, sizeof(plain));
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("CHACHA   %d %s took %5.3f seconds, %8.3f MB/s", numBlocks, blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");

}
#endif /* HAVE_CHACHA*/

#if( defined( HAVE_CHACHA ) && defined( HAVE_POLY1305 ) )
void bench_chacha20_poly1305_aead(void)
{
    float start, total, persec;
    int    i;

    byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    XMEMSET( authTag, 0, sizeof( authTag ) );

    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for (i = 0; i < numBlocks; i++)
    {
        wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, plain, sizeof(plain),
                                    cipher, authTag );
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("CHA-POLY %d %s took %5.3f seconds, %8.3f MB/s",
           numBlocks, blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");

}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */


#ifndef NO_MD5
void bench_md5(void)
{
    Md5    hash;
    byte   digest[MD5_DIGEST_SIZE];
    float start, total, persec;
    int    i;

    wc_InitMd5(&hash);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Md5Update(&hash, plain, sizeof(plain));

    wc_Md5Final(&hash, digest);

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("MD5      %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* NO_MD5 */


#ifndef NO_SHA
void bench_sha(void)
{
    Sha    hash;
    byte   digest[SHA_DIGEST_SIZE];
    float start, total, persec;
    int    i, ret;

    ret = wc_InitSha(&hash);
    if (ret != 0) {
        bench_printf("InitSha failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_ShaUpdate(&hash, plain, sizeof(plain));

    wc_ShaFinal(&hash, digest);

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("SHA      %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif /* NO_SHA */


#ifndef NO_SHA256
void bench_sha256(void)
{
    Sha256 hash;
    byte   digest[SHA256_DIGEST_SIZE];
    float start, total, persec;
    int    i, ret;

    ret = wc_InitSha256(&hash);
    if (ret != 0) {
        bench_printf("InitSha256 failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha256Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            bench_printf("Sha256Update failed, ret = %d\r\n", ret);
            return;
        }
    }

    ret = wc_Sha256Final(&hash, digest);
    if (ret != 0) {
        bench_printf("Sha256Final failed, ret = %d\r\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("SHA-256  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif

#ifdef WOLFSSL_SHA384
void bench_sha384(void)
{
    Sha384 hash;
    byte   digest[SHA384_DIGEST_SIZE];
    float start, total, persec;
    int    i, ret;

    ret = wc_InitSha384(&hash);
    if (ret != 0) {
        bench_printf("InitSha384 failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha384Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            bench_printf("Sha384Update failed, ret = %d\r\n", ret);
            return;
        }
    }

    ret = wc_Sha384Final(&hash, digest);
    if (ret != 0) {
        bench_printf("Sha384Final failed, ret = %d\r\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("SHA-384  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif

#ifdef WOLFSSL_SHA512
void bench_sha512(void)
{
    Sha512 hash;
    byte   digest[SHA512_DIGEST_SIZE];
    float start, total, persec;
    int    i, ret;

    ret = wc_InitSha512(&hash);
    if (ret != 0) {
        bench_printf("InitSha512 failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha512Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            bench_printf("Sha512Update failed, ret = %d\r\n", ret);
            return;
        }
    }

    ret = wc_Sha512Final(&hash, digest);
    if (ret != 0) {
        bench_printf("Sha512Final failed, ret = %d\r\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("SHA-512  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif

#ifdef WOLFSSL_RIPEMD
void bench_ripemd(void)
{
    RipeMd hash;
    byte   digest[RIPEMD_DIGEST_SIZE];
    float start, total, persec;
    int    i;

    wc_InitRipeMd(&hash);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_RipeMdUpdate(&hash, plain, sizeof(plain));

    wc_RipeMdFinal(&hash, digest);

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("RIPEMD   %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif


#ifdef HAVE_BLAKE2
void bench_blake2(void)
{
    Blake2b b2b;
    byte    digest[64];
    float  start, total, persec;
    int     i, ret;

    ret = wc_InitBlake2b(&b2b, 64);
    if (ret != 0) {
        bench_printf("InitBlake2b failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
        if (ret != 0) {
            bench_printf("Blake2bUpdate failed, ret = %d\r\n", ret);
            return;
        }
    }

    ret = wc_Blake2bFinal(&b2b, digest, 64);
    if (ret != 0) {
        bench_printf("Blake2bFinal failed, ret = %d\r\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("BLAKE2b  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}
#endif


#ifdef WOLFSSL_CMAC

void bench_cmac(void)
{
    Cmac    cmac;
    byte    digest[AES_BLOCK_SIZE];
    word32  digestSz = sizeof(digest);
    float  start, total, persec;
    int     i, ret;

    ret = wc_InitCmac(&cmac, key, 16, WC_CMAC_AES, NULL);
    if (ret != 0) {
        bench_printf("InitCmac failed, ret = %d\r\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_CmacUpdate(&cmac, plain, sizeof(plain));
        if (ret != 0) {
            bench_printf("CmacUpdate failed, ret = %d\r\n", ret);
            return;
        }
    }

    ret = wc_CmacFinal(&cmac, digest, &digestSz);
    if (ret != 0) {
        bench_printf("CmacFinal failed, ret = %d\r\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    bench_printf("AES-CMAC %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    bench_printf("\r\n");
}

#endif /* WOLFSSL_CMAC */


#ifndef NO_RSA


#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
    #if defined(WOLFSSL_MDK_SHELL)
        static char *certRSAname = "certs/rsa2048.der";
        /* set by shell command */
        static void set_Bench_RSA_File(char * cert) { certRSAname = cert ; }
    #elif defined(FREESCALE_MQX)
        static char *certRSAname = "a:\\certs\\rsa2048.der";
    #else
        static const char *certRSAname = "certs/rsa2048.der";
    #endif
#endif

void bench_rsa(void)
{
    int    i;
    int    ret;
    size_t bytes;
    word32 idx = 0;
    const byte* tmp;

    byte      message[] = "Everyone gets Friday off.";
#if defined(USE_CERT_BUFFERS_4096)
    byte      enc[512];  /* for up to 4096 bit */
#else
    byte      enc[256];  /* for up to 2048 bit */
#endif
    const int len = (int)strlen((char*)message);
    float    start, total, each, milliEach;

    RsaKey rsaKey;
    int    rsaKeySz = 2048; /* used in bench_printf */

#ifdef USE_CERT_BUFFERS_1024
    tmp = rsa_key_der_1024;
    bytes = sizeof_rsa_key_der_1024;
    rsaKeySz = 1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = rsa_key_der_2048;
    bytes = sizeof_rsa_key_der_2048;
#elif defined(USE_CERT_BUFFERS_4096)
    tmp = rsa_key_der_4096;
    bytes = sizeof_rsa_key_der_4096;
    rsaKeySz = 4096;
#else
    #error "need a cert buffer size"
#endif /* USE_CERT_BUFFERS */


#ifdef HAVE_CAVIUM
    if (wc_RsaInitCavium(&rsaKey, CAVIUM_DEV_ID) != 0)
        bench_printf("RSA init cavium failed\r\n");
#endif
    ret = wc_InitRsaKey(&rsaKey, 0);
    if (ret < 0) {
        bench_printf("InitRsaKey failed\r\n");
        return;
    }
    ret = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey, (word32)bytes);

    start = current_time(1);

    for (i = 0; i < ntimes; i++)
        ret = wc_RsaPublicEncrypt(message,len,enc,sizeof(enc), &rsaKey, &rng);

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    bench_printf("RSA %d encryption took %6.3f milliseconds, avg over %d"
           " iterations\r\n", rsaKeySz, milliEach, ntimes);

    if (ret < 0) {
        bench_printf("Rsa Public Encrypt failed\r\n");
        return;
    }

#ifdef WC_RSA_BLINDING
    wc_RsaSetRNG(&rsaKey, &rng);
#endif
    start = current_time(1);

    for (i = 0; i < ntimes; i++) {
#if defined(USE_CERT_BUFFERS_4096)
         byte  out[512];  /* for up to 4096 bit */
#else
         byte  out[256];  /* for up to 2048 bit */
#endif
         wc_RsaPrivateDecrypt(enc, (word32)ret, out, sizeof(out), &rsaKey);
    }

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    bench_printf("RSA %d decryption took %6.3f milliseconds, avg over %d"
           " iterations\r\n", rsaKeySz, milliEach, ntimes);

    wc_FreeRsaKey(&rsaKey);
#ifdef HAVE_CAVIUM
    wc_RsaFreeCavium(&rsaKey);
#endif
}
#endif


#ifndef NO_DH


#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
    #if defined(WOLFSSL_MDK_SHELL)
        static char *certDHname = "certs/dh2048.der";
        /* set by shell command */
        void set_Bench_DH_File(char * cert) { certDHname = cert ; }
    #elif defined(FREESCALE_MQX)
        static char *certDHname = "a:\\certs\\dh2048.der";
    #elif defined(NO_ASN)
        /* do nothing, but don't need a file */
    #else
        static const char *certDHname = "certs/dh2048.der";
    #endif
#endif

void bench_dh(void)
{
    int    i ;
    size_t bytes;
    word32 idx = 0, pubSz, privSz = 0, pubSz2, privSz2, agreeSz;
    const byte* tmp = NULL;

    byte   pub[256];    /* for 2048 bit */
    byte   pub2[256];   /* for 2048 bit */
    byte   agree[256];  /* for 2048 bit */
    byte   priv[32];    /* for 2048 bit */
    byte   priv2[32];   /* for 2048 bit */

    float start, total, each, milliEach;
    DhKey  dhKey;
    int    dhKeySz = 2048; /* used in bench_printf */

    (void)idx;
    (void)tmp;


#if defined(NO_ASN)
    dhKeySz = 1024;
    /* do nothing, but don't use default FILE */
#elif defined(USE_CERT_BUFFERS_1024)
    tmp = dh_key_der_1024;
    bytes = sizeof_dh_key_der_1024;
    dhKeySz = 1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = dh_key_der_2048;
    bytes = sizeof_dh_key_der_2048;
#else
    #error "need to define a cert buffer size"
#endif /* USE_CERT_BUFFERS */


    wc_InitDhKey(&dhKey);
#ifdef NO_ASN
    bytes = wc_DhSetKey(&dhKey, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
#else
    bytes = wc_DhKeyDecode(tmp, &idx, &dhKey, (word32)bytes);
#endif
    if (bytes != 0) {
        bench_printf("dhekydecode failed, can't benchmark\r\n");
        return;
    }

    start = current_time(1);

    for (i = 0; i < ntimes; i++)
        wc_DhGenerateKeyPair(&dhKey, &rng, priv, &privSz, pub, &pubSz);

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    bench_printf("DH  %d key generation  %6.3f milliseconds, avg over %d"
           " iterations\r\n", dhKeySz, milliEach, ntimes);

    wc_DhGenerateKeyPair(&dhKey, &rng, priv2, &privSz2, pub2, &pubSz2);
    start = current_time(1);

    for (i = 0; i < ntimes; i++)
        wc_DhAgree(&dhKey, agree, &agreeSz, priv, privSz, pub2, pubSz2);

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    bench_printf("DH  %d key agreement   %6.3f milliseconds, avg over %d"
           " iterations\r\n", dhKeySz, milliEach, ntimes);

    wc_FreeDhKey(&dhKey);
}
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
void bench_rsaKeyGen(void)
{
    RsaKey genKey;
    float start, total, each, milliEach;
    int    i;

    /* 1024 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_InitRsaKey(&genKey, 0);
        wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
        wc_FreeRsaKey(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("\r\n");
    bench_printf("RSA 1024 key generation  %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, genTimes);

    /* 2048 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_InitRsaKey(&genKey, 0);
        wc_MakeRsaKey(&genKey, 2048, 65537, &rng);
        wc_FreeRsaKey(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("RSA 2048 key generation  %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, genTimes);
}
#endif /* WOLFSSL_KEY_GEN */
#ifdef HAVE_NTRU
byte GetEntropy(ENTROPY_CMD cmd, byte* out);

byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    if (cmd == INIT)
        return 1; /* using local rng */

    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (wc_RNG_GenerateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

void bench_ntru(void)
{
    int    i;
    float start, total, each, milliEach;

    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    word16 ntruBits = 128;
    word16 type     = 0;
    word32 ret;

    byte ciphertext[1022];
    word16 ciphertext_len;
    byte plaintext[16];
    word16 plaintext_len;

    DRBG_HANDLE drbg;
    static byte const aes_key[] = {
        0xf3, 0xe9, 0x87, 0xbb, 0x18, 0x08, 0x3c, 0xaa,
        0x7b, 0x12, 0x49, 0x88, 0xaf, 0xb3, 0x22, 0xd8
    };

    static byte const wolfsslStr[] = {
        'w', 'o', 'l', 'f', 'S', 'S', 'L', ' ', 'N', 'T', 'R', 'U'
    };

    bench_printf("\r\n");
    for (ntruBits = 128; ntruBits < 257; ntruBits += 64) {
        switch (ntruBits) {
            case 128:
                type = NTRU_EES439EP1;
                break;
            case 192:
                type = NTRU_EES593EP1;
                break;
            case 256:
                type = NTRU_EES743EP1;
                break;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, wolfsslStr,
                sizeof(wolfsslStr), (ENTROPY_FN) GetEntropy, &drbg);
        if(ret != DRBG_OK) {
            bench_printf("NTRU drbg instantiate failed\r\n");
            return;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                                  NULL, &private_key_len, NULL);
        if (ret != NTRU_OK) {
            ntru_crypto_drbg_uninstantiate(drbg);
            bench_printf("NTRU failed to get key lengths\r\n");
            return;
        }

        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                     public_key, &private_key_len,
                                     private_key);

        ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            bench_printf("NTRU keygen failed\r\n");
            return;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, NULL, 0,
                (ENTROPY_FN)GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            bench_printf("NTRU error occurred during DRBG instantiation\r\n");
            return;
        }

        ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                sizeof(aes_key), aes_key, &ciphertext_len, NULL);

        if (ret != NTRU_OK) {
            bench_printf("NTRU error occurred requesting the buffer size needed\r\n");
            return;
        }
        start = current_time(1);

        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                    sizeof(aes_key), aes_key, &ciphertext_len, ciphertext);
            if (ret != NTRU_OK) {
                bench_printf("NTRU encrypt error\r\n");
                return;
            }
        }
        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != DRBG_OK) {
            bench_printf("NTRU error occurred uninstantiating the DRBG\r\n");
            return;
        }

        total = current_time(0) - start;
        each  = total / ntimes;   /* per second   */
        milliEach = each * 1000; /* milliseconds */

        bench_printf("NTRU %d encryption took %6.3f milliseconds, avg over %d"
           " iterations\r\n", ntruBits, milliEach, ntimes);


        ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                ciphertext_len, ciphertext, &plaintext_len, NULL);

        if (ret != NTRU_OK) {
            bench_printf("NTRU decrypt error occurred getting the buffer size needed\r\n");
            return;
        }

        plaintext_len = sizeof(plaintext);
        start = current_time(1);

        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                      ciphertext_len, ciphertext,
                                      &plaintext_len, plaintext);

            if (ret != NTRU_OK) {
                bench_printf("NTRU error occurred decrypting the key\r\n");
                return;
            }
        }

        total = current_time(0) - start;
        each  = total / ntimes;   /* per second   */
        milliEach = each * 1000; /* milliseconds */

        bench_printf("NTRU %d decryption took %6.3f milliseconds, avg over %d"
           " iterations\r\n", ntruBits, milliEach, ntimes);
    }

}

void bench_ntruKeyGen(void)
{
    float start, total, each, milliEach;
    int    i;

    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    word16 ntruBits = 128;
    word16 type     = 0;
    word32 ret;

    DRBG_HANDLE drbg;
    static uint8_t const pers_str[] = {
                'w', 'o', 'l', 'f',  'S', 'S', 'L', ' ', 't', 'e', 's', 't'
    };

    for (ntruBits = 128; ntruBits < 257; ntruBits += 64) {
        ret = ntru_crypto_drbg_instantiate(ntruBits, pers_str,
                sizeof(pers_str), GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            bench_printf("NTRU drbg instantiate failed\r\n");
            return;
        }

        switch (ntruBits) {
            case 128:
                type = NTRU_EES439EP1;
                break;
            case 192:
                type = NTRU_EES593EP1;
                break;
            case 256:
                type = NTRU_EES743EP1;
                break;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                                  NULL, &private_key_len, NULL);
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
        }

        total = current_time(0) - start;

        if (ret != NTRU_OK) {
            bench_printf("keygen failed\r\n");
            return;
        }

        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            bench_printf("NTRU drbg uninstantiate failed\r\n");
            return;
        }

        each = total / genTimes;
        milliEach = each * 1000;

        bench_printf("NTRU %d key generation  %6.3f milliseconds, avg over %d"
            " iterations\r\n", ntruBits, milliEach, genTimes);
    }
}
#endif

#ifdef HAVE_ECC
void bench_eccKeyGen(void)
{
    ecc_key genKey;
    float start, total, each, milliEach;
    int    i;
    int    ret;

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_ecc_init(&genKey);
        ret = wc_ecc_make_key(&rng, 32, &genKey);
        wc_ecc_free(&genKey);
    }

    if (ret != 0)
    {
        bench_printf("ecc_make_key failed\r\n");
        return;
    }
    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("\r\n");
    bench_printf("ECC  256 key generation  %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, genTimes);
}


void bench_eccKeyAgree(void)
{
    ecc_key genKey, genKey2;
    float start, total, each, milliEach;
    int    i, ret;
    byte   shared[32];
    byte   sig[64+16];  /* der encoding too */
    byte   digest[32];
    word32 x = 0;

    wc_ecc_init(&genKey);
    wc_ecc_init(&genKey2);

    ret = wc_ecc_make_key(&rng, 32, &genKey);
    if (ret != 0) {
        bench_printf("ecc_make_key failed\r\n");
        return;
    }
    ret = wc_ecc_make_key(&rng, 32, &genKey2);
    if (ret != 0) {
        bench_printf("ecc_make_key failed\r\n");
        return;
    }

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(shared);
        ret = wc_ecc_shared_secret(&genKey, &genKey2, shared, &x);
        if (ret != 0) {
            bench_printf("ecc_shared_secret failed\r\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("EC-DHE   key agreement   %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, agreeTimes);

    /* make dummy digest */
    for (i = 0; i < (int)sizeof(digest); i++)
        digest[i] = (byte)i;


    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(sig);
        ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &x, &rng, &genKey);
        if (ret != 0) {
            bench_printf("ecc_sign_hash failed\r\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("EC-DSA   sign   time     %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, agreeTimes);

    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        int verify = 0;
        ret = wc_ecc_verify_hash(sig, x, digest, sizeof(digest), &verify, &genKey);
        if (ret != 0) {
            bench_printf("ecc_verify_hash failed\r\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;     /* milliseconds */
    bench_printf("EC-DSA   verify time     %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, agreeTimes);

    wc_ecc_free(&genKey2);
    wc_ecc_free(&genKey);
}
#ifdef HAVE_ECC_ENCRYPT
void bench_eccEncrypt(void)
{
    ecc_key userA, userB;
    byte    msg[48];
    byte    out[80];
    word32  outSz   = sizeof(out);
    word32  plainSz = sizeof(plain);
    int     ret, i;
    float start, total, each, milliEach;

    wc_ecc_init(&userA);
    wc_ecc_init(&userB);

    wc_ecc_make_key(&rng, 32, &userA);
    wc_ecc_make_key(&rng, 32, &userB);

    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = i;

    start = current_time(1);

    for(i = 0; i < ntimes; i++) {
        /* encrypt msg to B */
        ret = wc_ecc_encrypt(&userA, &userB, msg, sizeof(msg), out, &outSz, NULL);
        if (ret != 0) {
            bench_printf("wc_ecc_encrypt failed! %d\r\n", ret);
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / ntimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("ECC      encrypt         %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, ntimes);

    start = current_time(1);

    for(i = 0; i < ntimes; i++) {
        /* decrypt msg from A */
        ret = wc_ecc_decrypt(&userB, &userA, out, outSz, plain, &plainSz, NULL);
        if (ret != 0) {
            bench_printf("wc_ecc_decrypt failed! %d\r\n", ret);
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / ntimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("ECC      decrypt         %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, ntimes);

    /* cleanup */
    wc_ecc_free(&userB);
    wc_ecc_free(&userA);
}
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
void bench_curve25519KeyGen(void)
{
    curve25519_key genKey;
    float start, total, each, milliEach;
    int    i;

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_curve25519_make_key(&rng, 32, &genKey);
        wc_curve25519_free(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("\r\n");
    bench_printf("CURVE25519 256 key generation %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, genTimes);
}

#ifdef HAVE_CURVE25519_SHARED_SECRET
void bench_curve25519KeyAgree(void)
{
    curve25519_key genKey, genKey2;
    float start, total, each, milliEach;
    int    i, ret;
    byte   shared[32];
    word32 x = 0;

    wc_curve25519_init(&genKey);
    wc_curve25519_init(&genKey2);

    ret = wc_curve25519_make_key(&rng, 32, &genKey);
    if (ret != 0) {
        bench_printf("curve25519_make_key failed\r\n");
        return;
    }
    ret = wc_curve25519_make_key(&rng, 32, &genKey2);
    if (ret != 0) {
        bench_printf("curve25519_make_key failed\r\n");
        return;
    }

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(shared);
        ret = wc_curve25519_shared_secret(&genKey, &genKey2, shared, &x);
        if (ret != 0) {
            bench_printf("curve25519_shared_secret failed\r\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("CURVE25519 key agreement      %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, agreeTimes);

    wc_curve25519_free(&genKey2);
    wc_curve25519_free(&genKey);
}
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
void bench_ed25519KeyGen(void)
{
    ed25519_key genKey;
    float start, total, each, milliEach;
    int    i;

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_ed25519_init(&genKey);
        wc_ed25519_make_key(&rng, 32, &genKey);
        wc_ed25519_free(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("\r\n");
    bench_printf("ED25519  key generation  %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, genTimes);
}


void bench_ed25519KeySign(void)
{
    ed25519_key genKey;
    float start, total, each, milliEach;
    int    i, ret;
    byte   sig[ED25519_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;

    wc_ed25519_init(&genKey);

    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &genKey);
    if (ret != 0) {
        bench_printf("ed25519_make_key failed\r\n");
        return;
    }

    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = (byte)i;

    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(sig);
        ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &x, &genKey);
        if (ret != 0) {
            bench_printf("ed25519_sign_msg failed\r\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    bench_printf("ED25519  sign   time     %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, agreeTimes);

    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        int verify = 0;
        ret = wc_ed25519_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                    &genKey);
        if (ret != 0 || verify != 1) {
            bench_printf("ed25519_verify_msg failed\r\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;     /* milliseconds */
    bench_printf("ED25519  verify time     %6.3f milliseconds, avg over %d"
           " iterations\r\n", milliEach, agreeTimes);

    wc_ed25519_free(&genKey);
}
#endif /* HAVE_ED25519 */


#ifdef _WIN32

    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    float current_time(int reset)
    {
        static int init = 0;
        static LARGE_INTEGER freq;

        LARGE_INTEGER count;

        (void)reset;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (float)count.QuadPart / freq.QuadPart;
    }

#elif defined MICROCHIP_PIC32
    #if defined(WOLFSSL_MICROCHIP_PIC32MZ)
        #define CLOCK 80000000.0
    #else
        #include <peripheral/timer.h>
        #define CLOCK 40000000.0
    #endif

    float current_time(int reset)
    {
        unsigned int ns;

        if (reset) {
            WriteCoreTimer(0);
        }

        /* get timer in ns */
        ns = ReadCoreTimer();

        /* return seconds as a float */
        return ( ns / CLOCK * 2.0);
    }

#elif defined(WOLFSSL_IAR_ARM_TIME) || defined (WOLFSSL_MDK_ARM) || defined(WOLFSSL_USER_CURRTIME)
    extern   float current_time(int reset);

#elif defined FREERTOS

    float current_time(int reset)
    {
        portTickType tickCount;

        (void) reset;

        /* tick count == ms, if configTICK_RATE_HZ is set to 1000 */
        tickCount = xTaskGetTickCount();
        return (float)tickCount / 1000;
    }

#elif defined (WOLFSSL_TIRTOS)

    extern float current_time(int reset);

#elif defined(FREESCALE_MQX)

    float current_time(int reset)
    {
        TIME_STRUCT tv;
        _time_get(&tv);

        return (float)tv.SECONDS + (float)tv.MILLISECONDS / 1000;
    }

#elif defined(FREESCALE_KSDK_BM)
#include <time.h>
static bool g_ksdkTimerIsInitialized = false;
static volatile uint32_t g_msCount = 0;

/*!
 * @brief Milliseconds counter since last POR/reset.
 */
void SysTick_Handler(void)
{
    g_msCount++;
}

/*!
 * @brief SysTick period configuration and interrupt enable.
 */
static uint32_t time_config(void)
{
    /* call CMSIS SysTick function. It enables the SysTick interrupt at low priority */
    return SysTick_Config(CORE_CLK_FREQ / 1000); /* 1 ms period */
}

/*!
 * @brief Get milliseconds since last POR/reset.
 */
static float time_get_ms(void)
{
    uint32_t currMsCount;
    uint32_t currTick;
    uint32_t loadTick;

    do
    {
        currMsCount = g_msCount;
        currTick = SysTick->VAL;
    } while (currMsCount != g_msCount);

    loadTick = CORE_CLK_FREQ / 1000;
    return (float)currMsCount + (float)(loadTick - currTick) / (float)loadTick;
}

static void ksdk_time_init(void)
{
    time_config();
    g_ksdkTimerIsInitialized = true;
}

static float ksdk_time_get(void)
{
    return time_get_ms() / 1000;
}

float current_time(int reset)
{
    if (!g_ksdkTimerIsInitialized)
    {
        ksdk_time_init();
        return (float)0;
    }

    return ksdk_time_get();
}

time_t ksdk_time(time_t *timer)
{
    time_t myTime;
    if (!g_ksdkTimerIsInitialized)
    {
        ksdk_time_init();
        return (time_t)0;
    }
    myTime = (time_t)ksdk_time_get();
    *timer = myTime;
    return myTime;
}

#elif defined(WOLFSSL_EMBOS)

    #include "RTOS.h"

    float current_time(int reset)
    {
        float time_now;
        float current_s = OS_GetTime() / 1000.0;
        float current_us = OS_GetTime_us() / 1000000.0;
        time_now = (float)( current_s + current_us);

        (void) reset;

        return time_now;
    }

#else

    #include <sys/time.h>

    float current_time(int reset)
    {
        struct timeval tv;

        (void)reset;

        gettimeofday(&tv, 0);

        return (float)tv.tv_sec + (float)tv.tv_usec / 1000000;
    }

#endif /* _WIN32 */

#ifdef HAVE_GET_CYCLES

static INLINE word64 get_intel_cycles(void)
{
    unsigned int lo_c, hi_c;
    __asm__ __volatile__ (
        "cpuid\r\n\t"
        "rdtsc"
            : "=a"(lo_c), "=d"(hi_c)   /* out */
            : "a"(0)                   /* in */
            : "%ebx", "%ecx");         /* clobber */
    return ((word64)lo_c) | (((word64)hi_c) << 32);
}

#endif /* HAVE_GET_CYCLES */
#else
    #ifndef NO_MAIN_DRIVER
        int main() { return 0; }
    #endif
#endif /* !NO_CRYPT_BENCHMARK */
