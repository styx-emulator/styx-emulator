INCLUDE(CMakeForceCompiler)

# CROSS COMPILER SETTING
SET(CMAKE_SYSTEM_NAME Generic)
CMAKE_MINIMUM_REQUIRED (VERSION 2.6)

# THE VERSION NUMBER
SET (Tutorial_VERSION_MAJOR 1)
SET (Tutorial_VERSION_MINOR 0)

# ENABLE ASM
ENABLE_LANGUAGE(ASM)

SET(CMAKE_STATIC_LIBRARY_PREFIX)
SET(CMAKE_STATIC_LIBRARY_SUFFIX)

SET(CMAKE_EXECUTABLE_LIBRARY_PREFIX)
SET(CMAKE_EXECUTABLE_LIBRARY_SUFFIX)


# CURRENT DIRECTORY
SET(ProjDirPath ${CMAKE_CURRENT_SOURCE_DIR})


SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -DDEBUG")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -D__STARTUP_CLEAR_BSS")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -g")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -Wall")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -fno-common")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mthumb")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mapcs")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -std=gnu99")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -D__STARTUP_CLEAR_BSS")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -Wall")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -fno-common")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mthumb")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mapcs")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -std=gnu99")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DCPU_MK21FN1M0AVMC12")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DTWR_K21F120M")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DTOWER")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DPRINTF_ADVANCED_ENABLE=1")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DFREESCALE_KSDK_BM")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DWOLFSSL_USER_SETTINGS")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Og")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-common")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mthumb")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mapcs")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -std=gnu99")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MMD")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MP")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DCPU_MK21FN1M0AVMC12")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DTWR_K21F120M")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DTOWER")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DPRINTF_ADVANCED_ENABLE=1")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DFREESCALE_KSDK_BM")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DWOLFSSL_USER_SETTINGS")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-common")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mthumb")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mapcs")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -std=gnu99")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MMD")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MP")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Og")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-common")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mthumb")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mapcs")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-rtti")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-exceptions")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -MMD")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -MP")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-common")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mthumb")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mapcs")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-rtti")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-exceptions")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -MMD")

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -MP")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --specs=nano.specs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --specs=nosys.specs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Wall")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fno-common")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -ffunction-sections")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fdata-sections")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -ffreestanding")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fno-builtin")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mthumb")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mapcs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --gc-sections")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -static")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -z")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} muldefs")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mcpu=cortex-m4")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mfloat-abi=hard")

SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -mfpu=fpv4-sp-d16")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} --specs=nano.specs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} --specs=nosys.specs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wall")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-common")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -ffunction-sections")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fdata-sections")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -ffreestanding")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-builtin")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mthumb")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mapcs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} --gc-sections")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -static")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -z")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Xlinker")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} muldefs")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mcpu=cortex-m4")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mfloat-abi=hard")

SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -mfpu=fpv4-sp-d16")

include_directories(${ProjDirPath}/../../../../../../CMSIS/Include)

include_directories(${ProjDirPath}/../../../../../../devices)

include_directories(${ProjDirPath}/..)

include_directories(${ProjDirPath}/../../../..)

include_directories(${ProjDirPath}/../../../../../../middleware/mmcau)

include_directories(${ProjDirPath}/../../../../../../middleware/wolfssl)

include_directories(${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/port)

include_directories(${ProjDirPath}/../../../../../../devices/MK21FA12/drivers)

include_directories(${ProjDirPath}/../../../../../../devices/MK21FA12)

include_directories(${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/io)

include_directories(${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/str)

include_directories(${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/log)

include_directories(${ProjDirPath}/../../../../../../devices/MK21FA12/utilities)

add_executable(wolfssl_selftest.elf
"${ProjDirPath}/../wolfssl_selftest.c"
"${ProjDirPath}/../user_settings.h"
"${ProjDirPath}/../pin_mux.c"
"${ProjDirPath}/../pin_mux.h"
"${ProjDirPath}/../board.c"
"${ProjDirPath}/../board.h"
"${ProjDirPath}/../clock_config.c"
"${ProjDirPath}/../clock_config.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_rnga.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_rnga.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_common.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_common.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_clock.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_clock.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_uart.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_uart.c"
"${ProjDirPath}/../../../../../../middleware/mmcau/cau_api.h"
"${ProjDirPath}/../../../../../../middleware/mmcau/fsl_mmcau.h"
"${ProjDirPath}/../../../../../../middleware/mmcau/fsl_mmcau.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_flash.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_flash.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/system_MK21FA12.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/system_MK21FA12.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/gcc/startup_MK21FA12.S"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_port.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_smc.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_smc.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/io/fsl_io.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/io/fsl_io.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/log/fsl_log.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/log/fsl_log.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/str/fsl_str.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/str/fsl_str.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/fsl_debug_console.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/fsl_debug_console.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/fsl_debug_console_conf.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_gpio.h"
"${ProjDirPath}/../../../../../../devices/MK21FA12/drivers/fsl_gpio.c"
"${ProjDirPath}/../../../../../../devices/MK21FA12/utilities/fsl_assert.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/callbacks.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/certs_test.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/crl.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/error-ssl.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/internal.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/ocsp.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/options.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/sniffer.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/sniffer_error.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/ssl.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/test.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/version.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/openssl/ec.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/openssl/ssl.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/openssl/bn.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/aes.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/arc4.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/asn.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/asn_public.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/blake2.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/blake2-impl.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/blake2-int.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/camellia.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/cmac.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/chacha.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/chacha20_poly1305.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/coding.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/compress.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/curve25519.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/des3.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/dh.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/dsa.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/ecc.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/ed25519.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/error-crypt.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/fe_operations.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/fips_test.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/ge_operations.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/hash.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/hc128.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/hmac.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/integer.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/idea.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/logging.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/md2.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/md4.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/md5.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/mem_track.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/memory.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/misc.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/mpi_class.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/mpi_superclass.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/pkcs7.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/poly1305.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/pwdbased.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/rabbit.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/random.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/ripemd.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/rsa.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/settings.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/sha.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/sha256.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/sha512.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/signature.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/srp.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/tfm.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/types.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/visibility.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/wc_encrypt.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/wc_port.h"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/aes.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/arc4.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/asm.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/asn.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/blake2b.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/camellia.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/chacha.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/chacha20_poly1305.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/coding.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/compress.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/curve25519.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/des3.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/dh.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/dsa.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/ecc.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/ecc_fp.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/ed25519.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/error.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/fe_low_mem.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/fe_operations.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/ge_low_mem.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/ge_operations.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/hash.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/hc128.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/hmac.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/integer.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/idea.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/logging.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/md2.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/md4.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/md5.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/memory.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/misc.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/pkcs7.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/poly1305.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/pwdbased.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/rabbit.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/random.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/ripemd.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/rsa.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/sha.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/sha256.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/sha512.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/signature.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/srp.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/tfm.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/wc_encrypt.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/wc_port.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/crl.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/internal.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/io.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/keys.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/ocsp.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/sniffer.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/ssl.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/src/tls.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfcrypt/src/port/nxp/ksdk_port.c"
"${ProjDirPath}/../../../../../../middleware/wolfssl/wolfssl/wolfcrypt/port/nxp/ksdk_port.h"
)


set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -T${ProjDirPath}/MK21FN1M0Axxx12_flash.ld -static")

set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -T${ProjDirPath}/MK21FN1M0Axxx12_flash.ld -static")

TARGET_LINK_LIBRARIES(wolfssl_selftest.elf -Wl,--start-group)
target_link_libraries(wolfssl_selftest.elf debug m)

target_link_libraries(wolfssl_selftest.elf debug c)

target_link_libraries(wolfssl_selftest.elf debug gcc)

target_link_libraries(wolfssl_selftest.elf debug nosys)

target_link_libraries(wolfssl_selftest.elf optimized m)

target_link_libraries(wolfssl_selftest.elf optimized c)

target_link_libraries(wolfssl_selftest.elf optimized gcc)

target_link_libraries(wolfssl_selftest.elf optimized nosys)

link_directories(${ProjDirPath}/../../../../../../middleware/mmcau/asm-cm4-cm7)

target_link_libraries(wolfssl_selftest.elf debug ${ProjDirPath}/../../../../../../middleware/mmcau/asm-cm4-cm7/lib_mmcau.a)

link_directories(${ProjDirPath}/../../../../../../middleware/mmcau/asm-cm4-cm7)

target_link_libraries(wolfssl_selftest.elf optimized ${ProjDirPath}/../../../../../../middleware/mmcau/asm-cm4-cm7/lib_mmcau.a)

TARGET_LINK_LIBRARIES(wolfssl_selftest.elf -Wl,--end-group)
