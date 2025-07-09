#define USE_STDPERIPH_DRIVER
#include "stm32_p103.h"

#define SHPR_BYTE_COUNT 12

/* Writes words into the specified register.  Each byte is filled with a
 * different number.
 * addr - Start address of the register.
 * size - Size of the register in bytes.
 * /inrement_seq -
 *   Define the value sequence to be used.  The first byte will be
 *   set to , the second byte will be
 *   set to  + increment_seq, and so on.
 */
void test_word_write(volatile uint32_t *addr, unsigned size,
        uint8_t start_seq, uint8_t increment_seq)
{
    int offset;
    uint8_t curr_seq;
    uint32_t register_value;

    curr_seq = start_seq;
    for(offset = 0; offset < (size / 4); offset ++) {
        register_value =
                curr_seq |
                ((curr_seq + increment_seq) << 8) |
                ((curr_seq + (increment_seq * 2)) << 16) |
                ((curr_seq + (increment_seq * 3)) << 24);
        addr[offset] = register_value;
        curr_seq += increment_seq * 4;
    }
}

/* Reads words from the specified register.  Note that the values are not
 * printed out.  They must be verified using a debugger.
 * addr - Start address of the register.
 * size - Size of the register in bytes.
 */
void test_word_read(volatile uint32_t *addr, unsigned size)
{
    int offset;
    uint32_t register_value;

    for(offset = 0; offset < (size / 4); offset ++) {
        register_value = addr[offset];
    }
}

/* See test_word_write. */
void test_hword_write(volatile uint16_t *addr, unsigned size,
        uint8_t start_seq, uint8_t increment_seq)
{
    int offset;
    uint8_t curr_seq;
    uint16_t register_value;

    curr_seq = start_seq;
    for(offset = 0; offset < (size / 2); offset ++) {
        register_value =
                curr_seq |
                ((curr_seq + increment_seq) << 8);
        addr[offset] = register_value;
        curr_seq += increment_seq * 2;
    }
}

/* See test_word_read. */
void test_hword_read(volatile uint16_t *addr, unsigned size)
{
    int offset;
    uint16_t register_value;

    for(offset = 0; offset < (size / 2); offset ++) {
        register_value = addr[offset];
    }
}

/* See test_word_write. */
void test_byte_write(volatile uint8_t *addr, unsigned size,
        uint8_t start_seq, uint8_t increment_seq)
{
    int offset;
    uint8_t curr_seq;

    curr_seq = start_seq;
    for(offset = 0; offset < size; offset ++) {
        addr[offset] = curr_seq;
        curr_seq += increment_seq;
    }
}

/* See test_word_read. */
void test_byte_read(volatile uint8_t *addr, unsigned size)
{
    int offset;
    uint8_t register_value;

    for(offset = 0; offset < size; offset ++) {
        register_value = addr[offset];
    }
}

int main(void)
{
    uint32_t *vtor_reg = (uint32_t *)0xE000ED08;
    uint32_t vtor = vtor_reg[0];

    // /* Note that the SHPR (System Handler Priority Registers) only hold a 4 bit
    //  * priority, which are stored in the upper 4 bits of each byte.  The lower
    //  * 4 bits of each byte are read-only and always hold 0.
    //  */
    // test_word_write((uint32_t *)SCB->SHP, SHPR_BYTE_COUNT, 0x10, 0x10);
    // test_word_read((uint32_t *)SCB->SHP, SHPR_BYTE_COUNT);

    // test_hword_write((uint16_t *)SCB->SHP, SHPR_BYTE_COUNT, 0x20, 0x10);
    // test_hword_read((uint16_t *)SCB->SHP, SHPR_BYTE_COUNT);

    // test_byte_write(SCB->SHP, SHPR_BYTE_COUNT, 0x30, 0x10);
    // test_byte_read(SCB->SHP, SHPR_BYTE_COUNT);

    // /* Not implemented in QEMU */
    // /*test_word_read((uint32_t *)0xe000efd0, 0x10);*/

    // test_word_read((uint32_t *)0xe000efe0, 0x10);
    // test_word_read((uint32_t *)0xe000eff0, 0x10);

    // test_hword_read((uint16_t *)0xe000efe0, 0x10);
    // test_hword_read((uint16_t *)0xe000eff0, 0x10);

    // test_byte_read((uint8_t *)0xe000efe0, 0x10);
    // test_byte_read((uint8_t *)0xe000eff0, 0x10);

    /* Freeze */
    while(1);
}
