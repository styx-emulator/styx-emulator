/*
   The result of this test is returned by test_emulation() and stored in r15 after hitting the infinite loop. Successful tests set a unique bit in the result.

   The program tests basic instruction emulation capabilities including arithmetic, bitwise, and branch operations.
*/

#include "common.h"

void set_bit(int *flag, int bit) {
    *flag |= (1 << bit);
}
int test_emulation() {
    int error_code = 0;

    // Test arithmetic operations
    int a = 100, b = 200, c = 300;
    if (a + b == 300) set_bit(&error_code, 0);
    if (c - b == 100) set_bit(&error_code, 1);
    if (a * 2 == 200) set_bit(&error_code, 2);
    if (b / 2 == 100) set_bit(&error_code, 3);
    if (c % 200 == 100) set_bit(&error_code, 4);

    // Test bitwise operations
    int x = 0b1100, y = 0b1010;
    if ((x & y) == 0b1000) set_bit(&error_code, 5);
    if ((x | y) == 0b1110) set_bit(&error_code, 6);
    if ((x ^ y) == 0b0110) set_bit(&error_code, 7);
    if ((~x & 0xF) == 0b0011) set_bit(&error_code, 8); // 4-bit mask for 32-bit PPC
    if ((x << 1) == 0b11000) set_bit(&error_code, 9);
    if ((y >> 1) == 0b0101) set_bit(&error_code, 10);

    // Test branch operations
    int branch_test = 0;
    if (a < b && b < c) branch_test = 1;
    if (branch_test == 1) set_bit(&error_code, 11);

    branch_test = 0;
    if (a < c) {
        branch_test = 1;
        if (c > b) {
            branch_test = 2;
        }
    }
    if (branch_test == 2) set_bit(&error_code, 12);

    // Test loop (complex behavior)
    int loop_count = 0;
    for (int i = 0; i < 10; i++) {
        loop_count += i;
    }
    if (loop_count == 45) set_bit(&error_code, 13); // sum of 0 to 9

    // Complex arithmetic
    int complex = (a * b) - (c / a) + (a % b);
    if (complex == 20097) set_bit(&error_code, 14);

    // Special register read/write
    unsigned int tcr_value = 0x1337;
    unsigned int tcr_read_value;
    // 0x3DA is SPR for TCR (Timer Control Register)
    asm volatile ("mtspr 0x3DA, %0\n\t"
                  "mfspr %1, 0x3DA, \n\t "
        : "=r" (tcr_read_value)
        : "a" (tcr_value)
        : /* no affected registers */);
    if (tcr_read_value == tcr_value) set_bit(&error_code, 15);

    // Check if all tests passed
    return error_code;
}

__attribute__((section(".text.main")))
int main(void) {
    run(test_emulation);
    return 0;
}
