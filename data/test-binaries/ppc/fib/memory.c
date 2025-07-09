#include "common.h"

// write and read from a 1mb block
int big_mem() {
    // Start of ram memory block
    int * start_addr = (int *) 0x00300000;
    // 1 megabyte
    int length = 1 << 20;

    // result will hold number of reads that were wrong, should be 0
    int result = 0;

    for (int i = 0; i < length; i++) {
        *(start_addr + i) = i;
    }
    for (int i = 0; i < length; i++) {
        int val = *(start_addr + i);
        if (val != i) {
            result ++;
        }
    }

    return result;
}

int main( void ) {
  run(big_mem);
}
