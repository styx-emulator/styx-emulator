#include "common.h"
int fibonacci_recursive(int n)
{
    if (n == 0) {
       return 0;
    }
    if (n == 1) {
       return 1;
    }
    return fibonacci_recursive(n - 1) + fibonacci_recursive(n - 2);
}

// Calculate fibonnaci numbers
int fib() {
    return fibonacci_recursive(26);
}

int main( void ) {
  run(fib);
}
