
void run(int func()) {
    int result = func();

    asm ("mr %%r15, %0\n\t"
        : /* no output */
        : "a" (result)
        : "%r15");


    for (;;) {}
}
