ENTRY(main)

SECTIONS {
    /* Set the starting address of the .text section to 0x100 */
    .text 0x100 : {
        _start = .;
	*(.text.startup)
        *(.text)
    }

    /* Define .data section */
    .data : {
        *(.data)
    }

    /* Define .bss section */
    .bss : {
        *(.bss)
        *(COMMON)
        _end = .;
    }
}
