/* Define memory regions */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 0x00200000
  RAM (rwx) : ORIGIN = 0x38000000, LENGTH = 0x00200000
}

/* Define entry point */
ENTRY(_start)

/* Define symbols */
SECTIONS
{
  .text : {
    KEEP(*(.vectors))

    *(.text)
    _start = .; /* Define the entry point at the beginning of the .text section */

    KEEP(*(.init))
    KEEP(*(.fini))

    /* .ctors */
    *crtbegin.o(.ctors)
    *crtbegin?.o(.ctors)
    *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
    *(SORT(.ctors.*))
    *(.ctors)

    /* .dtors */
    *crtbegin.o(.dtors)
    *crtbegin?.o(.dtors)
    *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
    *(SORT(.dtors.*))
    *(.dtors)

    *(.rodata*)

    KEEP(*(.eh_frame*))
  } > FLASH

  .data : {
    __copy_table_start__ = .;
    *(.data)
    __copy_table_end__ = .;
  } > RAM AT > FLASH

  .bss : {
    __zero_table_start__ = .;
    *(.bss)
    __zero_table_end__ = .;
  } > RAM

  /* Define stack and heap */
  /* Adjust the stack size as needed */
  _estack = ORIGIN(RAM) + LENGTH(RAM); /* Top of RAM */
  __StackLimit = ORIGIN(RAM); /* Bottom of RAM */
  __StackTop = _estack; /* Define __StackTop at the end of RAM */
  __StackSeal = _estack - 0x100; /* Example: reserve 256 bytes for the stack seal */

  /* Additional sections and definitions */
}
