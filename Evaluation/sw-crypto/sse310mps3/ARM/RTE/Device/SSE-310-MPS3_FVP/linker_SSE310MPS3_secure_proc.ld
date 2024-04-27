;
( (0x11000000) ) = 0x11000000;
( (0x00020000) ) = 0x00020000;
( (0x31000000) ) = 0x31000000;
( (0x00040000) ) = 0x00040000;
(0x00000400) = 0x00000400;
(0x00000400) = 0x00000400;
MEMORY
{
  FLASH (rx) : ORIGIN = ( (0x11000000) ), LENGTH = ( (0x00020000) )
  RAM (rwx) : ORIGIN = ( (0x31000000) ), LENGTH = ( (0x00040000) )
}
__heap_size__ = (0x00000400);
__stack_size__ = (0x00000400);
ENTRY(Reset_Handler)
SECTIONS
{
    .text :
    {
        KEEP(*(.vectors))
        __Vectors_End = .;
        __Vectors_Size = __Vectors_End - __Vectors;
        __end__ = .;
        *(.text*)
        KEEP(*(.init))
        KEEP(*(.fini))
        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)
         *crtbegin.o(.dtors)
         *crtbegin?.o(.dtors)
         *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
         *(SORT(.dtors.*))
         *(.dtors)
        *(.rodata*)
        KEEP(*(.eh_frame*))
    } > FLASH
    .gnu.sgstubs : ALIGN(32)
    {
        *(.gnu.sgstubs*)
    } > FLASH
    . = ALIGN(32);
    Image$$ER_CODE_CMSE_VENEER$$Base = ADDR(.gnu.sgstubs);
    Image$$ER_CODE_CMSE_VENEER$$Limit = .;
    Image$$ER_CODE_CMSE_VENEER$$Length = Image$$ER_CODE_CMSE_VENEER$$Limit - Image$$ER_CODE_CMSE_VENEER$$Base;
    ASSERT(((( (0x11000000) ) + ( (0x00020000) )) > Image$$ER_CODE_CMSE_VENEER$$Limit), "Veneer region does not fit into code memory")
    .ARM.extab : ALIGN(32)
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > FLASH
    __exidx_start = .;
    .ARM.exidx :
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASH
    __exidx_end = .;
    .copy.table : ALIGN(4)
    {
        __copy_table_start__ = .;
        LONG (__etext)
        LONG (__data_start__)
        LONG ((__data_end__ - __data_start__) / 4)
        LONG (DEFINED(__etext2) ? __etext2 : 0)
        LONG (DEFINED(__data2_start__) ? __data2_start__ : 0)
        LONG (DEFINED(__data2_start__) ? ((__data2_end__ - __data2_start__) / 4) : 0)
        __copy_table_end__ = .;
    } > FLASH
    .zero.table : ALIGN(4)
    {
        __zero_table_start__ = .;
        LONG (__bss_start__)
        LONG ((__bss_end__ - __bss_start__) / 4)
        LONG (DEFINED(__bss2_start__) ? __bss2_start__ : 0)
        LONG (DEFINED(__bss2_start__) ? ((__bss2_end__ - __bss2_start__) / 4) : 0)
        __zero_table_end__ = .;
    } > FLASH
    __etext = ALIGN(4);
    .data : ALIGN(4)
    {
        __data_start__ = .;
        *(vtable)
        *(.data*)
        . = ALIGN(4);
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);
        . = ALIGN(4);
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);
        . = ALIGN(4);
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE_HIDDEN (__fini_array_end = .);
        KEEP(*(.jcr*))
        . = ALIGN(4);
        __data_end__ = .;
    } > RAM AT> FLASH
    .bss : ALIGN(4)
    {
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > RAM
    bss_size = __bss_end__ - __bss_start__;
    .heap (COPY) : ALIGN(8)
    {
        __HeapBase = .;
        __end__ = .;
        end = __end__;
        KEEP(*(.heap*))
        __HeapLimit = .;
    } > RAM
    .stack : ALIGN(8)
    {
        __StackLimit = .;
        KEEP(*(.stack*))
        . += __stack_size__ - 0x8;
        __StackTop = .;
    } > RAM
    .msp_stack_seal_res :
    {
        . += 0x8;
    } > RAM
    __StackSeal = ADDR(.msp_stack_seal_res);
    .heap : ALIGN(8)
    {
        __end__ = .;
        PROVIDE(end = .);
        __HeapBase = .;
        . += __heap_size__;
        __HeapLimit = .;
        __heap_limit = .;
    } > RAM
    PROVIDE(__stack = __StackTop);
    ASSERT(__StackTop <= (( (0x31000000) ) + ( (0x00040000) )), "Secure RAM region overflowed")
}
