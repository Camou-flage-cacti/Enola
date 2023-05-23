#include "instrumented_asm.h"


int frwd_edge()
{
		__asm volatile(
	 //"LDR r0, [sp, #4]\n\t"
		"CMP r0, #5\n\t"
		//"BEQ 0xff\n\t"
		"PUSH {r1}\n\t"
		"MOV r1, #0x0CA4\n\t"
		"MOVT r1, #0x1100\n\t"
		"PACG r12, r1, r12\n\t"
		"MOV r1, 0x0CB4\n\t"
		"MOVT r1, #0x1100\n\t"
		"PACG r12, r1, r12\n\t"
		"POP {r1}\n\t"
	);
		return 1;
}