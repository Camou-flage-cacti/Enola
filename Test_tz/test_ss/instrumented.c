#include "instrumented_asm.h"


int frwd_edge()
{
		__asm volatile(
	  //"LDR r0, [sp, #4]\n\t"
		//"CMP r0, #5\n\t"
		//"BEQ 0x11000C9C\n\t"
		"PUSH {r1}\n\t"
		"MOV r1, #0x0C9C\n\t"
		//"PACG r12, r1, r12\n\t"
		//"MOV r1, 0x11000CAC\n\t"
		//"PACG r12, r1, r12\n\t"
		//"POP r1\n\t"
	);
		return 1;
}