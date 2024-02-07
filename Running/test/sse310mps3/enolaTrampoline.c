#include "enolaTrampoline.h"
struct occurrence_trace To;
void init_trampoline()
{
    To.arbitrary_cf = false;
    for(int i = 0; i <basicBlock_max; i++)
    {
        To.basicBlockStart[i] = -1;
        To.occurrence_count[i] = -1;
    }

    for(int i = 0; i <arbitrary_max; i++)
    {
        To.arbitrary_cf_addresses[i] = -1;
    }
}
/*TODO: implement secure trace storage for TA*/
void secure_trace_storage()
{
    printf("\r\n Debugging info: in the secure trace storage function =\r\n");
}
/*TODO Implement indirect branch analysis from the binary offline analysis data*/
void indirect_secure_trace_storage()
{
     printf("\r\n Debugging info: in the insecure trace storage function =\r\n");
}

void setup_S_PAC_Keys()
{
	__asm volatile(
		"MOV r5, #0x1122\n\t"
		"MOVT r5, #0x3344\n\t"
		"MSR CONTROL, r5\n\t"
		"MSR PAC_KEY_P_1, r5\n\t"
		"MSR PAC_KEY_P_2, r5\n\t"
		"MSR PAC_KEY_P_3, r5\n\t"
	);
}
void enable_PAC()
{
	__asm volatile(
		"MOV r5, #0x4c\n\t"
		"MSR CONTROL, r5\n\t"
	);
}

//void __attribute__((naked)) init_r12()
void init_registers()
{
	__asm volatile(
		"MOV r12, #0x0\n\t"
	);
}

/* void setup_NS_PAC_Keys()
{
		__asm volatile(
		"MOV r5, #0x1122\n\t"
		"MSR PAC_KEY_U_0, r5\n\t"
	  "MSR PAC_KEY_P_0_NS, r5\n\t"
		"MSR PAC_KEY_U_0_NS, r5\n\t"
	);
	
	/*__asm volatile(
		"MOVW r0, #0x0000\n\t"
		"MOVT r0, #0x1020\n\t"
	  "BLXNS r0\n\t"
	);*/
//} */
//void __attribute__((naked)) setup_S_PAC_Keys()