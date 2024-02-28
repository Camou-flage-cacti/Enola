#include "enolaTrampoline.h"

struct occurrence_trace To;

unsigned int indirect_target = 0;
unsigned int indirect_source = 0;

void init_trampoline()
{
    To.arbitrary_cf = false;
    for(int i = 0; i <basicBlock_max; i++)
    {
        To.basicBlockStart[i] = -1;
        To.occurrence_count[i] = 0;
    }

    for(int i = 0; i <arbitrary_max; i++)
    {
        To.arbitrary_cf_addresses[i] = -1;
    }
	To.occurrence_size = 0;
}

void print_occurence_trace()
{
	printf("\r\n ----------------Occurence Trace start-------------- \r\n");
	for (int i = 0; i < To.occurrence_size; i ++)
	{
		printf("\r\n Address: 0x%x Count: 0x%x \r\n", To.basicBlockStart[i], To.occurrence_count[i]);
	}
	printf("\r\n ----------------Occurence Trace end-------------- \r\n");
	return;
}
/*Get index of Occurece trace */
unsigned int get_idx(unsigned int addr)
{
	for(unsigned int i = 0; i <To.occurrence_size; i++)
	{
		if(To.basicBlockStart[i] == addr)
		{
			return i;
		}
	}
	return basicBlock_max;
}
/*TODO: implement secure trace storage for TA*/
void secure_trace_storage()
{	
	if(To.occurrence_size >= basicBlock_max)
	{
		printf("\r\n Error info: Occurence trace buffer full =\r\n");
		return;
	}

	unsigned int current_addr = 0;
	__asm volatile(
	"MOV r0, lr\n\t"
	"MOV %0, r0\n\t"
	: "=r" (current_addr)
	:
	: "r0"
	);
	unsigned int idx = get_idx(current_addr);
	idx = (idx == basicBlock_max ? To.occurrence_size++ : idx);
	printf("\r\n Debugging info: index %u =\r\n",idx);
	/*Update address and occurrence count*/
	To.basicBlockStart[idx] = current_addr;
	To.occurrence_count[idx]++;

	//To.occurrence_size++;

    printf("\r\n Debugging info: in the secure trace storage function =\r\n");
	print_occurence_trace();
	return;
}
/*TODO Implement indirect branch analysis from the binary offline analysis data*/
void indirect_secure_trace_storage()
{
	/*get the target address from r0, the instrumened code will provide it in r0*/
	__asm volatile(
	"MOV %0, r0\n\t"
	: "=r" (indirect_target)
	:
	: "r0"
	);
	/*get the source address from lr + 2, lr will always be the load from stack instruction*/
	__asm volatile(
	"MOV r0, lr\n\t"
	"MOV %0, r0\n\t"
	: "=r" (indirect_source)
	:
	: "r0"
	);
	/*We need to decrease by 1 as in ARM PC will always be -1 */
	indirect_source += 1;
	indirect_target--;
	printf("\r\n The indirect source is 0x%x and the target is at 0x%x address=\r\n", indirect_source, indirect_target);
	printf("\r\n Debugging info: in the insecure trace storage function =\r\n");

	return;
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
		"MOV r9, #0x0\n\t"
		"MOV r10, #0x0\n\t"
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