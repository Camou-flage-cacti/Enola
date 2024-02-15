#ifndef ENOLA_TEE_TRAMPOLINE_LIB
#define ENOLA_TEE_TRAMPOLINE_LIB

#include<stdio.h>
#include <stdbool.h>

#define arbitrary_max 5
#define basicBlock_max 5
/*Structure for occurence trace To*/
struct occurrence_trace
{
    unsigned int basicBlockStart[basicBlock_max];
    unsigned int occurrence_count[basicBlock_max];
    bool arbitrary_cf;
    unsigned int arbitrary_cf_addresses[arbitrary_max];
    unsigned int occurrence_size;

};

/*library functions*/
void init_trampoline();
void init_registers();
void enable_PAC();
void setup_S_PAC_Keys();
void secure_trace_storage();
void indirect_secure_trace_storage();
unsigned int get_idx(unsigned int addr);
void print_occurence_trace(); /*Temporary function*/
#endif