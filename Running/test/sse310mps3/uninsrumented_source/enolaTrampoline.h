#ifndef ENOLA_TEE_TRAMPOLINE_LIB
#define ENOLA_TEE_TRAMPOLINE_LIB

#include<stdio.h>
#include <stdbool.h>

#define ARBITRARY_MAX 50
#define BASIC_BlOCK_MAX 50
#define IBT_ADDRESS 0x31040000

/*Structure for occurence trace To*/
struct occurrence_trace
{
    unsigned int basicBlockStart[BASIC_BlOCK_MAX];
    unsigned int occurrence_count[BASIC_BlOCK_MAX];
    bool arbitrary_cf;
    unsigned int arbitrary_cf_addresses[ARBITRARY_MAX];
    unsigned int occurrence_size;

};



/*library functions*/
void init_trampoline();
void __attribute__((naked)) init_registers();
void __attribute__((naked)) enable_PAC();
void __attribute__((naked)) setup_S_PAC_Keys();
extern void secure_trace_storage();
extern void indirect_secure_trace_storage(int dummy, int dummy2);
unsigned int get_idx(unsigned int addr);
void print_occurence_trace(); /*Temporary function*/
void linear_search(unsigned int);
void intialize_IBT();
#endif