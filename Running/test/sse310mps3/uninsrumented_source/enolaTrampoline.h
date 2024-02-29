#ifndef ENOLA_TEE_TRAMPOLINE_LIB
#define ENOLA_TEE_TRAMPOLINE_LIB

#include<stdio.h>
#include <stdbool.h>

#define ARBITRARY_MAX 50
#define BASIC_BlOCK_MAX 50

/*Structure for occurence trace To*/
struct occurrence_trace
{
    unsigned int basicBlockStart[BASIC_BlOCK_MAX];
    unsigned int occurrence_count[BASIC_BlOCK_MAX];
    bool arbitrary_cf;
    unsigned int arbitrary_cf_addresses[ARBITRARY_MAX];
    unsigned int occurrence_size;

};

/*Structure for IBT*/
struct IBT
{
    unsigned int dest;
    unsigned int src;
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
void linear_search(unsigned int);
#endif