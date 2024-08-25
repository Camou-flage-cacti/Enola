#ifndef ENOLA_TEE_TRAMPOLINE_LIB
#define ENOLA_TEE_TRAMPOLINE_LIB

#include<stdint.h>
#include <stdbool.h>

#define ARBITRARY_MAX 1
#define BASIC_BlOCK_MAX 3500
#define IBT_ADDRESS 0x31040000

//#define  ELAPSED_TIME_MAX_SECTIONS  1
/*Structure for occurence trace To*/
struct occurrence_trace
{
    //unsigned int occurrence_size;
    unsigned int basicBlockStart[BASIC_BlOCK_MAX];
    unsigned int occurrence_count[BASIC_BlOCK_MAX];
    bool arbitrary_cf;
    unsigned int arbitrary_cf_addresses[ARBITRARY_MAX];

};

/*void  elapsed_time_clr   (uint32_t  i);      // Clear measured values
void  elapsed_time_init  (void);             // Module initialization
void  elapsed_time_start (uint32_t  i);      // Start measurement 
void  elapsed_time_stop  (uint32_t  i);      // Stop  measurement 
void  display_elapsed_times();*/


/*library functions*/
void init_trampoline();
void __attribute__((naked)) init_registers();
void __attribute__((naked)) enable_PAC();
void __attribute__((naked)) setup_S_PAC_Keys();
extern void secure_trace_storage(int current_addr)  __attribute__((cmse_nonsecure_entry)) ;
extern void indirect_secure_trace_storage(int indirect_target)  __attribute__((cmse_nonsecure_entry)) ;
unsigned int get_idx(unsigned int addr);
extern void print_occurence_trace()  __attribute__((cmse_nonsecure_entry)) ; /*Temporary function*/
int linear_ITL_search(unsigned int);
void intialize_IBT();
#endif