#ifndef ENOLA_TEE_TRAMPOLINE_LIB
#define ENOLA_TEE_TRAMPOLINE_LIB

#include<stdio.h>
#include<stdint.h>
#include <stdbool.h>

#define ARBITRARY_MAX 50
#define BASIC_BlOCK_MAX 50
#define IBT_ADDRESS 0x31040000

/*
********************************************************************************
*                MAXIMUM NUMBER OF ELAPSED TIME MEASUREMENT SECTIONS
********************************************************************************
*/
#define  ELAPSED_TIME_MAX_SECTIONS  6

/*Structure for occurence trace To*/
struct occurrence_trace
{
    unsigned int basicBlockStart[BASIC_BlOCK_MAX];
    unsigned int occurrence_count[BASIC_BlOCK_MAX];
    bool arbitrary_cf;
    unsigned int arbitrary_cf_addresses[ARBITRARY_MAX];
    unsigned int occurrence_size;

};
/*
********************************************************************************
*                       MODULE TO MEASURE EXECUTION TIME
********************************************************************************
*/

/*
********************************************************************************
*                             FUNCTION PROTOTYPES
********************************************************************************
*/

void  elapsed_time_clr   (uint32_t  i);      // Clear measured values
void  elapsed_time_init  (void);             // Module initialization
void  elapsed_time_start (uint32_t  i);      // Start measurement 
void  elapsed_time_stop  (uint32_t  i);      // Stop  measurement 
void  display_elapsed_times();


/*library functions*/
void init_trampoline();
// void  init_registers();
// void  enable_PAC();
// void  setup_S_PAC_Keys();
void __attribute__((naked)) init_registers();
void __attribute__((naked)) enable_PAC();
void __attribute__((naked)) setup_S_PAC_Keys();
void secure_trace_storage();
void indirect_secure_trace_storage(int dummy, int dummy2);
unsigned int get_idx(unsigned int addr);
void print_occurence_trace(); /*Temporary function*/
void linear_search(unsigned int);
void intialize_IBT();
void __attribute__((naked)) pacg_exe_time();
void test();
#endif