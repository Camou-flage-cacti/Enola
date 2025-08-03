#include "enolaTrampoline.h"
#include <stdio.h>

struct occurrence_trace To;

/*Size of IBT: number of entires*/

volatile unsigned int *IBT_size = (unsigned int *)IBT_ADDRESS;

volatile unsigned int * IBT_entry = (unsigned int *) (IBT_ADDRESS + sizeof(unsigned int));

unsigned int occurrence_trace_size = 0;
#define vi_range 23000
#define app_base 0x400
unsigned short int index_map[vi_range];
unsigned int total_exec = 0;
void intialize_IBT()
{
	#ifdef ENOLA_TRACE_DEBUG
	printf("\r\n ----------------IBT SIZE = 0x%x-------------- \r\n", *IBT_size);

	for(int i = 0; i < (*IBT_size) * 2 ; i+=2)
	{
		printf("\r\n-------------Destination: 0x%x || Source: 0x%x ---------------\r\n", IBT_entry[i], IBT_entry[i + 1]);
	}
	#endif
	
}
void init_trampoline()
{
    To.arbitrary_cf = false;
    for(int i = 0; i <BASIC_BlOCK_MAX; i++)
    {
        To.basicBlockStart[i] = -1;
        To.occurrence_count[i] = 0;
    }

    for(int i = 0; i <ARBITRARY_MAX; i++)
    {
        To.arbitrary_cf_addresses[i] = -1;
    }
		for(int i =0 ; i <vi_range; i++)
		{
			index_map[i] = 0xffff;
		}
	//To.occurrence_size = 0;
	occurrence_trace_size = 0;
	total_exec = 0;
}

void print_occurence_trace()
{
	printf("\r\n ----------------Occurence Trace start-------------- \r\n");
	printf("\r\n ----------------Total vi %d----------------\r\n",occurrence_trace_size);
	for (int i = 0; i < occurrence_trace_size; i ++)
	{
		printf("\r\n Address: 0x%x Count: 0x%x \r\n", To.basicBlockStart[i], To.occurrence_count[i]);
	}
	printf("\r\n ----------------Occurence Trace end-------------- \r\n");
	return;
}
/*Get index of Occurece trace */
unsigned int get_idx(unsigned int addr)
{
	for(unsigned int i = 0; i < occurrence_trace_size; i++)
	{
		if(To.basicBlockStart[i] == addr)
		{
			return i;
		}
	}
	return BASIC_BlOCK_MAX;
}
/*TODO: implement secure trace storage for TA*/
void secure_trace_storage(int current_addr)
{	
	/*unsigned int map_idx = (current_addr & 0xffff) - app_base;
	unsigned int idx = index_map [map_idx];
	if(idx == 0xffff)
	{
		To.basicBlockStart[occurrence_trace_size] = current_addr;
		index_map[map_idx] = occurrence_trace_size;
		idx = occurrence_trace_size++;
		
	}

	To.occurrence_count[idx]++;*/
	
	
 // Cache commonly used values to avoid repeated calculations
	unsigned int map_idx = (current_addr & 0xffff) - app_base;
	unsigned int *idx_ptr = &index_map[map_idx];
	unsigned int idx = *idx_ptr;

	// Check if the index has been initialized
	if (idx == 0xffffffff)
	{
			To.basicBlockStart[occurrence_trace_size] = current_addr;
			*idx_ptr = occurrence_trace_size;
			idx = occurrence_trace_size++;
	}

	// Use precomputed index to update the occurrence count
	To.occurrence_count[idx]++;
	
}
/*TODO Implement indirect branch analysis from the binary offline analysis data*/
void indirect_secure_trace_storage(int indirect_target)
{
	/*unsigned int map_idx = (indirect_target & 0xffff) - app_base;
	unsigned int idx = index_map [map_idx];
	if(idx == 0xffff)
	{
		To.basicBlockStart[occurrence_trace_size] = indirect_target;
		index_map[map_idx] = occurrence_trace_size;
		idx = occurrence_trace_size++;
	}
	
	To.occurrence_count[idx]++;*/
	 // Cache commonly used values to avoid repeated calculations
	unsigned int map_idx = (indirect_target & 0xffff) - app_base;
	unsigned int *idx_ptr = &index_map[map_idx];
	unsigned int idx = *idx_ptr;

	// Check if the index has been initialized
	if (idx == 0xffffffff)
	{
			To.basicBlockStart[occurrence_trace_size] = indirect_target;
			*idx_ptr = occurrence_trace_size;
			idx = occurrence_trace_size++;
	}

	// Use precomputed index to update the occurrence count
	To.occurrence_count[idx]++;
}
int linear_ITL_search(unsigned int target)
{
	for(int i ; i <ARBITRARY_MAX; i++)
	{
		if(To.arbitrary_cf_addresses[i] == target)
		{
			return i;
		}
	}
	return ARBITRARY_MAX;
}

// void __attribute__((naked)) setup_S_PAC_Keys()
// {
// 	__asm volatile(
// 		"MOV r5, #0x1122\n\t"
// 		"MOVT r5, #0x3344\n\t"
// 		"MSR PAC_KEY_P_0, r5\n\t"
// 		"MSR PAC_KEY_P_1, r5\n\t"
// 		"MSR PAC_KEY_P_2, r5\n\t"
// 		"MSR PAC_KEY_P_3, r5\n\t"
// 	);
// }
// void __attribute__((naked)) enable_PAC()
// {
// 	__asm volatile(
// 		"MOV r5, #0x4c\n\t"
// 		"MSR CONTROL, r5\n\t"
// 	);
// }

//void __attribute__((naked)) init_r12()
void __attribute__((naked)) init_registers()
{
	__asm volatile(
		"MOV r10, #0x0\n\t"
		"MOV r11, #0x0\n\t"
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


/*
********************************************************************************
*                           CORTEX-M - DWT TIMER
********************************************************************************
*/

/*#define  ARM_CM_DEMCR      (*(uint32_t *)0xE000EDFC)
#define  ARM_CM_DWT_CTRL   (*(uint32_t *)0xE0001000)
#define  ARM_CM_DWT_CYCCNT (*(uint32_t *)0xE0001004)*/

/*
********************************************************************************
*                             Data Structure
********************************************************************************
*/

/*typedef  struct  elapsed_time {
    uint32_t  start;
    uint32_t  current;
	uint32_t avg;
	uint32_t count;
	uint32_t sum;
    uint32_t  max;
    uint32_t  min;
} ELAPSED_TIME;
*/
/*
********************************************************************************
*                      STORAGE FOR ELAPSED TIME MEASUREMENTS
********************************************************************************
*/

//static  ELAPSED_TIME  elapsed_time_tbl[ELAPSED_TIME_MAX_SECTIONS];

/*
********************************************************************************
*                              MODULE INITIALIZATION
*
* Note(s): Must be called before any of the other functions in this module
********************************************************************************
*/

/*void  elapsed_time_init (void)         
{
    uint32_t  i;
    
    
    if (ARM_CM_DWT_CTRL != 0) {                  // See if DWT is available
		//printf("\r\n=DWT Available=\r\n");
        ARM_CM_DEMCR      |= 1 << 24;            // Set bit 24
        ARM_CM_DWT_CYCCNT  = 0;                
        ARM_CM_DWT_CTRL   |= 1 << 0;             // Set bit 0
    }
    for (i = 0; i < ELAPSED_TIME_MAX_SECTIONS; i++) {
        elapsed_time_clr(i);
    }
}*/

/*
********************************************************************************
*                  START THE MEASUREMENT OF A CODE SECTION
********************************************************************************
*/

/*void  elapsed_time_start (uint32_t  i)  
{
    elapsed_time_tbl[i].start = ARM_CM_DWT_CYCCNT;
}*/

/*
********************************************************************************
*           STOP THE MEASUREMENT OF A CODE SECTION AND COMPUTE STATS
********************************************************************************
*/

/*void  elapsed_time_stop (uint32_t  i)  
{
    uint32_t       stop; 
    ELAPSED_TIME  *p_tbl;
    

    stop           = ARM_CM_DWT_CYCCNT;   
    p_tbl          = &elapsed_time_tbl[i];
    p_tbl->current = stop - p_tbl->start;
	p_tbl->count++;
	p_tbl->sum	  +=  p_tbl->current;
	p_tbl->avg     = p_tbl->sum /p_tbl->count;
    if (p_tbl->max < p_tbl->current) {
        p_tbl->max = p_tbl->current;
    }
    if (p_tbl->min > p_tbl->current) {
        p_tbl->min = p_tbl->current;
    }
}*/

/*
********************************************************************************
*                      CLEAR THE MEASUREMENTS STATS
********************************************************************************
*/

/*void  elapsed_time_clr (uint32_t  i)         
{
    ELAPSED_TIME  *p_tbl;
    
    
    p_tbl          = &elapsed_time_tbl[i];
    p_tbl->start   = 0;
    p_tbl->current = 0;
	p_tbl->avg	   = 0;
	p_tbl->count   = 0;
	p_tbl->sum     = 0;
    p_tbl->min     = 0xFFFFFFFF;
    p_tbl->max     = 0;
}

void  display_elapsed_times()
{
	ELAPSED_TIME  *p_tbl;
	for (int i = 0; i < ELAPSED_TIME_MAX_SECTIONS; i++) 
	{
		p_tbl          = &elapsed_time_tbl[i];
		printf("\r\n Evaluation info: Code snippet: %d || Average CPU cycles used %d || Max used %d ||Min used %d || Execution count %d\r\n", i, p_tbl->avg, p_tbl->max, p_tbl->min,p_tbl->count);
	}
}*/