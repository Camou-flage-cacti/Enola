#include "enola-measurement.h"

static  ELAPSED_TIME  elapsed_time_tbl[ELAPSED_TIME_MAX_SECTIONS];

void  elapsed_time_init (void)         
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
}

void  elapsed_time_start (uint32_t  i)  
{
    elapsed_time_tbl[i].start = ARM_CM_DWT_CYCCNT;
}

void  elapsed_time_stop (uint32_t  i)  
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
}

void  elapsed_time_clr (uint32_t  i)         
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
        test_llvm_nsc(p_tbl->avg);
		//printf("\r\n Evaluation info: Code snippet: %d || Average CPU cycles used %d || Max used %d ||Min used %d || Execution count %d\r\n", i, p_tbl->avg, p_tbl->max, p_tbl->min,p_tbl->count);
	}
}