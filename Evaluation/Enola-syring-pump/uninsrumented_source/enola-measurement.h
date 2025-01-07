#ifndef ENOLA_MEASUREMEND_LIB
#define ENOLA_MEASUREMEND_LIB
#include<stdint.h>



#define  ARM_CM_DEMCR      (*(uint32_t *)0xE000EDFC)
#define  ARM_CM_DWT_CTRL   (*(uint32_t *)0xE0001000)
#define  ARM_CM_DWT_CYCCNT (*(uint32_t *)0xE0001004)
#define  ELAPSED_TIME_MAX_SECTIONS  1
typedef  struct  elapsed_time {
    uint32_t  start;
    uint32_t  current;
	uint32_t avg;
	uint32_t count;
	uint32_t sum;
    uint32_t  max;
    uint32_t  min;
} ELAPSED_TIME;

void  elapsed_time_clr   (uint32_t  i);      // Clear measured values
void  elapsed_time_init  (void);             // Module initialization
void  elapsed_time_start (uint32_t  i);      // Start measurement 
void  elapsed_time_stop  (uint32_t  i);      // Stop  measurement 
void  display_elapsed_times();
void delayMicroseconds(float usecs);
int toUInt(char* input, int len);
extern void test_llvm_nsc(int);
#endif