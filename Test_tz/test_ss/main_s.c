#include <stdio.h>
#include <arm_cmse.h>
#include "SSE310MPS3.h"
#include "platform_base_address.h"
#include "mpc_sie_drv.h"
#include "mpc_sie_reg_map.h"
#include "Driver_MPC.h"
#include "user_func.h"

#define MPC_SRAM_CONTROLLER 0x57000000
//#define MPC_QSPI_CONTROLLER 0x57001000

#define     __IM     volatile const      /*! Defines 'read only' structure member permissions */
#define     __OM     volatile            /*! Defines 'write only' structure member permissions */
#define     __IOM    volatile            /*! Defines 'read / write' structure member permissions */

typedef struct /* see "ARM CoreLink SSE-200 Subsystem Technical Reference Manual r0p0" */
{
  __IOM  uint32_t CTRL;                     /* Offset: 0x000 (R/W) Control Register */
         uint32_t RESERVED0[3];
  __IM   uint32_t BLK_MAX;                  /* Offset: 0x010 (R/ ) Block Maximum Register */
  __IM   uint32_t BLK_CFG;                  /* Offset: 0x014 (R/ ) Block Configuration Register */
  __IOM  uint32_t BLK_IDX;                  /* Offset: 0x018 (R/W) Block Index Register */
  __IOM  uint32_t BLK_LUT;                  /* Offset: 0x01C (R/W) Block Lookup Tabe Register */
  __IM   uint32_t INT_STAT;                 /* Offset: 0x020 (R/ ) Interrupt Status Register */
  __OM   uint32_t INT_CLEAR;                /* Offset: 0x024 ( /W) Interrupt Clear Register */
  __IOM  uint32_t INT_EN;                   /* Offset: 0x028 (R/W) Interrupt Enable Register */
  __IM   uint32_t INT_INFO1;                /* Offset: 0x02C (R/ ) Interrupt Info1 Register */
  __IM   uint32_t INT_INFO2;                /* Offset: 0x030 (R/ ) Interrupt Info2 Register */
  __OM   uint32_t INT_SET;                  /* Offset: 0x034 ( /W) Interrupt Set Register */
} MPS3_MPC_TypeDef;

//#define MPS3_MPCFPGASRAM         ((MPS3_MPC_TypeDef               *) MPC_SRAM_CONTROLLER   )
#define MPS3_MPCFPGASRAM         ((struct mpc_sie_reg_map_t               *) MPC_SRAM_CONTROLLER   )
#define MPS3_MPCFPGASRAM2         ((struct mpc_sie_reg_map_t               *) MPC_SRAM_CONTROLLER   )
#define NONSECURE_START (0x1020000u)
//#define NONSECURE_START (0x28000000u)

#define FPGA_MPC_ADDRESS_BASE 0x01020000//0x28000000 //
#define FPGA_MPC_ADDRESS_LIMIT 0x011FFFFF//0x287FFFFF //
#define MPC_REGION_OFFSET 0x20000


//#define NONSECURE_START SRAM_BASE_NS
/* typedef for NonSecure callback functions */
typedef int32_t (*NonSecure_fpParam)(uint32_t) __attribute__((cmse_nonsecure_call));
typedef void (*NonSecure_fpVoid)(void) __attribute__((cmse_nonsecure_call));


//void __attribute__((naked)) setup_NS_PAC_Keys()
void setup_NS_PAC_Keys()
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
}
//void __attribute__((naked)) setup_S_PAC_Keys()
void setup_S_PAC_Keys()
{
		__asm volatile(
		"MOV r5, #0x1122\n\t"
		"MOVT r5, #0x3344\n\t"
	  "MSR PAC_KEY_P_0, r5\n\t"
		"MSR PAC_KEY_P_1, r5\n\t"
		"MSR PAC_KEY_P_2, r5\n\t"
		"MSR PAC_KEY_P_3, r5\n\t"
	);
}
void switch_to_NS ()
{
		uint32_t NonSecure_StackPointer = (*((uint32_t *)(NONSECURE_START + 0u)));
		NonSecure_fpVoid NonSecure_ResetHandler = (NonSecure_fpVoid)(*((uint32_t *)(NONSECURE_START + 4u)));
		NonSecure_ResetHandler();
}

//void __attribute__((naked)) enable_PAC() //change to naked functions we don't need function prolouge and epilougle.
void enable_PAC()
{
	__asm volatile(
		"MOV r5, #0x4c\n\t"
	  "MSR CONTROL, r5\n\t"
	);
}

//void __attribute__((naked)) init_r12()
void init_r12()
{
	__asm volatile(
		"MOV r12, #0x0\n\t"
	);
}

void set_MSP_NS()
{
	__asm volatile(
		"MOV r12, #0x0818\n\t"
		"MOVT r12, #0x2104\n\t"
		"MSR MSP_NS, r12\n\t"
		//"MSR PSP_NS, r12\n\t"
	);
}


int main()
{
	/*setup_S_PAC_Keys();
	init_r12();
	enable_PAC();
	int result = func_add(10, 30);
	func_substract(5, &result);
	func_multiply(result, 2);
	func_div(2, &result);
	
	int r = cond_function(5, 5);*/
	//setup_MPC();
	setup_NS_PAC_Keys();
	//set_MSP_NS();
	switch_to_NS ();
	
	return 0;
}