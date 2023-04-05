#include <stdio.h>
#include <arm_cmse.h>
#include "SSE310MPS3.h"
#include "platform_base_address.h"
#include "mpc_sie_drv.h"
#include "mpc_sie_reg_map.h"
#include "Driver_MPC.h"

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

int main()
{
	//struct mpc_sie_dev_t obj;
	//obj.data->sie_version = 0x65;
//	obj.cfg->base = (const)0x65;
	//enum mpc_sie_error_t ret = mpc_sie_init(&obj);
	
//	MPS3_MPCFPGASRAM->ctrl &= ~(1UL << 8U);              /* clear auto increment */
 // MPS3_MPCFPGASRAM->blk_idx = 0;                       /* write LUT index */
  //MPS3_MPCFPGASRAM->blk_lutn = 0xFFFF0000UL;            /* configure blocks */
	
	
	//MPS3_MPCFPGASRAM2->ctrl &= ~(1UL << 8U);              /* clear auto increment */
  //MPS3_MPCFPGASRAM2->blk_idx = 1;                       /* write LUT index */
 // MPS3_MPCFPGASRAM2->blk_lutn = 0xFFFFFFFFUL;            /* configure blocks */

 // MPS3_MPCFPGASRAM2->blk_idx = 0;                       /* write LUT index */
 // MPS3_MPCFPGASRAM2->blk_lutn = 0xFFFFFFFFUL;            /* configure blocks */
	
	//MPC_ISRAM1_RANGE_BASE_NS->CTRL &= ~(1UL << 8U);  
		uint32_t NonSecure_StackPointer = (*((uint32_t *)(NONSECURE_START + 0u)));
		NonSecure_fpVoid NonSecure_ResetHandler = (NonSecure_fpVoid)(*((uint32_t *)(NONSECURE_START + 4u)));
	//ARM_DRIVER_MPC tst;
	//uintptr_t base = 0x57000000, limit = 0x00020000;
//	ARM_MPC_SEC_ATTR atttr= ARM_MPC_ATTR_MIXED;
//	int ret = tst.Initialize();
	//tst.ConfigRegion(base, limit, atttr);
	
  //__ASM volatile ("MSR msp_ns, %0" : : "r" (NONSECURE_START) : );
		
		
		//struct mpc_sie_memory_range_t rng = {0x28000000, 0x287FFFFF, 0, MPC_SIE_SEC_ATTR_NONSECURE};
		struct mpc_sie_memory_range_t rng = {FPGA_MPC_ADDRESS_BASE, FPGA_MPC_ADDRESS_LIMIT, MPC_REGION_OFFSET, MPC_SIE_SEC_ATTR_NONSECURE};
		
		const struct mpc_sie_memory_range_t *rng_ptr = &rng;
		const struct mpc_sie_memory_range_t **double_rng_ptr = & rng_ptr;
		
		const struct mpc_sie_dev_cfg_t mpc_cfg = {MPC_SRAM_CONTROLLER, double_rng_ptr, 1}; 
		
		struct mpc_sie_dev_data_t mpc_data = {false, 0x65};
		
		struct mpc_sie_dev_t dev_test = {&mpc_cfg, &mpc_data};
		
		enum mpc_sie_sec_attr_t mpc_attr = MPC_SIE_SEC_ATTR_NONSECURE;
		
		enum mpc_sie_error_t init_mpc_dev = mpc_sie_init(&dev_test); /*Initialization correct*/
		
		/* get ctrl of the MPC*/
		uint32_t ctrl_holder = 0;
		enum mpc_sie_error_t get_ctrl = mpc_sie_get_ctrl(&dev_test, &ctrl_holder);
	
		
		/* get block size of the MPC device*/
		uint32_t blk_size_holder = 0;
		enum mpc_sie_error_t get_block_size = mpc_sie_get_block_size(&dev_test, &blk_size_holder);
		
		/*get region config test */
		enum mpc_sie_sec_attr_t mpc_get_config_holder; 
		enum mpc_sie_error_t mpc_current_config_ret = mpc_sie_get_region_config(&dev_test, FPGA_MPC_ADDRESS_BASE, FPGA_MPC_ADDRESS_LIMIT, &mpc_get_config_holder);
		/*test config region*/
		//rng.attr = MPC_SIE_SEC_ATTR_NONSECURE;
		//enum mpc_sie_error_t mpc_config_ret = mpc_sie_config_region(&dev_test, FPGA_MPC_ADDRESS_BASE, FPGA_MPC_ADDRESS_LIMIT, mpc_attr);
		
		/*confirm NS configuration*/
		mpc_current_config_ret = mpc_sie_get_region_config(&dev_test, FPGA_MPC_ADDRESS_BASE, FPGA_MPC_ADDRESS_LIMIT, &mpc_get_config_holder);
		
		
	/*__asm volatile(
		"MOV r5, #0x1122\n\t"
		"MSR PAC_KEY_U_0, r5\n\t"
	  "MSR PAC_KEY_P_0_NS, r5\n\t"
		"MSR PAC_KEY_U_0_NS, r5\n\t"
	);*/
	
	/*__asm volatile(
		"MOVW r0, #0x0000\n\t"
		"MOVT r0, #0x1020\n\t"
	  "BLXNS r0\n\t"
	);*/
	
	NonSecure_ResetHandler();
	return 0;
}