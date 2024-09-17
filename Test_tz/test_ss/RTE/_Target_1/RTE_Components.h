
/*
 * Auto generated Run-Time-Environment Configuration File
 *      *** Do not modify ! ***
 *
 * Project: 'test_s' 
 * Target:  'Target 1' 
 */

#ifndef RTE_COMPONENTS_H
#define RTE_COMPONENTS_H


/*
 * Define the Device Header File: 
 */
#define CMSIS_device_header "SSE310MPS3.h"

/* ARM::CMSIS Driver:I2C:1.0.1 */
#define RTE_I2C0      1

/* ARM::CMSIS Driver:MPC:1.1.0 */
#define RTE_SRAM_MPC      1
        #define RTE_ISRAM0_MPC    1
        #define RTE_ISRAM1_MPC    1
        #define RTE_QSPI_MPC      1
        #define RTE_DDR4_MPC      0
        #define RTE_VM0_MPC       1
        #define RTE_VM1_MPC       1
        #define RTE_SSRAM2_MPC    1
        #define RTE_SSRAM3_MPC    1
/* ARM::CMSIS Driver:PPC:1.1.0 */
#define RTE_MAIN0_PPC_CORSTONE310            1
        #define RTE_MAIN_EXP0_PPC_CORSTONE310        1
        #define RTE_MAIN_EXP1_PPC_CORSTONE310        1
        #define RTE_MAIN_EXP2_PPC_CORSTONE310        1
        #define RTE_MAIN_EXP3_PPC_CORSTONE310        1
        #define RTE_PERIPH0_PPC_CORSTONE310          1
        #define RTE_PERIPH1_PPC_CORSTONE310          1
        #define RTE_PERIPH_EXP0_PPC_CORSTONE310      1
        #define RTE_PERIPH_EXP1_PPC_CORSTONE310      1
        #define RTE_PERIPH_EXP2_PPC_CORSTONE310      1
        #define RTE_PERIPH_EXP3_PPC_CORSTONE310      1
/* ARM::CMSIS Driver:USART:1.1.0 */
#define RTE_USART0      1

/* ARM::CMSIS:RTOS2:Keil RTX5:Library:5.9.0 */
#define RTE_CMSIS_RTOS2                 /* CMSIS-RTOS2 */
        #define RTE_CMSIS_RTOS2_RTX5            /* CMSIS-RTOS2 Keil RTX5 */
/* ARM::Device:Native Driver:SysCounter:1.0.1 */
#define RTE_SYSCOUNTER      1
/* ARM::Device:Native Driver:Timeout:1.0.1 */
#define RTE_TIMEOUT      1
/* ARM::Native Driver:SysCounter:1.0.1 */
#define RTE_SYSCOUNTER      1
/* ARM::Native Driver:Timeout:1.0.1 */
#define RTE_TIMEOUT      1


#endif /* RTE_COMPONENTS_H */
