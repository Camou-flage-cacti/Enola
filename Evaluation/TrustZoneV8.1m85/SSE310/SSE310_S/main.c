/*----------------------------------------------------------------------------
 * Name:    main_s.c
 * Purpose: Main function secure mode
 *----------------------------------------------------------------------------*/

#include <arm_cmse.h>
#include <stdio.h>
#include "RTE_Components.h"                        /* Component selection */
#include CMSIS_device_header
/* Start address of non-secure application */
#define NONSECURE_START (0x01020000u)



extern int stdout_init (void);

/* typedef for NonSecure callback functions */
typedef int32_t (*NonSecure_fpParam)(uint32_t) __attribute__((cmse_nonsecure_call));
typedef void    (*NonSecure_fpVoid) (void)     __attribute__((cmse_nonsecure_call));

char text[] = "Hello World (secure)\r\n";

/*----------------------------------------------------------------------------
  NonSecure callback functions
 *----------------------------------------------------------------------------*/
extern NonSecure_fpParam pfNonSecure_LED_On;
       NonSecure_fpParam pfNonSecure_LED_On  = (NonSecure_fpParam)NULL;
extern NonSecure_fpParam pfNonSecure_LED_Off;
       NonSecure_fpParam pfNonSecure_LED_Off = (NonSecure_fpParam)NULL;


void Secure_printf (char* pString) __attribute__((cmse_nonsecure_entry)) ;
void Secure_printf (char* pString)
{
  printf("%s", pString);
}

void test_llvm_nsc (int a) __attribute__((cmse_nonsecure_entry)) ;
void test_llvm_nsc (int a)
{
  printf("LLVM NSC compiled count: 0x%x\n\r", a);
}

static uint32_t x;
/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main (void)
{
  uint32_t         NonSecure_StackPointer =                   (*((uint32_t *)(NONSECURE_START + 0u)));
  NonSecure_fpVoid NonSecure_ResetHandler = (NonSecure_fpVoid)(*((uint32_t *)(NONSECURE_START + 4u)));

  /* exercise some floating point instructions from Secure Mode */
  volatile uint32_t fpuType = SCB_GetFPUType(); 
  volatile float  x1 = 12.4567f;
  volatile float  x2 = 0.6637967f;
  volatile float  x3 = 24.1111118f;

  x3 = x3 * (x1 / x2);
	uint32_t s_msp = 0, s_psp = 0, ns_msp = 0, ns_psp = 0;

  /* exercise some core register from Secure Mode */
  s_msp = __get_MSP();
  s_psp = __get_PSP();
  __TZ_set_MSP_NS(NonSecure_StackPointer);
  ns_msp = __TZ_get_MSP_NS();
  __TZ_set_PSP_NS(0x01020000u); //need to figure out the value. this value is wrong if psp is required
  ns_psp = __TZ_get_PSP_NS();
 // SystemCoreClockUpdate();

  stdout_init();
	s_msp = ns_msp * s_psp * ns_psp;
  NonSecure_ResetHandler();
}

