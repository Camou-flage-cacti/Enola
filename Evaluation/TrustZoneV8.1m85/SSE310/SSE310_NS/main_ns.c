/*----------------------------------------------------------------------------
 * Name:    main_ns.c
 * Purpose: Main function non-secure mode
 *----------------------------------------------------------------------------*/

#include <arm_cmse.h>
#include "RTE_Components.h"                        /* Component selection */
#include CMSIS_device_header
#include "..\SSE310_S\Secure_Functions.h"     /* Secure Code Entry Points */


char text[] = "Hello World (non-secure) xx\r\n";

static uint32_t x;
/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main (void)
{
  uint32_t c;

  x = __get_MSP();
  x = __get_PSP();

#if 0
  LED_Initialize ();                    /* already done in S part */
#endif

  SystemCoreClockUpdate();

	Secure_printf(text);
	Secure_printf(text);
	for (int i = 0; i < 5; i++)
	{
		test_llvm_nsc(i + 1);
	}
}
