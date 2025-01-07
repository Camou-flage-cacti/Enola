/*----------------------------------------------------------------------------
 * Name:    main_ns.c
 * Purpose: Main function non-secure mode
 *----------------------------------------------------------------------------*/

#include <arm_cmse.h>
#include "RTE_Components.h"                        /* Component selection */
#include CMSIS_device_header
#include "Board_LED.h"                             /* ::Board Support:LED */
#include "Secure_Functions.h"     /* Secure Code Entry Points */
#include "enola-measurement.h"
#include "support.h"

char text[] = "Hello World (non-secure) xx\r\n";

static uint32_t x;
/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main (void)
{
  uint32_t i;

  /* exercise some core register from Non Secure Mode */
  x = __get_MSP();
  x = __get_PSP();

  SystemCoreClockUpdate();

  elapsed_time_init();
	elapsed_time_start(0);
  volatile int result = benchmark ();
  elapsed_time_stop(0);

  print_occurence_trace();
  int correct = verify_benchmark (result);
  return (!correct);

}
