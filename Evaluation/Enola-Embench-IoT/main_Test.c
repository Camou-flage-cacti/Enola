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
#define FIXED_ADDRESS 0x1000

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

  int *ptr = (int *) FIXED_ADDRESS;  // Pointer to the fixed address
  int input_value = *ptr; 
  int ret;
  //printf("Enter an integer: ");
  //scanf("%d", &input_value);
  
  // First if condition
  if (input_value > 50) {
      ret = 1;
  }
  // Second if-else condition
  else if (input_value > 20) {
       ret = 13;
  }
  // Else condition
  else {
       ret = 10;
  }

  return ret;
 
}

