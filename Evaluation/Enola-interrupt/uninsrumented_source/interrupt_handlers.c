#include "interrupt_handlers.h"
#include <stdio.h>


/*----------------------------------------------------------------------------
  SysTick IRQ Handler
 *----------------------------------------------------------------------------*/
//void ns_SysTick_Handler (void);

void ns_SysTick_Handler (void) {
  static unsigned int ticks;

  switch (ticks++) {
    case  10:
      LED_On(7u);
      break;
    case 20:
      Secure_LED_On(6u);
      break;
    case 30:
      LED_Off(7u);
      break;
    case 50:
      Secure_LED_Off(6u);
      break;
    case 99:
      ticks = 0;
      break;
    default:
      if (ticks > 99) {
        ticks = 0;
      }
  }
}