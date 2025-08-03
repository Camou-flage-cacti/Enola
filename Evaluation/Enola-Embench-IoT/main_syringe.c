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
#include "syringePump.h"

char text[] = "Hello World (non-secure) xx\r\n";

static uint32_t x;
/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/

//C-FLAT new code
void main(void) {
    /* exercise some core register from Non Secure Mode */
    x = __get_MSP();
    x = __get_PSP();

    SystemCoreClockUpdate();


	//info("Starting syringe pump");
	setup();

  int count = 0;
  elapsed_time_init();
  elapsed_time_start(0);
//	while(count < 6) {

    //loop();
    loop(count);
    count++;

//	}
  print_occurence_trace();
  elapsed_time_stop(0);
}
