/*----------------------------------------------------------------------------
 * Name:    main_ns.c
 * Purpose: Main function non-secure mode
 *----------------------------------------------------------------------------*/

#include <arm_cmse.h>
#include "RTE_Components.h"                        /* Component selection */
#include CMSIS_device_header
#include "Board_LED.h"                             /* ::Board Support:LED */
#include "..\IOTKit_CM33_s\Secure_Functions.h"      /* Secure Code Entry Points */
#include "IOTKit_CM33_FP.h"
#include "interrupt_handlers.h"


char text[] = "Done executing the LED toggle (non-secure)\r\n";

/*----------------------------------------------------------------------------
  NonSecure functions used for callbacks
 *----------------------------------------------------------------------------*/
int32_t NonSecure_LED_On(uint32_t num);
int32_t NonSecure_LED_On(uint32_t num)
{
  return LED_On(num);
}

int32_t NonSecure_LED_Off(uint32_t num);
int32_t NonSecure_LED_Off(uint32_t num)
{
  return LED_Off(num);
}


/*----------------------------------------------------------------------------
  SysTick IRQ Handler
 *----------------------------------------------------------------------------*/
/*void ns_SysTick_Handler (void);
void ns_SysTick_Handler (void) {
  static uint32_t ticks;

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
*/
/*
void ns_Timer0_Handler (void);
void ns_Timer0_Handler (void) {
  static uint32_t ticks;

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

void TIMER0_Handler (void);
void TIMER0_Handler (void) {
  static uint32_t ticks;

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


void Timer0_Init_NS(void) {
	
   // 1ms = 25,000 ticks at 25MHz
    IOTKIT_TIMER0->RELOAD = 25000;

    // Clear any pending interrupt
    IOTKIT_TIMER0->INTCLEAR = IOTKIT_TIMER_INTCLEAR_Msk;

    // Enable interrupt generation
    IOTKIT_TIMER0->CTRL |= IOTKIT_TIMER_CTRL_IRQEN_Msk;

    // Enable the timer
    IOTKIT_TIMER0->CTRL |= IOTKIT_TIMER_CTRL_EN_Msk;

    // Enable TIMER0 interrupt at NVIC (ARM core interrupt controller)
    NVIC_EnableIRQ(TIMER0_IRQn);
}

*/

static uint32_t x;
/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main (void)
{
  uint32_t i;

  /* exercise some floating point instructions */
  volatile uint32_t fpuType = SCB_GetFPUType(); 
  volatile float  x1 = 12.4567f;
  volatile float  x2 = 0.6637967f;
  volatile float  x3 = 24.1111118f;

  x3 = x3 * (x1 / x2);

  /* exercise some core register from Non Secure Mode */
  x = __get_MSP();
  x = __get_PSP();

  /* register NonSecure callbacks in Secure application */
  Secure_LED_On_callback(NonSecure_LED_On);
  Secure_LED_Off_callback(NonSecure_LED_Off);

#if 0
  LED_Initialize ();                      /* already done in Secure part */
#endif

  SystemCoreClockUpdate();
  //SysTick_Config(SystemCoreClock / 100);  /* Generate interrupt each 10 ms */
	Secure_Register_NS_Handler(15, ns_SysTick_Handler);
	//Secure_Register_NS_Handler(3, ns_Timer0_Handler);
	
	// Init Timer0 from NS — IRQ goes to Secure
  //Timer0_Init_NS();

  for (uint32_t i = 1; i <10000; i++) {
//	while(1) {
		//uint32_t val = IOTKIT_TIMER0->VALUE;
    LED_On (5u);
    for (i = 0; i < 0x100000; i++) __NOP();
    LED_Off(5u);
    for (i = 0; i < 0x100000; i++) __NOP();
    Secure_LED_On (4u);
    for (i = 0; i < 0x100000; i++) __NOP();
    Secure_LED_Off(4u);
    for (i = 0; i < 0x100000; i++) __NOP();
		
/*		if (IOTKIT_TIMER0->INTSTATUS & IOTKIT_TIMER_INTSTATUS_Msk) {
     Secure_printf(text);
	}*/
  }
	Secure_printf(text);
}
