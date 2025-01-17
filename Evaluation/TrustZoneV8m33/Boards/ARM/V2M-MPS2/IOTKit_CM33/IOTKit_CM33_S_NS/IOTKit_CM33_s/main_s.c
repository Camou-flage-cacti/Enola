/*----------------------------------------------------------------------------
 * Name:    main_s.c
 * Purpose: Main function secure mode
 *----------------------------------------------------------------------------*/

#include <arm_cmse.h>
#include <stdio.h>
#include "RTE_Components.h"                        /* Component selection */
#include CMSIS_device_header
#include "Board_LED.h"                             /* ::Board Support:LED */
#include "Board_GLCD.h"                            /* ::Board Support:Graphic LCD */
#include "GLCD_Config.h"                           /* Keil.V2M-MPS2 IOT-Kit::Board Support:Graphic LCD */
#include "enolaTrampoline.h"
/* Start address of non-secure application */
#define NONSECURE_START (0x00200000u)

extern GLCD_FONT     GLCD_Font_16x24;

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


/*----------------------------------------------------------------------------
  Secure functions exported to NonSecure application
 *----------------------------------------------------------------------------*/
int32_t Secure_LED_On (uint32_t num) __attribute__((cmse_nonsecure_entry));
int32_t Secure_LED_On (uint32_t num)
{
  return LED_On(num);
}

int32_t Secure_LED_Off (uint32_t num) __attribute__((cmse_nonsecure_entry)) ;
int32_t Secure_LED_Off (uint32_t num)
{
  return LED_Off(num);
}

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


/*----------------------------------------------------------------------------
  Secure function for NonSecure callbacks exported to NonSecure application
 *----------------------------------------------------------------------------*/
int32_t Secure_LED_On_callback(NonSecure_fpParam callback) __attribute__((cmse_nonsecure_entry));
int32_t Secure_LED_On_callback(NonSecure_fpParam callback)
{
  pfNonSecure_LED_On = callback;
  return 0;
}

int32_t Secure_LED_Off_callback(NonSecure_fpParam callback) __attribute__((cmse_nonsecure_entry));
int32_t Secure_LED_Off_callback(NonSecure_fpParam callback)
{
  pfNonSecure_LED_Off = callback;
  return 0;
}


/*----------------------------------------------------------------------------
  SysTick IRQ Handler
 *----------------------------------------------------------------------------*/
/*void SysTick_Handler (void);
void SysTick_Handler (void) {
  static uint32_t ticks = 0;
  static uint32_t ticks_printf = 0;

  switch (ticks++) {
    case  10:
      LED_On (0u);
      break;
    case 20:
      LED_Off(0u);
      break;
    case 30:
      if (pfNonSecure_LED_On != NULL)
      {
        pfNonSecure_LED_On(1u);
      }
      break;
    case 50:
      if (pfNonSecure_LED_Off != NULL)
      {
        pfNonSecure_LED_Off(1u);
      }
      break;
    case 99:
      ticks = 0;
      if (ticks_printf++ == 3)
      {
        printf("%s", text);
        ticks_printf = 0;
      }
      break;
    default:
      if (ticks > 99) {
        ticks = 0;
      }
  }
}
*/

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

  /* exercise some core register from Secure Mode */
  x = __get_MSP();
  x = __get_PSP();
  __TZ_set_MSP_NS(NonSecure_StackPointer);
  x = __TZ_get_MSP_NS();
  __TZ_set_PSP_NS(0x22000000u);
  x = __TZ_get_PSP_NS();

  SystemCoreClockUpdate();

  stdout_init();                          /* Initialize Serial interface */
  /*LED_Initialize ();*/
  GLCD_Initialize();

  /* display initial screen */
  GLCD_SetFont(&GLCD_Font_16x24);
  GLCD_SetBackgroundColor(GLCD_COLOR_WHITE);
  GLCD_ClearScreen();
  GLCD_SetBackgroundColor(GLCD_COLOR_BLUE);
  GLCD_SetForegroundColor(GLCD_COLOR_RED);
  GLCD_DrawString(0*16, 0*24, "   CactiLab   ");
  GLCD_DrawString(0*16, 1*24, " ENOLA  ");
  GLCD_DrawString(0*16, 2*24, "   CFA    ");

  GLCD_SetBackgroundColor(GLCD_COLOR_WHITE);
  GLCD_SetForegroundColor(GLCD_COLOR_BLACK);
  switch ((SCB->CPUID >> 4) & 0xFFF) {
    case 0xD20:
      GLCD_DrawString(0*16, 4*24, "  Cortex-M23        ");
      break;
    case 0xD21:
      GLCD_DrawString(0*16, 4*24, "  Cortex-M85        ");
      break;
    default:
      GLCD_DrawString(0*16, 4*24, "  unknown Cortex-M  ");
      break;
  }

  //SysTick_Config(SystemCoreClock / 100);  /* Generate interrupt each 10 ms */
	
	init_trampoline();
  NonSecure_ResetHandler();
}

