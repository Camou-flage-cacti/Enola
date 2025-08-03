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
#define NS_VECTOR_TABLE_SIZE 144

extern GLCD_FONT     GLCD_Font_16x24;

extern int stdout_init (void);

/* typedef for NonSecure callback functions */
typedef int32_t (*NonSecure_fpParam)(uint32_t) __attribute__((cmse_nonsecure_call));
typedef void    (*NonSecure_fpVoid) (void)     __attribute__((cmse_nonsecure_call));
typedef void (*ns_handler_t)(void) __attribute__((cmse_nonsecure_call));

#define NS_STACK_BASE   0x28400000UL
#define NS_STACK_SIZE   0x00000400UL
#define NS_STACK_LIMIT  (NS_STACK_BASE + NS_STACK_SIZE - 1)

#define NS_STACK_REGION 1

static ns_handler_t ns_vector_table[NS_VECTOR_TABLE_SIZE] = {0};

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

void test_llvm_nsc (int a) __attribute__((cmse_nonsecure_entry)) ;
void test_llvm_nsc (int a)
{
  printf("LLVM NSC compiled count: 0x%x\n\r", a);
}

/**Get index of irq number**/
__attribute__((cmse_nonsecure_entry))
void Secure_Register_NS_Handler(uint32_t irq_num, ns_handler_t cb) {
    if (irq_num < NS_VECTOR_TABLE_SIZE) {
        ns_vector_table[irq_num] = cb;
    }
}

/* === 1. Initialize MPU for Non-Secure world with no restrictions === */
void Enable_NS_MPU(void)
{
    // Enable Non-Secure MPU with default map fallback (PRIVDEFENA)
    MPU_NS->CTRL = (1 << 0) | (1 << 2); // ENABLE | PRIVDEFENA
}

/**Trap all interrupts into the dispatcher **/

void Secure_ENOLA_Dispatcher(void) { 
	  
    uint32_t exc_num = __get_IPSR() & 0x1FF;  // Mask to ensure range 0–511
		
		uint32_t saved_r10, saved_r11;

		// Save r10 and r11 into local variables
    __asm volatile (
        "mov %[out_r10], r10 \n"
        "mov %[out_r11], r11 \n"
        : [out_r10] "=r" (saved_r10), [out_r11] "=r" (saved_r11)
    );
		
		// Save original region settings
    MPU_NS->RNR  = NS_STACK_REGION;
    uint32_t original_rbar = MPU_NS->RBAR;
    uint32_t original_rlar = MPU_NS->RLAR;

    // Set region to Read-Only
    MPU_NS->RNR  = NS_STACK_REGION;
    MPU_NS->RBAR = NS_STACK_BASE | (1 << 4); // VALID
    MPU_NS->RLAR = (NS_STACK_LIMIT & ~0x1F)  // Align to 32B
                 | (1 << 0)                  // ENABLE
                 | (0b110 << 1);             // AP[2:1] = 0b11 => RO
		
		

    if (exc_num < NS_VECTOR_TABLE_SIZE && ns_vector_table[exc_num]) 
		{
        ns_handler_t handler = ns_vector_table[exc_num];
        handler();  // Call the Non-Secure registered handler
    }

    // Restore region config
    MPU_NS->RNR  = NS_STACK_REGION;
    MPU_NS->RBAR = original_rbar;
    MPU_NS->RLAR = original_rlar;
		
		// Restore r10 and r11 from saved values
    __asm volatile (
        "mov r10, %[in_r10] \n"
        "mov r11, %[in_r11] \n"
        :: [in_r10] "r" (saved_r10), [in_r11] "r" (saved_r11)
    );
}


/*void TIMER0_Handler (void);
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
*/
/*----------------------------------------------------------------------------
  SysTick IRQ Handler
 *----------------------------------------------------------------------------*/
void s_SysTick_Handler (void);
void s_SysTick_Handler (void) {
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
  LED_Initialize ();
  GLCD_Initialize();
	NVIC->ITNS[0] &= ~(1 << 3);  // IRQ3 = Timer0 -> Secure
	NVIC_EnableIRQ(TIMER0_IRQn);

  /* display initial screen */
  GLCD_SetFont(&GLCD_Font_16x24);
  GLCD_SetBackgroundColor(GLCD_COLOR_WHITE);
  GLCD_ClearScreen();
  GLCD_SetBackgroundColor(GLCD_COLOR_BLUE);
  GLCD_SetForegroundColor(GLCD_COLOR_RED);
  GLCD_DrawString(0*16, 0*24, "   V2M-MPS2+ Demo   ");
  GLCD_DrawString(0*16, 1*24, " Secure/Non-Secure  ");
  GLCD_DrawString(0*16, 2*24, "   www.keil.com     ");

  GLCD_SetBackgroundColor(GLCD_COLOR_WHITE);
  GLCD_SetForegroundColor(GLCD_COLOR_BLACK);
  switch ((SCB->CPUID >> 4) & 0xFFF) {
    case 0xD20:
      GLCD_DrawString(0*16, 4*24, "  Cortex-M23        ");
      break;
    case 0xD21:
      GLCD_DrawString(0*16, 4*24, "  Cortex-M33        ");
      break;
    default:
      GLCD_DrawString(0*16, 4*24, "  unknown Cortex-M  ");
      break;
  }
	Enable_NS_MPU();

  SysTick_Config(SystemCoreClock / 100);  /* Generate interrupt each 10 ms */
  
	
	init_trampoline();
  NonSecure_ResetHandler();
}

