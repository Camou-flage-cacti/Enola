#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "application.h"
#include "Device.h"
#include "enolaTrampoline.h"

static FILE __stdio = FDEV_SETUP_STREAM(stdout_putchar, NULL, NULL, _FDEV_SETUP_WRITE);
FILE *const stdin = &__stdio;
__strong_reference(stdin, stdout);
__strong_reference(stdin, stderr);


/*int main(void)
{
	stdout_init();
	printf("\r\n= Hello World LLVM5=\r\n");
}*/


int main(void)
{
	stdout_init();
	//setup_S_PAC_Keys();
	//init_registers();
	//enable_PAC();
	//init_trampoline();
	// printf("\r\n= setup done=\r\n");
	// printf("\r\n= INitializing IBT=\r\n");
	 //intialize_IBT();
	// printf("\r\n= IBT init done=\r\n");
	//print_occurence_trace();
	int x = 32;
	//x = x << 2;
	int result = mod2(x);
	printf("\r\n= mod2 function call result %d=\r\n", result);
	result = loopOver(x);
	//printf("\r\n= loopOver %d=\r\n", result);
	result = switchcase(x);
	//printf("\r\n= switchcase %d=\r\n", result);
	int (*func_ptr)(int) = &func;
	result = (*func_ptr)(10);
	//printf("\r\n= func_ptr %d=\r\n", result);
	int nums[] = {0,1,0,3,12};
	moveZeros(nums, 5);
	// for(int i = 0; i < 5; i++)
	// {
	// 	printf("\r\n %d\r\n", nums[i]);
	// }
	return 0;
}
