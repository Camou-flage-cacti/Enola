#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "application.h"
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
	elapsed_time_init();
	for(int i =0; i<10;i++)
	{
		elapsed_time_start(0);
		setup_S_PAC_Keys();
		init_registers();
		elapsed_time_stop(0);
	}
	enable_PAC();
	for(int i =0; i<10;i++)
	{
		elapsed_time_start(1);
		init_trampoline();
		elapsed_time_stop(1);
	}
	printf("\r\n= setup done=\r\n");
	printf("\r\n= INitializing IBT=\r\n");
	for(int i =0; i<10;i++)
	{
		elapsed_time_start(2);
		intialize_IBT();
		elapsed_time_stop(2);
	}
	for(int i =0; i<10;i++)
	{
		elapsed_time_start(3);
		secure_trace_storage();
		elapsed_time_stop(3);
	}
	printf("\r\n= IBT init done=\r\n");
	//print_occurence_trace();
	int x = 32;
	//x = x << 2;
	int result = mod2(x);
	printf("\r\n= mod2 function call result %d=\r\n", result);
	result = loopOver(x);
	printf("\r\n= loopOver %d=\r\n", result);
	result = switchcase(x);
	printf("\r\n= switchcase %d=\r\n", result);
	int (*func_ptr)(int) = &func;
	(*func_ptr)(10);
	int nums[] = {0,1,0,3,12};
	moveZeros(nums, 5);
	test();

	// elapsed_time_start(5);
	// pacg_exe_time();
	// elapsed_time_start(5);
	display_elapsed_times();
	return 0;
}
