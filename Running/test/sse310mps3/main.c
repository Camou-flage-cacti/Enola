#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"

static FILE __stdio = FDEV_SETUP_STREAM(stdout_putchar, NULL, NULL, _FDEV_SETUP_WRITE);
FILE *const stdin = &__stdio;
__strong_reference(stdin, stdout);
__strong_reference(stdin, stderr);


int main(void)
{
		stdout_init();
		printf("\r\n= Hello World LLVM4=\r\n");
}
