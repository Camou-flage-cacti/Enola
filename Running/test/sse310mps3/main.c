#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "application.h"

static FILE __stdio = FDEV_SETUP_STREAM(stdout_putchar, NULL, NULL, _FDEV_SETUP_WRITE);
FILE *const stdin = &__stdio;
__strong_reference(stdin, stdout);
__strong_reference(stdin, stderr);


/*int main(void)
{
	stdout_init();
	printf("\r\n= Hello World LLVM5=\r\n");
}*/
/*int mod2(int x)
{
	printf("\r\n= mod2 %d=\r\n", x);
	if (x%2 == 0)
		return 0;
	else
		return 1;
}
void loopOver(int x)
{
	for(int i = 0; i < x; i++)
	{
		x = x % (x + i);
	}
	printf("\r\n= loopOver %d=\r\n", x);
}

int switchcase(int x)
{
	switch(x % 3)
	{
		case 0:
			x = x % 4;
			break;
		case 1:
			x = x % 5;
			break;
		case 2:
			x = x % 6;
			break;
		default:
			break;

	}
	printf("\r\n= switchcase %d=\r\n", x);
	return x;
}
*/
int main(void)
{
	stdout_init();
	int x = 32;
	x = x << 2;
	int result = mod2(x);
	printf("\r\n= mod2 %d=\r\n", result);
	result = loopOver(x);
	printf("\r\n= loopOver %d=\r\n", result);
	result = switchcase(x);
	printf("\r\n= switchcase %d=\r\n", result);
	return 0;
}
