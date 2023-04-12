#include "user_func.h"


int func_add(int a, int b)
{
	int res = a + b;
	
		__asm volatile(
	  "PACG r12, r14, r12\n\t"
	);
		
	return res;
}

void func_substract(int sub, int *result)
{
	__asm volatile(
	  "PACG r12, r14, r12\n\t"
	);
	*result = *result - sub;
}

int func_multiply(int a, int b)
{
	int res =  a * b;
	__asm volatile(
	  "PACG r12, r14, r12\n\t"
	);
	return res;
}
	
void func_div(int a, int *result)
{
	*result = *result / a;
}