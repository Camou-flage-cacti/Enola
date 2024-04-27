#include "user_func.h"
#include "instrumented_asm.h"

//"AUTG r12, r14, r5\n\t" validate
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

int cond_function(int a, int b)
{
	if (frwd_edge() && a == 5)
	{
		return func_add(a, b);
	}
	else{
		return func_multiply(a, b);
	}
}