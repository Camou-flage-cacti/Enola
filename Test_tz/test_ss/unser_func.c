#include "user_func.h"


int func_add(int a, int b)
{
	return a + b;
}

void func_substract(int sub, int *result)
{
	*result = *result - sub;
}

int func_multiply(int a, int b)
{
	return a * b;
}
	
void func_div(int a, int *result)
{
	*result = *result / a;
}