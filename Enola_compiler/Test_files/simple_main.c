#include <stdio.h>

int factorial(int x)
{
	if(x==1)
		return x;
	return x * factorial(x - 1);
}

int square(int x)
{
	return x * x;
}

/*void branchToAddress (void* address, int arg1)
{
        asm volatile (
                "push {r0}\n"
        );

        asm volatile (
                "blx %[address]"
                :
                : [address] "r" (address)
        );

        asm volatile (
                "pop {r0}\n"
        );
}*/


int main()
{
	int (*func_ptr)(int);
	int x;
	scanf("%d", &x);
	printf("hello world\n");
	if (x%2 == 1)
	{
		func_ptr = &square;
	}
	else
	{
		func_ptr = &factorial;
	}

	//branchToAddress(func_ptr, x);
	(*func_ptr)(x);
	return 0;
}
