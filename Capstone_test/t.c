#include <stdio.h>

void func(int a)
{
	printf("Value %d\n", a);
}

int main()
{
	int a = 10;
	for (int i = 0; i < a; i++)
	{
		func(a * -1* i);
	}

}

