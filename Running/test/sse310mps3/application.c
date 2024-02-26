#include "application.h"
int mod2(int x)
{
	if (x%2 == 0)
		return 0 + x;
	else
		return 1 + x;
}
int loopOver(int x)
{
	for(int i = 0; x > 1; i++)
	{
		x = x / 2;
	}
	return x;
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
	return x;
}

int func(int a)
{
        return a*10;
}