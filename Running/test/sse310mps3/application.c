#include "application.h"
int mod2(int x)
{
	if (x%2 == 0)
		return 0;
	else
		return 1;
}
int loopOver(int x)
{
	for(int i = 0; i < x; i++)
	{
		x = x % (x + i);
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