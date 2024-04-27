#include <stdio.h>

int loopOver(int x)
{
	for(int i = 0; x > 1; i++)
	{
		x = x / 2;
	}
	return x;
}

/*
int mod2(int x, int y)
{
	x = loopOver(y);
	if (x%9 == 2 || x%9 ==3)
		return 0;
	else if(x == 111 && x%y)
	{
		
		return x - (y%6) + (x *y);
	}
	else
		return 1;
}*/

/*int convIf(int x)
{
	if(x%3 == 0)
	{
		x = x % 4;
	}
	else if(x%3 == 1)
	{
		x = x % 5;
	}
	if(x%3 == 2)
	{
		x = x % 6;
	}
	return x;
}*/
/*int switchcase(int x)
{
	//x = x %3;
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
}*/

int main()
{
	int x = 32,y;
	x = x << 2;
	scanf("%d %d", &x, &y);
	//mod2(x, y);
	loopOver(x);
	//switchcase(x);
	return 0;
}
