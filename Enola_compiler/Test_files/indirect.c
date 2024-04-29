#include <stdio.h>
#include <limits.h>

extern void id_call (void (* f) ());
extern void funca (void);
extern void funcb (void);
extern void funcc (void);

void (*f[])(void) = { funca, funcb };

void test (void)  {
  id_call (f[0]);
  id_call (f[1]);

// The following always generates an inter-bank table entry
  id_call (funcc);
}

void funca ()  {
  ;
}

void funcb ()  {
  ;
}

void funcc ()  {
  ;
}

void id_call (void (* f) ())  {
  f ();
}

int foo(int a) {
  return a;
}

int bar(int a) {
  return a;
}

int baz(int a) {
  return a;
}

int direct_version() {
  int i, b = 0;
  for (i = 0; i < INT_MAX; ++i) {
      b = foo(b) + bar(b) + baz(b);
  }
  return b;
}

int indirect_version(int (*fn)(int), int (*fn2)(int), int (*fn3)(int)) {
  int i, b = 0;

  for (i = 0; i < INT_MAX; ++i) {
    b = fn(b) + fn2(b) + fn3(b);
  }

  return b;
}

int add(int a, int b) { return a + b; }

int inc(int a) { return ++a; }

int (*Fptr)(int) = &inc; // NOLINT

typedef int (*funcPtr)(int);

typedef int (*charfuncPtr)(char);

int testcall(int a) {funcPtr test = (funcPtr)0x38000001; a = test(a); return a;}

int testloop(int count)
{
  int sum;
  for (int i = 0; i < count; i++)
  {
    for (int j = 0; j < count; j++)
    {
      sum++;
    }
  }
  return sum;
}

int testconditionbr()
{
  int sum = 1;
  for (int i = 0; i < 10; i++)
  {
    switch (i%2)
    {
    case 0:{
      funcPtr test = (funcPtr)0x38000001;
      test(sum);
      break;
    }
    case 1:{
      sum += 1;
      break;
    }
    
    default:
      break;
    }
  } 

  if (sum > 10)
  {
    return sum;
  } 
  return 0;
}

int main(void) {

  printf("Hello World!\n");
  int i = 42;
  int j = 13;
  int k = add(i, j);
  int tmp = k;
  int tmp2;
  id_call (f[1]);
  k = inc(k);
  for (int idx = 0; idx < 100; ++idx) {
    ++k;
  }
  k = Fptr(k);
  tmp = testcall(tmp);
  tmp2 = testloop(k);

  funcPtr test = (funcPtr)k;
  test(k);

  direct_version();
  indirect_version(&foo, &bar, &baz);

 // __asm("BX r0");
 // __asm("BLX r0");

  testconditionbr();
  return 0;
}
