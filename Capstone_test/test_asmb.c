#include <stdio.h>

extern int myAssemblyFunction(int a, int b);

int main() {
    int result;
    int a = 5;
    int b = 10;

    //result = myAssemblyFunction(a, b);

    printf("Result: %d\n", result);
    return 0;
}
