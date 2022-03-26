#include<stdio.h>
#include<string.h>
#include<stdlib.h>

int main(){
    int a = 1337;
    int *p = &a;
    printf("%p\n", p);
    int b;
    scanf("%d", &b);
    printf("%d\n", b);
    p += b;
    printf("%p\n", p);
}
