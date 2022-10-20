#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main ()
{
    unsigned int r;
    srand(time(NULL));
    r = rand() % 1000000 ;

    printf("%d\n", r);
    return(0);
}