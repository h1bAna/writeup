// gcc -o vtable_bypass vtable_bypass.c -no-pie 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

FILE * fp;

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main()
{
    initialize();

    fp = fopen("/dev/urandom", "r");
    printf("stdout: %p\n", stdout);
    printf("Data: ");
    read(0, fp, 300);

    if (*(long*)((char*) fp + 0xe0) != 0)
    {
        exit(0);
    }

    fclose(fp);
}
