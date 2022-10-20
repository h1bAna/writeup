#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main()
{
    char buf[16];
    size_t size;
    long value;
    void (*jump)();

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    printf("Data: ");
    read(0, buf, size);

    printf("*jmp=");
    scanf("%ld", &value);

    jump = *(long *)value;
    jump();

    return 0;
}
