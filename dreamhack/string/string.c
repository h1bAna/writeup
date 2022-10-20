#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    close(2);
    dup2(1, 2);

    signal(SIGALRM, alarm_handler);
    alarm(60);
}


void input(char *buf) {
	printf("Input: ");
	read(0, buf, 255);
}

void print(char *buf) {
	warnx(buf);
}

int main() {
	int idx;
	char buf[256];

	initialize();

	memset(buf, 0, sizeof(buf));

	while(1) {
		printf("1. Input\n");
		printf("2. Print\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);
		switch(idx) {
			case 1:
				input(buf);
				break;
			case 2:
				print(buf);
				break;
			default:
				break;
		}
	}
	return 0;
}
