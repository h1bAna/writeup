// gcc -o iofile_aw iofile_aw.c -fno-stack-protector -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char buf[80];

int size = 512;
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

void read_str() {
	fgets(buf, sizeof(buf)-1, stdin);
}

void get_shell() {
	system("/bin/sh");
}

void help() {
	printf("read: Read a line from the standard input and split it into fields.\n");
}

void read_command(char *s) {
	/* No overflow here */
	int len;
	len = read(0, s, size);
	if(s[len-1] == '\x0a') 
		s[len-1] = '\0';
}

int main(int argc, char *argv[]) {
	int idx = 0;
	int sel;
	char command[512];
	long *dst = 0;
	long *src = 0;
	memset(command, 0, sizeof(command)-1);

	initialize();

	while(1) {
		printf("# ");
		read_command(command);
		
		if(!strcmp(command, "read")) {
			read_str();
		}

		else if(!strcmp(command, "help")) {
			help();
		}

		else if(!strncmp(command, "printf", 6)) {
			if ( strtok(command, " ") ) {
				src = (long *)strtok(NULL, " ");
				dst = (long *)stdin;
				if(src) 
					memcpy(dst, src, 0x40);
			}				
		}

		else if(!strcmp(command, "exit")) {
			return 0;
		}
		else {
			printf("%s: command not found\n", command);
		}
	}
	return 0;
}
