#include<stdio.h>
#include<stdlib.h>

int main(){
    int fd1= openat("AT_FDCWD",'../flag.txt');
    printf("%d",fd1);
}