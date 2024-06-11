#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

char secret[0x10];

void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(time(0));
    for (int i = 0; i < 0x10; i++)
    {
        secret[i] = 48 + (rand() % (126 - 47) + 1);
    }
}

int main(){
    init();
    write(1, secret, 0x10);
    return 0;
}