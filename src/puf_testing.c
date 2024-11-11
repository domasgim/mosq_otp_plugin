#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

u_int8_t generate_random_int() {
        return (u_int8_t)(rand() % 256);
}

int main() {
        printf("Testing PUF...\n");

        srand(time(NULL));
        printf("%u \n", generate_random_int());
}
