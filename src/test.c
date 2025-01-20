#include <stdio.h>

int main() {
        unsigned int num = 1; // Starting number
        int shifts = 5; // Number of shifts

        printf("Original number: %u\n", num);

        num >>= 1; // Shift bits to the left by 1
        printf("After shift: %u\n", num);
        num >>= 0; // Shift bits to the left by 1
        printf("After shift: %u\n", num);
        num >>= 0; // Shift bits to the left by 1
        printf("After shift: %u\n", num);
        num >>= 1; // Shift bits to the left by 1
        printf("After shift: %u\n", num);
        num >>= 1; // Shift bits to the left by 1
        printf("After shift: %u\n", num);

        return 0;
}