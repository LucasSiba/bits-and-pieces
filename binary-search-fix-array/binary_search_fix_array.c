#include <stdio.h>
#include <math.h>

char
run_search(int *arr, int element_cnt, int t)
{
    // Binary search
    int bot = 0;
    int top = element_cnt;
    int pos = (bot + top) / 2;

    while (bot < top) {
        if (arr[pos] < t) {
            bot = pos + 1;
        } else if (arr[pos] > t) {
            top = pos - 1;
        } else {
            return 1;
        }
        pos = (bot + top) / 2;
    }   

    return (arr[pos] == t);
}

int
main(void)
{
    int x;
    int data[] = {3, 7, 9, 10, 11, 20, 21, 22, 23, 24, 25, 30, 40, 60, 110};

    for (x = 0; x < (int)(sizeof(data) / sizeof(int)); x++) {
        printf("%d ", data[x]);
    }
    printf("\n");

    for (x = 0; x < 200; x++) {
        char found;
        found = run_search(data, (int)(sizeof(data) / sizeof(int)), x);
        if (found) {
            printf("Yes-%d\t", x);
        } else {
            printf("    %d\t", x);
        }
        if (x % 10 == 0) {
            printf("\n");
        }
    }

    return 0;
}

