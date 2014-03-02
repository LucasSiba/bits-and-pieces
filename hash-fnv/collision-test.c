#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t
fnv04(char const *buf, int len)
{
    uint32_t hash = 0x811C9DC5;

    for (; --len >= 0; ++buf)
        hash = (hash ^ *(uint8_t const*)buf) * 0x01000193;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;

    return hash;
}

static int
increment(char *buf, int depth, int max_depth)
{
    //printf("increment buf[0]=%x, depth=%d, max_depth=%d\n", buf[0], depth, max_depth);
    if (depth > max_depth) { return 0; }
    buf[0] += 1;
    if (buf[0] == 0) {
        return increment(buf + 1, depth + 1, max_depth);
    }
    return 1;
}

int
main(int argc, char * argv[])
{
    (void)argc;
    (void)argv;

    char key[4];
    int  keylen;
    char* data = malloc(-1U);
    unsigned count = 0;

    memset(data, 0, -1U);

    for (keylen = 1; keylen <= (int)sizeof(key); keylen++) {
        printf("keylen is now %d\n", keylen);
        memset(key, 0, sizeof(key));
        while (increment(key, 1, keylen)) {
            uint32_t hash = fnv04((char*)&key, keylen);
            if (data[hash]) {
                //printf("collision at len=%d\n", keylen);
                //int i;
                //for (i = 0; i < keylen; i++) { printf("%02x", (unsigned char)key[i]); }
                //printf("=hash, key=%u\n", hash);
                count++;
            }
            data[hash] = 1;
        }
    }

    printf("Count=%u\n", count);
    return 0;
}

