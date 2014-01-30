#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t
fnv04(char const *buf, int len)
{
    uint32_t hash = 0x811C9DC5;
    for (; --len >= 0; ++buf)
        hash = (hash ^ *(uint8_t const*)buf) * 0x01000193;
    hash += hash << 13; hash ^= hash >> 7; hash += hash << 3;
    hash ^= hash >> 17; hash += hash << 5;
    return hash;
}

unsigned* hash_table;
unsigned  hash_bucket_count;

static void
hash_create(unsigned max_entries)
{
    // leave 25% open space
    hash_bucket_count = (int)(max_entries * (5.0/4.0));
    hash_table = (unsigned*)malloc(sizeof(int) * hash_bucket_count);
    memset(hash_table, 0, sizeof(int) * hash_bucket_count);
}

static void
hash_add(unsigned val)
{
    uint32_t key = fnv04((char*)(&val), 4);
    unsigned bucket = key % hash_bucket_count;
    unsigned orig_bucket = bucket;
    do {
        if (hash_table[bucket] == 0) {
            hash_table[bucket] = val;
            return;
        }
        bucket++;
        if (bucket == hash_bucket_count) {
            bucket = 0;
        }
    } while (bucket != orig_bucket);

    if (bucket == orig_bucket) {
        printf("Hash table full!");
    }
}

static int
hash_check(unsigned val)
{
    uint32_t key = fnv04((char*)(&val), 4);
    unsigned bucket = key % hash_bucket_count;
    unsigned orig_bucket = bucket;
    do {
        if (hash_table[bucket] == val) {
            return 1;
        }
        if (hash_table[bucket] == 0) {
            return 0;
        }
        bucket++;
        if (bucket == hash_bucket_count) { 
            bucket = 0;
        }
    } while (bucket != orig_bucket);
    return 0;
}

static void
hash_destroy(void)
{
    free(hash_table);
}

int
main(int argc, char * argv[])
{
    (void)argc;
    (void)argv;

    hash_create(100);

    // add some interesting numbers
    hash_add(0);
    hash_add(1);
    hash_add(2);
    hash_add(99);
    hash_add(100);
    hash_add(101);
    hash_add(0xFFFFFFFD);
    hash_add(0xFFFFFFFE);
    hash_add(0xFFFFFFFF);

    unsigned i;
    for (i = 0; i != 0xFFFFFFFF; i++) {
        if (hash_check(i)) {
            printf("Found %u in hash\n", i);
        }
    }

    hash_destroy();
    return 0;
}

