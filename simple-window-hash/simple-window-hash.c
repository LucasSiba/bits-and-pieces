#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#define WINDOW_HASH_BUCKET_SEARCH_RANGE 4

typedef struct WINDOW_HASH_BUCKET {
    uint32_t key;
    time_t   accessed;
    char     a_string[1024];
    int      a_number;
} window_hash_bucket;

window_hash_bucket* window_hash = NULL;
unsigned            window_hash_size = 0;

static void
window_hash_init(unsigned max_entries)
{
    window_hash_size = max_entries;
    assert(window_hash_size > (WINDOW_HASH_BUCKET_SEARCH_RANGE - 1));
    window_hash = (window_hash_bucket*)malloc(sizeof(window_hash_bucket) * window_hash_size);
    memset(window_hash, 0, sizeof(window_hash_bucket) * window_hash_size);
}

static void
window_hash_destroy(void)
{
    assert(window_hash != NULL);
    free(window_hash);
}


//// here ////

static time_t
window_hash_add(window_hash_bucket* new)
{
    int i;
    time_t bucked_used_time;

    assert(window_hash != NULL);

    // Best always starts with the first bucket
    window_hash_bucket* best = &(window_hash[(new->key) % window_hash_size]);

    for (i = 1; i < WINDOW_HASH_BUCKET_SEARCH_RANGE; i++) {
        window_hash_bucket* bucket = &(window_hash[(new->key + i) % window_hash_size]);
        if (bucket->accessed < best->accessed) { best = bucket; }
    }

    bucked_used_time = best->accessed;
    best->accessed = time(NULL);
    best->key = new->key;

    strcpy(best->a_string, new->a_string);
    best->a_number = new->a_number;

    return bucked_used_time;
}

static window_hash_bucket*
window_hash_get(uint32_t key)
{
    int i;
    window_hash_bucket* bucket;

    assert(window_hash != NULL);

    for (i = 0; i < WINDOW_HASH_BUCKET_SEARCH_RANGE; i++) {
        bucket = &(window_hash[(key + i) % window_hash_size]);

        if (bucket->accessed != 0 && bucket->key == key) {
            bucket->accessed = time(NULL);
            break;
        }
        bucket = NULL;
    }

    return bucket;
}

int
main(void)
{
    window_hash_init(23);

    window_hash_bucket add_me;
    add_me.key = 0xffeeddcc;
    add_me.a_number = 42;
    strcpy(add_me.a_string, "foo");

    window_hash_add(&add_me);
    
    window_hash_bucket* res;
    res = window_hash_get(0);
    if (res == NULL) { printf("ok!\n"); } else { printf("not ok!\n"); }
    res = window_hash_get(0xffeeddcc);
    if (res != NULL) { printf("ok!\n"); } else { printf("not ok!\n"); }
    if (res->a_number == 42) { printf("ok!\n"); } else { printf("not ok!\n"); }

    window_hash_destroy();
    return 0;
}
