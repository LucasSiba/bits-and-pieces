// http://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function

#include <stdint.h>

uint32_t
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

uint64_t
fnv08(char const *buf, int len)
{
    uint64_t hash = 0xCBF29CE484222325ULL;

    for (; --len >= 0; ++buf)
        hash = (hash ^ *(uint8_t const*)buf) * 0x00000100000001B3ULL;

    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;

    return  hash;
}
