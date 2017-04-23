//https://raw.githubusercontent.com/wolkykim/qlibc/master/src/utilities/qhash.c

/**
 * Get 32-bit FNV1 hash.
 *
 * @param data      source data
 * @param nbytes    size of data
 *
 * @return 32-bit unsigned hash value.
 *
 * @code
 *  uint32_t hashval = qhashfnv1_32((void*)"hello", 5);
 * @endcode
 *
 * @code
 *  Fowler/Noll/Vo hash
 *
 *  The basis of this hash algorithm was taken from an idea sent as reviewer
 *  comments to the IEEE POSIX P1003.2 committee by:
 *
 *      Phong Vo (http://www.research.att.com/info/kpv/)
 *      Glenn Fowler (http://www.research.att.com/~gsf/)
 *
 *  In a subsequent ballot round:
 *
 *      Landon Curt Noll (http://www.isthe.com/chongo/)
 *
 *  improved on their algorithm.  Some people tried this hash and found that
 *  it worked rather well. In an EMail message to Landon, they named it the
 *  ``Fowler/Noll/Vo'' or FNV hash.
 *
 *  FNV hashes are designed to be fast while maintaining a low collision rate.
 *  The FNV speed allows one to quickly hash lots of data while maintaining
 *  a reasonable collision rate.  See:
 *
 *      http://www.isthe.com/chongo/tech/comp/fnv/index.html
 *
 *  for more details as well as other forms of the FNV hash.
 * @endcode
 */
uint32_t qhashfnv1_32(const void *data, size_t nbytes) {
    if (data == NULL || nbytes == 0)
        return 0;

    unsigned char *dp;
    uint32_t h = 0x811C9DC5;

    for (dp = (unsigned char *) data; *dp && nbytes > 0; dp++, nbytes--) {
#ifdef __GNUC__
        h += (h<<1) + (h<<4) + (h<<7) + (h<<8) + (h<<24);
#else
        h *= 0x01000193;
#endif
        h ^= *dp;
    }

    return h;
}

/**
 * Get 64-bit FNV1 hash integer.
 *
 * @param data      source data
 * @param nbytes    size of data
 *
 * @return 64-bit unsigned hash value.
 *
 * @code
 *   uint64_t fnv64 = qhashfnv1_64((void*)"hello", 5);
 * @endcode
 */
uint64_t qhashfnv1_64(const void *data, size_t nbytes) {
    if (data == NULL || nbytes == 0)
        return 0;

    unsigned char *dp;
    uint64_t h = 0xCBF29CE484222325ULL;

    for (dp = (unsigned char *) data; *dp && nbytes > 0; dp++, nbytes--) {
#ifdef __GNUC__
        h += (h << 1) + (h << 4) + (h << 5) +
        (h << 7) + (h << 8) + (h << 40);
#else
        h *= 0x100000001B3ULL;
#endif
        h ^= *dp;
    }

    return h;
}
/**
 * Get 32-bit Murmur3 hash.
 *
 * @param data      source data
 * @param nbytes    size of data
 *
 * @return 32-bit unsigned hash value.
 *
 * @code
 *  uint32_t hashval = qhashmurmur3_32((void*)"hello", 5);
 * @endcode
 *
 * @code
 *  MurmurHash3 was created by Austin Appleby  in 2008. The initial
 *  implementation was published in C++ and placed in the public.
 *    https://sites.google.com/site/murmurhash/
 *  Seungyoung Kim has ported its implementation into C language
 *  in 2012 and published it as a part of qLibc component.
 * @endcode
 */
uint32_t qhashmurmur3_32(const void *data, size_t nbytes) {
    if (data == NULL || nbytes == 0)
        return 0;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = nbytes / 4;
    const uint32_t *blocks = (const uint32_t *) (data);
    const uint8_t *tail = (const uint8_t *) (data + (nblocks * 4));

    uint32_t h = 0;

    int i;
    uint32_t k;
    for (i = 0; i < nblocks; i++) {
        k = blocks[i];

        k *= c1;
        k = (k << 15) | (k >> (32 - 15));
        k *= c2;

        h ^= k;
        h = (h << 13) | (h >> (32 - 13));
        h = (h * 5) + 0xe6546b64;
    }

    k = 0;
    switch (nbytes & 3) {
        case 3:
            k ^= tail[2] << 16;
        case 2:
            k ^= tail[1] << 8;
        case 1:
            k ^= tail[0];
            k *= c1;
            k = (k << 15) | (k >> (32 - 15));
            k *= c2;
            h ^= k;
    };

    h ^= nbytes;

    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}
