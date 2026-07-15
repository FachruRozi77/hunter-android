#include "FastRandom.h"

FastRandom::FastRandom(uint64_t seed) {
    uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
    s[0] = splitmix64(&z); s[1] = splitmix64(&z);
    s[2] = splitmix64(&z); s[3] = splitmix64(&z);
    for(int i = 0; i < 20; i++) next();
}

uint64_t FastRandom::splitmix64(uint64_t* x) {
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

inline uint64_t FastRandom::rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

inline uint64_t FastRandom::next() {
    const uint64_t result = rotl(s[1] * 5, 7) * 9;
    const uint64_t t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t; s[3] = rotl(s[3], 45);
    return result;
}