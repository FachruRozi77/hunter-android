#ifndef FASTRANDOM_H
#define FASTRANDOM_H

#include <cstdint>

struct alignas(64) FastRandom {
    uint64_t s[4];
    explicit FastRandom(uint64_t seed = 1);
    static uint64_t splitmix64(uint64_t* x);
    inline uint64_t rotl(uint64_t x, int k);
    // FIX: Removed 'inline' — definition is in FastRandom.cpp, not a header.
    // 'inline' with -flto causes undefined symbol when called from other TUs.
    uint64_t next();
};

#endif // FASTRANDOM_H
