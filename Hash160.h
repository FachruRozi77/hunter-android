#ifndef HASH160_H
#define HASH160_H

#include <openssl/evp.h>
#include <cstdint>

class Hash160 {
private:
    EVP_MD_CTX* sha_ctx;
    EVP_MD_CTX* ripemd_ctx;

public:
    Hash160();
    ~Hash160();

    // Single key
    void compute(const uint8_t pubKey[33], uint8_t out[20]);

    // Batch - exactly one implementation
    void computeBatch(const uint8_t pubKeys[][33], uint8_t out[][20], int n);
};

#endif // HASH160_H