#include "Hash160.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>

Hash160::Hash160() {
    sha_ctx = EVP_MD_CTX_new();
    ripemd_ctx = EVP_MD_CTX_new();
}

Hash160::~Hash160() {
    EVP_MD_CTX_free(sha_ctx);
    EVP_MD_CTX_free(ripemd_ctx);
}

void Hash160::compute(const uint8_t pubKey[33], uint8_t out[20]) {
    unsigned int sha_len = SHA256_DIGEST_LENGTH;
    unsigned int ripemd_len = RIPEMD160_DIGEST_LENGTH;
    uint8_t sha_result[SHA256_DIGEST_LENGTH];

    EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha_ctx, pubKey, 33);
    EVP_DigestFinal_ex(sha_ctx, sha_result, &sha_len);

    EVP_DigestInit_ex(ripemd_ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ripemd_ctx, sha_result, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ripemd_ctx, out, &ripemd_len);
}

void Hash160::computeBatch(const uint8_t pubKeys[][33], uint8_t out[][20], int n) {
    for (int i = 0; i < n; ++i) {
        compute(pubKeys[i], out[i]);
    }
}