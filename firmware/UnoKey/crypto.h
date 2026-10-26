// Crypto helpers for UnoKey, built on BearSSL (ArduinoBearSSL library).
#pragma once
#include <stdint.h>
#include <stddef.h>

// Random numbers: HMAC-DRBG seeded from on-chip noise plus a seed carried
// over from the previous boot. More entropy is mixed in as it shows up.
void cryptoBegin(const uint8_t carriedSeed[32]);
void rngAddEntropy(const void *data, size_t n);
void rngAddTiming();  // mixes in the cycle counter at an unpredictable moment
void rngBytes(void *out, size_t n);

void sha256(const void *data, size_t n, uint8_t out[32]);
void sha256Two(const void *a, size_t an, const void *b, size_t bn, uint8_t out[32]);
void hmacSha256(const uint8_t *key, size_t keyLen, const void *data, size_t n, uint8_t out[32]);
void hmacSha256Two(const uint8_t *key, size_t keyLen, const void *a, size_t an,
                   const void *b, size_t bn, uint8_t out[32]);
void hmacSha1(const uint8_t *key, size_t keyLen, const void *data, size_t n, uint8_t out[20]);
void hkdfSha256(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen,
                const char *info, uint8_t *out, size_t outLen);
void pbkdf2Sha256(const uint8_t *pw, size_t pwLen, const uint8_t *salt, size_t saltLen,
                  uint32_t iterations, uint8_t out[32]);

// AES-256-CBC with an all-zero IV (CTAP2 PIN protocol 1). len % 16 == 0.
void aes256CbcEncrypt(const uint8_t key[32], uint8_t *buf, size_t len);
void aes256CbcDecrypt(const uint8_t key[32], uint8_t *buf, size_t len);

// ChaCha20-Poly1305 in place.
void aeadSeal(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t len,
              const uint8_t *aad, size_t aadLen, uint8_t tag[16]);
bool aeadOpen(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t len,
              const uint8_t *aad, size_t aadLen, const uint8_t tag[16]);

// NIST P-256.
bool p256ScalarValid(const uint8_t k[32]);
bool p256PublicKey(const uint8_t priv[32], uint8_t x[32], uint8_t y[32]);
void p256NewKey(uint8_t priv[32], uint8_t x[32], uint8_t y[32]);
size_t p256SignDer(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[72]);
bool p256Ecdh(const uint8_t priv[32], const uint8_t peerX[32], const uint8_t peerY[32],
              uint8_t sharedX[32]);

bool ctEqual(const void *a, const void *b, size_t n);
void secureZero(void *p, size_t n);
uint32_t crc32(const void *data, size_t n, uint32_t crc = 0);
