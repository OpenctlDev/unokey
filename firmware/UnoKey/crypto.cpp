#include "crypto.h"
#include <Arduino.h>
#include <ArduinoBearSSL.h>
#include "bearssl/bearssl.h"
#include <string.h>

static br_hmac_drbg_context drbg;
static const br_ec_impl *const EC = &br_ec_p256_m31;

// P-256 group order n, big-endian.
static const uint8_t P256_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

// ---------------------------------------------------------------- entropy

static void enableCycleCounter() {
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

// Samples ADC noise and clock jitter into a SHA-256 pool. Each reading
// carries little entropy on its own, so we take a lot of them.
static void collectEntropy(br_sha256_context &pool) {
  static const uint8_t pins[] = {A0, A1, A2, A3, A4, A5};
  analogReadResolution(14);
  for (int round = 0; round < 96; round++) {
    for (uint8_t i = 0; i < sizeof(pins); i++) {
      uint32_t sample[2];
      sample[0] = (uint32_t)analogRead(pins[i]);
      sample[1] = DWT->CYCCNT;
      br_sha256_update(&pool, sample, sizeof(sample));
    }
  }
  analogReadResolution(10);
  const bsp_unique_id_t *uid = R_BSP_UniqueIdGet();
  br_sha256_update(&pool, uid, sizeof(*uid));
  uint32_t t[2] = {micros(), DWT->CYCCNT};
  br_sha256_update(&pool, t, sizeof(t));
}

void cryptoBegin(const uint8_t carriedSeed[32]) {
  enableCycleCounter();
  br_sha256_context pool;
  br_sha256_init(&pool);
  collectEntropy(pool);
  uint8_t seed[64];
  br_sha256_out(&pool, seed);
  memcpy(seed + 32, carriedSeed, 32);
  br_hmac_drbg_init(&drbg, &br_sha256_vtable, seed, sizeof(seed));
  secureZero(seed, sizeof(seed));
}

void rngAddEntropy(const void *data, size_t n) { br_hmac_drbg_update(&drbg, data, n); }

void rngAddTiming() {
  uint32_t t[2] = {DWT->CYCCNT, micros()};
  br_hmac_drbg_update(&drbg, t, sizeof(t));
}

void rngBytes(void *out, size_t n) { br_hmac_drbg_generate(&drbg, out, n); }

// ---------------------------------------------------------------- hashes

void sha256(const void *data, size_t n, uint8_t out[32]) {
  br_sha256_context c;
  br_sha256_init(&c);
  br_sha256_update(&c, data, n);
  br_sha256_out(&c, out);
}

void sha256Two(const void *a, size_t an, const void *b, size_t bn, uint8_t out[32]) {
  br_sha256_context c;
  br_sha256_init(&c);
  br_sha256_update(&c, a, an);
  br_sha256_update(&c, b, bn);
  br_sha256_out(&c, out);
}

void hmacSha256Two(const uint8_t *key, size_t keyLen, const void *a, size_t an,
                   const void *b, size_t bn, uint8_t out[32]) {
  br_hmac_key_context kc;
  br_hmac_context hc;
  br_hmac_key_init(&kc, &br_sha256_vtable, key, keyLen);
  br_hmac_init(&hc, &kc, 0);
  br_hmac_update(&hc, a, an);
  if (bn) br_hmac_update(&hc, b, bn);
  br_hmac_out(&hc, out);
}

void hmacSha256(const uint8_t *key, size_t keyLen, const void *data, size_t n, uint8_t out[32]) {
  hmacSha256Two(key, keyLen, data, n, nullptr, 0, out);
}

void hmacSha1(const uint8_t *key, size_t keyLen, const void *data, size_t n, uint8_t out[20]) {
  br_hmac_key_context kc;
  br_hmac_context hc;
  br_hmac_key_init(&kc, &br_sha1_vtable, key, keyLen);
  br_hmac_init(&hc, &kc, 0);
  br_hmac_update(&hc, data, n);
  br_hmac_out(&hc, out);
}

void hkdfSha256(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen,
                const char *info, uint8_t *out, size_t outLen) {
  br_hkdf_context hc;
  br_hkdf_init(&hc, &br_sha256_vtable, salt, saltLen);
  br_hkdf_inject(&hc, ikm, ikmLen);
  br_hkdf_flip(&hc);
  br_hkdf_produce(&hc, info, strlen(info), out, outLen);
}

void pbkdf2Sha256(const uint8_t *pw, size_t pwLen, const uint8_t *salt, size_t saltLen,
                  uint32_t iterations, uint8_t out[32]) {
  br_hmac_key_context kc;
  br_hmac_context hc;
  uint8_t u[32];
  static const uint8_t blockIndex[4] = {0, 0, 0, 1};
  br_hmac_key_init(&kc, &br_sha256_vtable, pw, pwLen);
  br_hmac_init(&hc, &kc, 0);
  br_hmac_update(&hc, salt, saltLen);
  br_hmac_update(&hc, blockIndex, sizeof(blockIndex));
  br_hmac_out(&hc, u);
  memcpy(out, u, 32);
  for (uint32_t i = 1; i < iterations; i++) {
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, u, 32);
    br_hmac_out(&hc, u);
    for (int j = 0; j < 32; j++) out[j] ^= u[j];
  }
  secureZero(u, sizeof(u));
}

// ---------------------------------------------------------------- ciphers

void aes256CbcEncrypt(const uint8_t key[32], uint8_t *buf, size_t len) {
  br_aes_ct_cbcenc_keys k;
  uint8_t iv[16] = {0};
  br_aes_ct_cbcenc_init(&k, key, 32);
  br_aes_ct_cbcenc_run(&k, iv, buf, len);
  secureZero(&k, sizeof(k));
}

void aes256CbcDecrypt(const uint8_t key[32], uint8_t *buf, size_t len) {
  br_aes_ct_cbcdec_keys k;
  uint8_t iv[16] = {0};
  br_aes_ct_cbcdec_init(&k, key, 32);
  br_aes_ct_cbcdec_run(&k, iv, buf, len);
  secureZero(&k, sizeof(k));
}

void aeadSeal(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t len,
              const uint8_t *aad, size_t aadLen, uint8_t tag[16]) {
  br_poly1305_ctmul_run(key, nonce, buf, len, aad, aadLen, tag, br_chacha20_ct_run, 1);
}

bool aeadOpen(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t len,
              const uint8_t *aad, size_t aadLen, const uint8_t tag[16]) {
  uint8_t calc[16];
  br_poly1305_ctmul_run(key, nonce, buf, len, aad, aadLen, calc, br_chacha20_ct_run, 0);
  if (ctEqual(calc, tag, 16)) return true;
  // Wrong key or tampered data: put the ciphertext back and report failure.
  br_poly1305_ctmul_run(key, nonce, buf, len, aad, aadLen, calc, br_chacha20_ct_run, 1);
  return false;
}

// ---------------------------------------------------------------- P-256

bool p256ScalarValid(const uint8_t k[32]) {
  bool nonzero = false;
  for (int i = 0; i < 32; i++) nonzero |= k[i] != 0;
  if (!nonzero) return false;
  for (int i = 0; i < 32; i++) {
    if (k[i] < P256_N[i]) return true;
    if (k[i] > P256_N[i]) return false;
  }
  return false;  // equal to n
}

bool p256PublicKey(const uint8_t priv[32], uint8_t x[32], uint8_t y[32]) {
  uint8_t point[65];
  if (EC->mulgen(point, priv, 32, BR_EC_secp256r1) != 65) return false;
  memcpy(x, point + 1, 32);
  memcpy(y, point + 33, 32);
  return true;
}

void p256NewKey(uint8_t priv[32], uint8_t x[32], uint8_t y[32]) {
  do {
    rngBytes(priv, 32);
  } while (!p256ScalarValid(priv) || !p256PublicKey(priv, x, y));
}

size_t p256SignDer(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[72]) {
  br_ec_private_key sk;
  sk.curve = BR_EC_secp256r1;
  sk.x = (unsigned char *)priv;
  sk.xlen = 32;
  return br_ecdsa_i31_sign_asn1(EC, &br_sha256_vtable, hash, &sk, sig);
}

bool p256Ecdh(const uint8_t priv[32], const uint8_t peerX[32], const uint8_t peerY[32],
              uint8_t sharedX[32]) {
  uint8_t point[65];
  point[0] = 0x04;
  memcpy(point + 1, peerX, 32);
  memcpy(point + 33, peerY, 32);
  if (!EC->mul(point, sizeof(point), priv, 32, BR_EC_secp256r1)) return false;
  memcpy(sharedX, point + 1, 32);
  secureZero(point, sizeof(point));
  return true;
}

// ---------------------------------------------------------------- misc

bool ctEqual(const void *a, const void *b, size_t n) {
  const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= x[i] ^ y[i];
  return d == 0;
}

void secureZero(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}

uint32_t crc32(const void *data, size_t n, uint32_t crc) {
  const uint8_t *p = (const uint8_t *)data;
  crc = ~crc;
  while (n--) {
    crc ^= *p++;
    for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}
