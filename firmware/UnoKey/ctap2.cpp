#include "ctap2.h"
#include "cbor.h"
#include "config.h"
#include "crypto.h"
#include "passkeys.h"
#include "storage.h"
#include "ui.h"
#include <Arduino.h>
#include <string.h>

enum : uint8_t {
  CMD_MAKE_CREDENTIAL = 0x01,
  CMD_GET_ASSERTION = 0x02,
  CMD_GET_INFO = 0x04,
  CMD_CLIENT_PIN = 0x06,
  CMD_RESET = 0x07,
  CMD_GET_NEXT_ASSERTION = 0x08,
};

enum : uint8_t {
  ST_OK = 0x00,
  ST_INVALID_COMMAND = 0x01,
  ST_INVALID_PARAMETER = 0x02,
  ST_INVALID_LENGTH = 0x03,
  ST_CBOR_UNEXPECTED_TYPE = 0x11,
  ST_INVALID_CBOR = 0x12,
  ST_MISSING_PARAMETER = 0x14,
  ST_CREDENTIAL_EXCLUDED = 0x19,
  ST_UNSUPPORTED_ALGORITHM = 0x26,
  ST_OPERATION_DENIED = 0x27,
  ST_KEY_STORE_FULL = 0x28,
  ST_UNSUPPORTED_OPTION = 0x2B,
  ST_INVALID_OPTION = 0x2C,
  ST_KEEPALIVE_CANCEL = 0x2D,
  ST_NO_CREDENTIALS = 0x2E,
  ST_USER_ACTION_TIMEOUT = 0x2F,
  ST_NOT_ALLOWED = 0x30,
  ST_PIN_INVALID = 0x31,
  ST_PIN_BLOCKED = 0x32,
  ST_PIN_AUTH_INVALID = 0x33,
  ST_PIN_AUTH_BLOCKED = 0x34,
  ST_PIN_NOT_SET = 0x35,
  ST_PIN_REQUIRED = 0x36,
  ST_PIN_POLICY_VIOLATION = 0x37,
  ST_OTHER = 0x7F,
};

static const uint8_t FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_AT = 0x40, FLAG_ED = 0x80;
static const int64_t ALG_ES256 = -7;
static const int64_t ALG_ECDH_ES_HKDF_256 = -25;

// Credential IDs: version | flags | nonce[16] | mac[16]
// flags bit 0 = discoverable, bits 1-2 = credProtect level.
static const uint8_t CRED_ID_VERSION = 0xA5;

static uint8_t credMacKey[32], credKeyKey[32];
static bool fidoKeysReady;

static uint8_t kaPriv[32], kaX[32], kaY[32];  // PIN protocol key agreement
static uint8_t pinToken[32];
static uint8_t pinMismatchesThisBoot;
static uint32_t counter;

static struct {
  bool active;
  uint32_t lastMs;
  uint8_t rpIdHash[32];
  uint8_t clientDataHash[32];
  uint8_t flags;
  uint8_t slots[PASSKEY_SLOTS];
  uint8_t count;
  uint8_t next;
} nextAssertion;

// ---------------------------------------------------------------- helpers

static void deriveFidoKeys() {
  hkdfSha256(nullptr, 0, g_cfg.fidoSecret, 32, "unokey cred mac", credMacKey, 32);
  hkdfSha256(nullptr, 0, g_cfg.fidoSecret, 32, "unokey cred key", credKeyKey, 32);
  fidoKeysReady = true;
}

// The FIDO secret is created on first use, so by then the RNG has also
// absorbed USB timing and request data.
static bool ensureFidoSecret() {
  if (!g_cfg.fidoReady) {
    rngAddTiming();
    rngBytes(g_cfg.fidoSecret, 32);
    g_cfg.fidoReady = 1;
    if (!configSave()) {
      g_cfg.fidoReady = 0;
      return false;
    }
  }
  if (!fidoKeysReady) deriveFidoKeys();
  return true;
}

static void newPinToken() { rngBytes(pinToken, sizeof(pinToken)); }

static void newKeyAgreement() { p256NewKey(kaPriv, kaX, kaY); }

static void credMac(const uint8_t rpIdHash[32], const uint8_t *idHead, uint8_t out[16]) {
  uint8_t full[32];
  hmacSha256Two(credMacKey, 32, rpIdHash, 32, idHead, 18, full);
  memcpy(out, full, 16);
}

static void makeCredId(const uint8_t rpIdHash[32], uint8_t flags, const uint8_t nonce[16],
                       uint8_t id[CRED_ID_LEN]) {
  id[0] = CRED_ID_VERSION;
  id[1] = flags;
  memcpy(id + 2, nonce, 16);
  credMac(rpIdHash, id, id + 18);
}

// Checks that a credential ID was made by this key for this RP.
static bool parseCredId(const uint8_t rpIdHash[32], const uint8_t *id, size_t len, uint8_t &flags,
                        const uint8_t *&nonce) {
  if (!fidoKeysReady || len != CRED_ID_LEN || id[0] != CRED_ID_VERSION) return false;
  uint8_t mac[16];
  credMac(rpIdHash, id, mac);
  if (!ctEqual(mac, id + 18, 16)) return false;
  flags = id[1];
  nonce = id + 2;
  return true;
}

static void credPrivateKey(const uint8_t rpIdHash[32], const uint8_t nonce[16], uint8_t priv[32]) {
  uint8_t in[49];
  memcpy(in, rpIdHash, 32);
  memcpy(in + 32, nonce, 16);
  for (uint8_t i = 0;; i++) {
    in[48] = i;
    hmacSha256(credKeyKey, 32, in, sizeof(in), priv);
    if (p256ScalarValid(priv)) break;
  }
}

static uint32_t nextCounter() {
  counter++;
  // Persist in steps of 32 to spare the flash; after a reboot we resume
  // from the stored bound, so the counter never goes backwards.
  if (counter >= g_cfg.signCounter) {
    g_cfg.signCounter = counter + 32;
    configSave();
  }
  return counter;
}

static void putBe32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void putCoseKey(CborWriter &w, const uint8_t x[32], const uint8_t y[32], int64_t alg) {
  cborPutMap(w, 5);
  cborPutInt(w, 1);
  cborPutInt(w, 2);  // kty: EC2
  cborPutInt(w, 3);
  cborPutInt(w, alg);
  cborPutInt(w, -1);
  cborPutInt(w, 1);  // crv: P-256
  cborPutInt(w, -2);
  cborPutBytes(w, x, 32);
  cborPutInt(w, -3);
  cborPutBytes(w, y, 32);
}

// Reads a COSE EC2 public key (as sent by the platform for PIN protocol 1).
static bool readCoseKey(CborReader &r, uint8_t x[32], uint8_t y[32]) {
  size_t n;
  if (!cborGetMap(r, n)) return false;
  bool haveX = false, haveY = false;
  for (size_t i = 0; i < n; i++) {
    int64_t key;
    if (!cborGetInt(r, key)) return false;
    if (key == -2 || key == -3) {
      const uint8_t *b;
      size_t bl;
      if (!cborGetBytes(r, b, bl) || bl != 32) return false;
      memcpy(key == -2 ? x : y, b, 32);
      (key == -2 ? haveX : haveY) = true;
    } else if (!cborSkip(r)) {
      return false;
    }
  }
  return haveX && haveY;
}

static bool readCredDescriptor(CborReader &r, const uint8_t *&id, size_t &idLen, bool &isPublicKey) {
  size_t n;
  if (!cborGetMap(r, n)) return false;
  id = nullptr;
  idLen = 0;
  isPublicKey = false;
  for (size_t i = 0; i < n; i++) {
    const char *k;
    size_t kl;
    if (!cborGetText(r, k, kl)) return false;
    if (cborTextEquals(k, kl, "id")) {
      if (!cborGetBytes(r, id, idLen)) return false;
    } else if (cborTextEquals(k, kl, "type")) {
      const char *t;
      size_t tl;
      if (!cborGetText(r, t, tl)) return false;
      isPublicKey = cborTextEquals(t, tl, "public-key");
    } else if (!cborSkip(r)) {
      return false;
    }
  }
  return id != nullptr;
}

// Reads a map of option names to booleans; unknown options are ignored.
struct Options {
  bool hasRk, rk, hasUv, uv, hasUp, up;
};

static bool readOptions(CborReader &r, Options &o) {
  size_t n;
  if (!cborGetMap(r, n)) return false;
  for (size_t i = 0; i < n; i++) {
    const char *k;
    size_t kl;
    bool v;
    if (!cborGetText(r, k, kl)) return false;
    if (cborPeekMajor(r) != CBOR_SIMPLE) {
      if (!cborSkip(r)) return false;
      continue;
    }
    if (!cborGetBool(r, v)) return false;
    if (cborTextEquals(k, kl, "rk")) o.hasRk = true, o.rk = v;
    else if (cborTextEquals(k, kl, "uv")) o.hasUv = true, o.uv = v;
    else if (cborTextEquals(k, kl, "up")) o.hasUp = true, o.up = v;
  }
  return true;
}

static void rpLabel(const char *rpId, size_t len, char *out, size_t cap) {
  size_t n = len < cap - 1 ? len : cap - 1;
  memcpy(out, rpId, n);
  out[n] = 0;
}

static uint8_t askPresence(const char *title, const char *detail) {
  switch (uiConfirm(title, detail, UP_TIMEOUT_MS)) {
    case UI_APPROVED: return ST_OK;
    case UI_DENIED: return ST_OPERATION_DENIED;
    case UI_CANCELLED: return ST_KEEPALIVE_CANCEL;
    default: return ST_USER_ACTION_TIMEOUT;
  }
}

static bool pinAuthValid(const uint8_t *pinAuth, size_t len, const uint8_t clientDataHash[32]) {
  if (len != 16) return false;
  uint8_t mac[32];
  hmacSha256(pinToken, sizeof(pinToken), clientDataHash, 32, mac);
  return ctEqual(mac, pinAuth, 16);
}

// ---------------------------------------------------------------- getInfo

static uint8_t getInfo(CborWriter &w) {
  cborPutMap(w, 10);
  cborPutUint(w, 0x01);
  cborPutArray(w, 1);
  cborPutText(w, "FIDO_2_0");
  cborPutUint(w, 0x02);
  cborPutArray(w, 1);
  cborPutText(w, "credProtect");
  cborPutUint(w, 0x03);
  cborPutBytes(w, UNOKEY_AAGUID, 16);
  cborPutUint(w, 0x04);
  cborPutMap(w, 4);
  cborPutText(w, "rk");
  cborPutBool(w, true);
  cborPutText(w, "up");
  cborPutBool(w, true);
  cborPutText(w, "plat");
  cborPutBool(w, false);
  cborPutText(w, "clientPin");
  cborPutBool(w, g_cfg.fidoPinSet != 0);
  cborPutUint(w, 0x05);
  cborPutUint(w, CTAP_MAX_MSG);
  cborPutUint(w, 0x06);
  cborPutArray(w, 1);
  cborPutUint(w, 1);
  cborPutUint(w, 0x07);
  cborPutUint(w, CTAP_MAX_CRED_IN_LIST);
  cborPutUint(w, 0x08);
  cborPutUint(w, CRED_ID_LEN);
  cborPutUint(w, 0x09);
  cborPutArray(w, 1);
  cborPutText(w, "usb");
  cborPutUint(w, 0x0A);
  cborPutArray(w, 1);
  cborPutMap(w, 2);
  cborPutText(w, "alg");
  cborPutInt(w, ALG_ES256);
  cborPutText(w, "type");
  cborPutText(w, "public-key");
  return ST_OK;
}

// ---------------------------------------------------------------- makeCredential

static uint8_t makeCredential(CborReader &r, CborWriter &w) {
  size_t n;
  if (!cborGetMap(r, n)) return ST_INVALID_CBOR;
  const uint8_t *cdh = nullptr, *userId = nullptr, *pinAuth = nullptr, *excl = nullptr;
  size_t cdhLen = 0, userIdLen = 0, pinAuthLen = 0, exclLen = 0;
  const char *rpId = nullptr, *userName = nullptr, *displayName = nullptr;
  size_t rpIdLen = 0, userNameLen = 0, displayNameLen = 0;
  bool haveParams = false, es256 = false, havePinAuth = false;
  uint64_t pinProtocol = 0, credProtect = 0;
  Options opt = {};

  for (size_t i = 0; i < n; i++) {
    uint64_t key;
    if (!cborGetUint(r, key)) return ST_INVALID_CBOR;
    switch (key) {
      case 1:
        if (!cborGetBytes(r, cdh, cdhLen)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 2: {
        size_t m;
        if (!cborGetMap(r, m)) return ST_CBOR_UNEXPECTED_TYPE;
        for (size_t j = 0; j < m; j++) {
          const char *k;
          size_t kl;
          if (!cborGetText(r, k, kl)) return ST_INVALID_CBOR;
          if (cborTextEquals(k, kl, "id")) {
            if (!cborGetText(r, rpId, rpIdLen)) return ST_CBOR_UNEXPECTED_TYPE;
          } else if (!cborSkip(r)) {
            return ST_INVALID_CBOR;
          }
        }
        break;
      }
      case 3: {
        size_t m;
        if (!cborGetMap(r, m)) return ST_CBOR_UNEXPECTED_TYPE;
        for (size_t j = 0; j < m; j++) {
          const char *k;
          size_t kl;
          if (!cborGetText(r, k, kl)) return ST_INVALID_CBOR;
          if (cborTextEquals(k, kl, "id")) {
            if (!cborGetBytes(r, userId, userIdLen)) return ST_CBOR_UNEXPECTED_TYPE;
          } else if (cborTextEquals(k, kl, "name")) {
            if (!cborGetText(r, userName, userNameLen)) return ST_CBOR_UNEXPECTED_TYPE;
          } else if (cborTextEquals(k, kl, "displayName")) {
            if (!cborGetText(r, displayName, displayNameLen)) return ST_CBOR_UNEXPECTED_TYPE;
          } else if (!cborSkip(r)) {
            return ST_INVALID_CBOR;
          }
        }
        break;
      }
      case 4: {
        size_t m;
        if (!cborGetArray(r, m)) return ST_CBOR_UNEXPECTED_TYPE;
        for (size_t j = 0; j < m; j++) {
          size_t mm;
          if (!cborGetMap(r, mm)) return ST_CBOR_UNEXPECTED_TYPE;
          int64_t alg = 0;
          bool isPk = false;
          for (size_t k2 = 0; k2 < mm; k2++) {
            const char *k;
            size_t kl;
            if (!cborGetText(r, k, kl)) return ST_INVALID_CBOR;
            if (cborTextEquals(k, kl, "alg")) {
              if (!cborGetInt(r, alg)) return ST_CBOR_UNEXPECTED_TYPE;
            } else if (cborTextEquals(k, kl, "type")) {
              const char *t;
              size_t tl;
              if (!cborGetText(r, t, tl)) return ST_CBOR_UNEXPECTED_TYPE;
              isPk = cborTextEquals(t, tl, "public-key");
            } else if (!cborSkip(r)) {
              return ST_INVALID_CBOR;
            }
          }
          if (isPk && alg == ALG_ES256) es256 = true;
        }
        haveParams = true;
        break;
      }
      case 5:
        if (cborPeekMajor(r) != CBOR_ARRAY) return ST_CBOR_UNEXPECTED_TYPE;
        if (!cborCapture(r, excl, exclLen)) return ST_INVALID_CBOR;
        break;
      case 6: {
        size_t m;
        if (!cborGetMap(r, m)) return ST_CBOR_UNEXPECTED_TYPE;
        for (size_t j = 0; j < m; j++) {
          const char *k;
          size_t kl;
          if (!cborGetText(r, k, kl)) return ST_INVALID_CBOR;
          if (cborTextEquals(k, kl, "credProtect") && cborPeekMajor(r) == CBOR_UINT) {
            uint64_t v;
            cborGetUint(r, v);
            if (v >= 1 && v <= 3) credProtect = v;
          } else if (!cborSkip(r)) {
            return ST_INVALID_CBOR;
          }
        }
        break;
      }
      case 7:
        if (!readOptions(r, opt)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 8:
        if (!cborGetBytes(r, pinAuth, pinAuthLen)) return ST_CBOR_UNEXPECTED_TYPE;
        havePinAuth = true;
        break;
      case 9:
        if (!cborGetUint(r, pinProtocol)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      default:
        if (!cborSkip(r)) return ST_INVALID_CBOR;
        break;
    }
  }
  if (!cdh || !rpId || !userId || !haveParams) return ST_MISSING_PARAMETER;
  if (cdhLen != 32 || userIdLen == 0 || userIdLen > 64) return ST_INVALID_LENGTH;

  char label[48];
  rpLabel(rpId, rpIdLen, label, sizeof(label));

  // An empty pinAuth means "touch the key you want to use".
  if (havePinAuth && pinAuthLen == 0) {
    uint8_t st = askPresence("SELECT", label);
    if (st != ST_OK) return st;
    return g_cfg.fidoPinSet ? ST_PIN_INVALID : ST_PIN_NOT_SET;
  }
  bool uv = false;
  if (havePinAuth) {
    if (pinProtocol != 1 || !pinAuthValid(pinAuth, pinAuthLen, cdh)) return ST_PIN_AUTH_INVALID;
    uv = true;
  } else if (g_cfg.fidoPinSet) {
    return ST_PIN_REQUIRED;
  }
  if (!es256) return ST_UNSUPPORTED_ALGORITHM;
  if (opt.hasUv && opt.uv) return ST_UNSUPPORTED_OPTION;
  if (opt.hasUp && !opt.up) return ST_INVALID_OPTION;
  const bool rk = opt.hasRk && opt.rk;

  if (!ensureFidoSecret()) return ST_OTHER;
  uint8_t rpIdHash[32];
  sha256(rpId, rpIdLen, rpIdHash);

  if (excl) {
    CborReader er;
    cborReaderInit(er, excl, exclLen);
    size_t m;
    if (!cborGetArray(er, m)) return ST_INVALID_CBOR;
    for (size_t j = 0; j < m; j++) {
      const uint8_t *id;
      size_t idLen;
      bool isPk;
      uint8_t f;
      const uint8_t *nonce;
      if (!readCredDescriptor(er, id, idLen, isPk)) return ST_INVALID_CBOR;
      if (!isPk || !parseCredId(rpIdHash, id, idLen, f, nonce)) continue;
      if ((f & 1) && passkeyFindNonce(rpIdHash, nonce) < 0) continue;  // passkey was deleted
      uint8_t st = askPresence("ALREADY SAVED", label);
      return st != ST_OK ? st : (uint8_t)ST_CREDENTIAL_EXCLUDED;
    }
  }

  if (rk && passkeyFindUser(rpIdHash, userId, userIdLen) < 0 && passkeyCount() >= PASSKEY_SLOTS)
    return ST_KEY_STORE_FULL;

  uint8_t st = askPresence(rk ? "SAVE PASSKEY" : "REGISTER", label);
  if (st != ST_OK) return st;

  rngAddTiming();
  uint8_t nonce[16];
  rngBytes(nonce, sizeof(nonce));
  const uint8_t level = credProtect ? (uint8_t)credProtect : 1;
  uint8_t credId[CRED_ID_LEN];
  makeCredId(rpIdHash, (uint8_t)((rk ? 1 : 0) | (level << 1)), nonce, credId);

  if (rk) {
    PasskeyRecord rec;
    memset(&rec, 0, sizeof(rec));
    rec.used = PASSKEY_USED;
    rec.credProtect = level;
    rec.seq = ++g_cfg.passkeySeq;
    memcpy(rec.nonce, nonce, 16);
    memcpy(rec.rpIdHash, rpIdHash, 32);
    rec.userIdLen = (uint8_t)userIdLen;
    memcpy(rec.userId, userId, userIdLen);
    rec.rpIdLen = (uint8_t)utf8Fit(rpId, rpIdLen, sizeof(rec.rpId));
    memcpy(rec.rpId, rpId, rec.rpIdLen);
    if (userName) {
      rec.userNameLen = (uint8_t)utf8Fit(userName, userNameLen, sizeof(rec.userName));
      memcpy(rec.userName, userName, rec.userNameLen);
    }
    if (displayName) {
      rec.displayNameLen = (uint8_t)utf8Fit(displayName, displayNameLen, sizeof(rec.displayName));
      memcpy(rec.displayName, displayName, rec.displayNameLen);
    }
    if (passkeyStore(rec) < 0) return ST_KEY_STORE_FULL;
    configSave();  // keeps passkeySeq
  }

  uint8_t priv[32], x[32], y[32];
  credPrivateKey(rpIdHash, nonce, priv);
  if (!p256PublicKey(priv, x, y)) return ST_OTHER;

  uint8_t authData[200];
  size_t ad = 0;
  memcpy(authData, rpIdHash, 32);
  ad += 32;
  authData[ad++] = (uint8_t)(FLAG_UP | (uv ? FLAG_UV : 0) | FLAG_AT | (credProtect ? FLAG_ED : 0));
  putBe32(authData + ad, nextCounter());
  ad += 4;
  memcpy(authData + ad, UNOKEY_AAGUID, 16);
  ad += 16;
  authData[ad++] = 0;
  authData[ad++] = (uint8_t)CRED_ID_LEN;
  memcpy(authData + ad, credId, CRED_ID_LEN);
  ad += CRED_ID_LEN;
  CborWriter kw;
  cborWriterInit(kw, authData + ad, sizeof(authData) - ad);
  putCoseKey(kw, x, y, ALG_ES256);
  if (credProtect) {
    cborPutMap(kw, 1);
    cborPutText(kw, "credProtect");
    cborPutUint(kw, credProtect);
  }
  if (kw.overflow) return ST_OTHER;
  ad += kw.len;

  // Packed self-attestation: signed with the new credential's own key.
  uint8_t hash[32], sig[72];
  sha256Two(authData, ad, cdh, 32, hash);
  const size_t sigLen = p256SignDer(priv, hash, sig);
  secureZero(priv, sizeof(priv));
  if (!sigLen) return ST_OTHER;

  cborPutMap(w, 3);
  cborPutUint(w, 1);
  cborPutText(w, "packed");
  cborPutUint(w, 2);
  cborPutBytes(w, authData, ad);
  cborPutUint(w, 3);
  cborPutMap(w, 2);
  cborPutText(w, "alg");
  cborPutInt(w, ALG_ES256);
  cborPutText(w, "sig");
  cborPutBytes(w, sig, sigLen);
  return ST_OK;
}

// ---------------------------------------------------------------- getAssertion

// Signs for one credential and writes the response map.
static uint8_t writeAssertion(CborWriter &w, const uint8_t rpIdHash[32], const uint8_t cdh[32],
                              uint8_t flags, const uint8_t credId[CRED_ID_LEN], int slot,
                              uint8_t total) {
  PasskeyRecord rec;
  const bool resident = slot >= 0 && passkeyRead((uint8_t)slot, rec);
  uint8_t priv[32];
  credPrivateKey(rpIdHash, credId + 2, priv);

  uint8_t authData[37];
  memcpy(authData, rpIdHash, 32);
  authData[32] = flags;
  putBe32(authData + 33, nextCounter());
  uint8_t hash[32], sig[72];
  sha256Two(authData, sizeof(authData), cdh, 32, hash);
  const size_t sigLen = p256SignDer(priv, hash, sig);
  secureZero(priv, sizeof(priv));
  if (!sigLen) return ST_OTHER;

  cborPutMap(w, 3 + (resident ? 1 : 0) + (total > 1 ? 1 : 0));
  cborPutUint(w, 1);
  cborPutMap(w, 2);
  cborPutText(w, "id");
  cborPutBytes(w, credId, CRED_ID_LEN);
  cborPutText(w, "type");
  cborPutText(w, "public-key");
  cborPutUint(w, 2);
  cborPutBytes(w, authData, sizeof(authData));
  cborPutUint(w, 3);
  cborPutBytes(w, sig, sigLen);
  if (resident) {
    // Names only go out after user verification (CTAP2 privacy rule).
    const bool names = (flags & FLAG_UV) != 0;
    const bool withName = names && rec.userNameLen;
    const bool withDisplay = names && rec.displayNameLen;
    cborPutUint(w, 4);
    cborPutMap(w, 1 + (withName ? 1 : 0) + (withDisplay ? 1 : 0));
    cborPutText(w, "id");
    cborPutBytes(w, rec.userId, rec.userIdLen);
    if (withName) {
      cborPutText(w, "name");
      cborPutText(w, rec.userName, rec.userNameLen);
    }
    if (withDisplay) {
      cborPutText(w, "displayName");
      cborPutText(w, rec.displayName, rec.displayNameLen);
    }
  }
  if (total > 1) {
    cborPutUint(w, 5);
    cborPutUint(w, total);
  }
  return ST_OK;
}

static uint8_t assertionForSlot(CborWriter &w, const uint8_t rpIdHash[32], const uint8_t cdh[32],
                                uint8_t flags, uint8_t slot, uint8_t total) {
  PasskeyRecord rec;
  if (!passkeyRead(slot, rec)) return ST_NO_CREDENTIALS;
  uint8_t credId[CRED_ID_LEN];
  makeCredId(rpIdHash, (uint8_t)(1 | (rec.credProtect << 1)), rec.nonce, credId);
  return writeAssertion(w, rpIdHash, cdh, flags, credId, slot, total);
}

static uint8_t getAssertion(CborReader &r, CborWriter &w) {
  size_t n;
  if (!cborGetMap(r, n)) return ST_INVALID_CBOR;
  const char *rpId = nullptr;
  size_t rpIdLen = 0;
  const uint8_t *cdh = nullptr, *allow = nullptr, *pinAuth = nullptr;
  size_t cdhLen = 0, allowLen = 0, pinAuthLen = 0;
  bool havePinAuth = false;
  uint64_t pinProtocol = 0;
  Options opt = {};

  for (size_t i = 0; i < n; i++) {
    uint64_t key;
    if (!cborGetUint(r, key)) return ST_INVALID_CBOR;
    switch (key) {
      case 1:
        if (!cborGetText(r, rpId, rpIdLen)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 2:
        if (!cborGetBytes(r, cdh, cdhLen)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 3:
        if (cborPeekMajor(r) != CBOR_ARRAY) return ST_CBOR_UNEXPECTED_TYPE;
        if (!cborCapture(r, allow, allowLen)) return ST_INVALID_CBOR;
        break;
      case 5:
        if (!readOptions(r, opt)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 6:
        if (!cborGetBytes(r, pinAuth, pinAuthLen)) return ST_CBOR_UNEXPECTED_TYPE;
        havePinAuth = true;
        break;
      case 7:
        if (!cborGetUint(r, pinProtocol)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      default:  // extensions and anything unknown
        if (!cborSkip(r)) return ST_INVALID_CBOR;
        break;
    }
  }
  if (!rpId || !cdh) return ST_MISSING_PARAMETER;
  if (cdhLen != 32) return ST_INVALID_LENGTH;

  char label[48];
  rpLabel(rpId, rpIdLen, label, sizeof(label));

  if (havePinAuth && pinAuthLen == 0) {
    uint8_t st = askPresence("SELECT", label);
    if (st != ST_OK) return st;
    return g_cfg.fidoPinSet ? ST_PIN_INVALID : ST_PIN_NOT_SET;
  }
  bool uv = false;
  if (havePinAuth) {
    if (pinProtocol != 1 || !pinAuthValid(pinAuth, pinAuthLen, cdh)) return ST_PIN_AUTH_INVALID;
    uv = true;
  }
  if (opt.hasUv && opt.uv) return ST_UNSUPPORTED_OPTION;
  if (opt.hasRk) return ST_INVALID_OPTION;
  const bool up = !opt.hasUp || opt.up;

  uint8_t rpIdHash[32];
  sha256(rpId, rpIdLen, rpIdHash);
  const uint8_t flags = (uint8_t)((up ? FLAG_UP : 0) | (uv ? FLAG_UV : 0));

  if (allow) {
    CborReader ar;
    cborReaderInit(ar, allow, allowLen);
    size_t m;
    if (!cborGetArray(ar, m)) return ST_INVALID_CBOR;
    const uint8_t *chosen = nullptr;
    int chosenSlot = -1;
    for (size_t j = 0; j < m && !chosen; j++) {
      const uint8_t *id, *nonce;
      size_t idLen;
      bool isPk;
      uint8_t f;
      if (!readCredDescriptor(ar, id, idLen, isPk)) return ST_INVALID_CBOR;
      if (!isPk || !parseCredId(rpIdHash, id, idLen, f, nonce)) continue;
      if (((f >> 1) & 3) == 3 && !uv) continue;  // credProtect 3 needs the PIN
      if (f & 1) {
        chosenSlot = passkeyFindNonce(rpIdHash, nonce);
        if (chosenSlot < 0) continue;  // passkey was deleted
      }
      chosen = id;
    }
    if (!chosen) return ST_NO_CREDENTIALS;
    if (up) {
      uint8_t st = askPresence("LOGIN", label);
      if (st != ST_OK) return st;
    }
    return writeAssertion(w, rpIdHash, cdh, flags, chosen, chosenSlot, 0);
  }

  // No allow list: offer the passkeys stored for this site.
  uint8_t slots[PASSKEY_SLOTS];
  int found = passkeyListRp(rpIdHash, slots, PASSKEY_SLOTS);
  int count = 0;
  for (int i = 0; i < found; i++) {
    PasskeyRecord rec;
    if (!passkeyRead(slots[i], rec)) continue;
    if (rec.credProtect >= 2 && !uv) continue;  // hidden from discovery without the PIN
    slots[count++] = slots[i];
  }
  if (count == 0) return ST_NO_CREDENTIALS;
  if (!ensureFidoSecret()) return ST_OTHER;
  if (up) {
    uint8_t st = askPresence("LOGIN", label);
    if (st != ST_OK) return st;
  }
  if (count > 1) {
    nextAssertion.active = true;
    nextAssertion.lastMs = millis();
    memcpy(nextAssertion.rpIdHash, rpIdHash, 32);
    memcpy(nextAssertion.clientDataHash, cdh, 32);
    nextAssertion.flags = flags;
    memcpy(nextAssertion.slots, slots, (size_t)count);
    nextAssertion.count = (uint8_t)count;
    nextAssertion.next = 1;
  }
  return assertionForSlot(w, rpIdHash, cdh, flags, slots[0], (uint8_t)count);
}

static uint8_t getNextAssertion(CborWriter &w) {
  if (!nextAssertion.active || nextAssertion.next >= nextAssertion.count ||
      millis() - nextAssertion.lastMs > 30000) {
    nextAssertion.active = false;
    return ST_NOT_ALLOWED;
  }
  const uint8_t slot = nextAssertion.slots[nextAssertion.next++];
  nextAssertion.lastMs = millis();
  if (nextAssertion.next >= nextAssertion.count) nextAssertion.active = false;
  return assertionForSlot(w, nextAssertion.rpIdHash, nextAssertion.clientDataHash,
                          nextAssertion.flags, slot, 0);
}

// ---------------------------------------------------------------- clientPIN

static bool sharedSecret(const uint8_t px[32], const uint8_t py[32], uint8_t out[32]) {
  uint8_t z[32];
  if (!p256Ecdh(kaPriv, px, py, z)) return false;
  sha256(z, sizeof(z), out);
  secureZero(z, sizeof(z));
  return true;
}

// Decrypts newPinEnc and stores the PIN's hash.
static uint8_t storeNewPin(const uint8_t shared[32], const uint8_t *enc, size_t encLen) {
  if (encLen < 64 || encLen > 256 || encLen % 16) return ST_INVALID_PARAMETER;
  uint8_t buf[256];
  memcpy(buf, enc, encLen);
  aes256CbcDecrypt(shared, buf, encLen);
  size_t pinLen = 0;
  while (pinLen < encLen && buf[pinLen]) pinLen++;
  if (pinLen < 4 || pinLen > 63) {
    secureZero(buf, sizeof(buf));
    return ST_PIN_POLICY_VIOLATION;
  }
  uint8_t hash[32];
  sha256(buf, pinLen, hash);
  secureZero(buf, sizeof(buf));
  memcpy(g_cfg.fidoPinHash, hash, 16);
  g_cfg.fidoPinSet = 1;
  g_cfg.fidoPinRetries = FIDO_PIN_MAX_RETRIES;
  pinMismatchesThisBoot = 0;
  newPinToken();
  return configSave() ? ST_OK : ST_OTHER;
}

// Checks pinHashEnc against the stored PIN, counting attempts first so that
// pulling the plug can't be used to get free guesses.
static uint8_t checkPinHash(const uint8_t shared[32], const uint8_t *enc, size_t encLen) {
  if (encLen != 16) return ST_INVALID_PARAMETER;
  g_cfg.fidoPinRetries--;
  if (!configSave()) return ST_OTHER;
  uint8_t buf[16];
  memcpy(buf, enc, 16);
  aes256CbcDecrypt(shared, buf, 16);
  const bool ok = ctEqual(buf, g_cfg.fidoPinHash, 16);
  secureZero(buf, sizeof(buf));
  if (!ok) {
    newKeyAgreement();
    pinMismatchesThisBoot++;
    if (g_cfg.fidoPinRetries == 0) return ST_PIN_BLOCKED;
    if (pinMismatchesThisBoot >= 3) return ST_PIN_AUTH_BLOCKED;
    return ST_PIN_INVALID;
  }
  pinMismatchesThisBoot = 0;
  g_cfg.fidoPinRetries = FIDO_PIN_MAX_RETRIES;
  return configSave() ? ST_OK : ST_OTHER;
}

static uint8_t clientPin(CborReader &r, CborWriter &w) {
  size_t n;
  if (!cborGetMap(r, n)) return ST_INVALID_CBOR;
  uint64_t protocol = 0, sub = 0;
  bool haveProtocol = false, haveSub = false, haveKa = false;
  uint8_t px[32], py[32];
  const uint8_t *pinAuth = nullptr, *newPinEnc = nullptr, *pinHashEnc = nullptr;
  size_t pinAuthLen = 0, newPinEncLen = 0, pinHashEncLen = 0;
  for (size_t i = 0; i < n; i++) {
    uint64_t key;
    if (!cborGetUint(r, key)) return ST_INVALID_CBOR;
    switch (key) {
      case 1:
        if (!cborGetUint(r, protocol)) return ST_CBOR_UNEXPECTED_TYPE;
        haveProtocol = true;
        break;
      case 2:
        if (!cborGetUint(r, sub)) return ST_CBOR_UNEXPECTED_TYPE;
        haveSub = true;
        break;
      case 3:
        if (!readCoseKey(r, px, py)) return ST_INVALID_PARAMETER;
        haveKa = true;
        break;
      case 4:
        if (!cborGetBytes(r, pinAuth, pinAuthLen)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 5:
        if (!cborGetBytes(r, newPinEnc, newPinEncLen)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      case 6:
        if (!cborGetBytes(r, pinHashEnc, pinHashEncLen)) return ST_CBOR_UNEXPECTED_TYPE;
        break;
      default:
        if (!cborSkip(r)) return ST_INVALID_CBOR;
        break;
    }
  }
  if (!haveProtocol || !haveSub) return ST_MISSING_PARAMETER;
  if (protocol != 1) return ST_INVALID_PARAMETER;

  uint8_t shared[32];
  switch (sub) {
    case 0x01:  // getRetries
      cborPutMap(w, 1);
      cborPutUint(w, 3);
      cborPutUint(w, g_cfg.fidoPinRetries);
      return ST_OK;

    case 0x02:  // getKeyAgreement
      cborPutMap(w, 1);
      cborPutUint(w, 1);
      putCoseKey(w, kaX, kaY, ALG_ECDH_ES_HKDF_256);
      return ST_OK;

    case 0x03: {  // setPIN
      if (!haveKa || !pinAuth || !newPinEnc) return ST_MISSING_PARAMETER;
      if (g_cfg.fidoPinSet) return ST_NOT_ALLOWED;
      if (!sharedSecret(px, py, shared)) return ST_INVALID_PARAMETER;
      uint8_t mac[32];
      hmacSha256(shared, 32, newPinEnc, newPinEncLen, mac);
      if (pinAuthLen != 16 || !ctEqual(mac, pinAuth, 16)) return ST_PIN_AUTH_INVALID;
      uint8_t st = storeNewPin(shared, newPinEnc, newPinEncLen);
      secureZero(shared, sizeof(shared));
      return st;
    }

    case 0x04: {  // changePIN
      if (!haveKa || !pinAuth || !newPinEnc || !pinHashEnc) return ST_MISSING_PARAMETER;
      if (!g_cfg.fidoPinSet) return ST_PIN_NOT_SET;
      if (g_cfg.fidoPinRetries == 0) return ST_PIN_BLOCKED;
      if (pinMismatchesThisBoot >= 3) return ST_PIN_AUTH_BLOCKED;
      if (!sharedSecret(px, py, shared)) return ST_INVALID_PARAMETER;
      uint8_t mac[32];
      hmacSha256Two(shared, 32, newPinEnc, newPinEncLen, pinHashEnc, pinHashEncLen, mac);
      if (pinAuthLen != 16 || !ctEqual(mac, pinAuth, 16)) return ST_PIN_AUTH_INVALID;
      uint8_t st = checkPinHash(shared, pinHashEnc, pinHashEncLen);
      if (st == ST_OK) st = storeNewPin(shared, newPinEnc, newPinEncLen);
      secureZero(shared, sizeof(shared));
      return st;
    }

    case 0x05: {  // getPINToken
      if (!haveKa || !pinHashEnc) return ST_MISSING_PARAMETER;
      if (!g_cfg.fidoPinSet) return ST_PIN_NOT_SET;
      if (g_cfg.fidoPinRetries == 0) return ST_PIN_BLOCKED;
      if (pinMismatchesThisBoot >= 3) return ST_PIN_AUTH_BLOCKED;
      if (!sharedSecret(px, py, shared)) return ST_INVALID_PARAMETER;
      uint8_t st = checkPinHash(shared, pinHashEnc, pinHashEncLen);
      if (st == ST_OK) {
        uint8_t enc[32];
        memcpy(enc, pinToken, 32);
        aes256CbcEncrypt(shared, enc, 32);
        cborPutMap(w, 1);
        cborPutUint(w, 2);
        cborPutBytes(w, enc, 32);
      }
      secureZero(shared, sizeof(shared));
      return st;
    }
  }
  return ST_INVALID_PARAMETER;
}

// ---------------------------------------------------------------- reset

bool ctap2WipeAll() {
  rngAddTiming();
  rngBytes(g_cfg.fidoSecret, 32);
  g_cfg.fidoReady = 1;
  g_cfg.fidoPinSet = 0;
  g_cfg.fidoPinRetries = FIDO_PIN_MAX_RETRIES;
  memset(g_cfg.fidoPinHash, 0, sizeof(g_cfg.fidoPinHash));
  g_cfg.passkeySeq = 0;
  const bool ok = passkeyWipeAll() && configSave();
  fidoKeysReady = false;
  deriveFidoKeys();
  nextAssertion.active = false;
  pinMismatchesThisBoot = 0;
  newPinToken();
  newKeyAgreement();
  return ok;
}

void ctap2ReloadAfterImport(uint32_t minCounter) {
  fidoKeysReady = false;
  deriveFidoKeys();
  nextAssertion.active = false;
  if (counter < minCounter) counter = minCounter;
  if (g_cfg.signCounter < counter) g_cfg.signCounter = counter;
}

uint32_t ctap2Counter() { return counter; }

static uint8_t resetAuthenticator() {
  if (millis() > FIDO_RESET_WINDOW_MS) return ST_NOT_ALLOWED;  // re-plug the key first
  uint8_t st = askPresence("ERASE PASSKEYS?", "");
  if (st != ST_OK) return st;
  return ctap2WipeAll() ? ST_OK : ST_OTHER;
}

// ---------------------------------------------------------------- entry points

void ctap2Begin() {
  counter = g_cfg.signCounter;
  if (g_cfg.fidoReady) deriveFidoKeys();
  newPinToken();
  newKeyAgreement();
}

size_t ctap2Handle(const uint8_t *req, size_t reqLen, uint8_t *resp, size_t respCap) {
  const uint8_t cmd = req[0];
  if (cmd != CMD_GET_NEXT_ASSERTION) nextAssertion.active = false;
  CborReader r;
  cborReaderInit(r, req + 1, reqLen - 1);
  CborWriter w;
  cborWriterInit(w, resp + 1, respCap - 1);
  uint8_t st;
  switch (cmd) {
    case CMD_GET_INFO: st = getInfo(w); break;
    case CMD_MAKE_CREDENTIAL: st = makeCredential(r, w); break;
    case CMD_GET_ASSERTION: st = getAssertion(r, w); break;
    case CMD_GET_NEXT_ASSERTION: st = getNextAssertion(w); break;
    case CMD_CLIENT_PIN: st = clientPin(r, w); break;
    case CMD_RESET: st = resetAuthenticator(); break;
    default: st = ST_INVALID_COMMAND; break;
  }
  if (st == ST_OK && w.overflow) st = ST_OTHER;
  resp[0] = st;
  return st == ST_OK ? 1 + w.len : 1;
}
