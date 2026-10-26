#include "vault.h"
#include "config.h"
#include "crypto.h"
#include "storage.h"
#include "ui.h"
#include <Arduino.h>
#include <stdio.h>
#include <string.h>

// Page layout: [used u16] then records back to back.
// Record: [len u16][id u16][type u8][reserved u8][nonce 12][ciphertext][tag 16]
// Plaintext: [nameLen u8][name][value]
static const size_t REC_HEAD = 18;
static const size_t REC_OVERHEAD = REC_HEAD + 16;
static const size_t PLAIN_MAX = 1 + VAULT_NAME_MAX + VAULT_VALUE_MAX;
static const uint8_t DEK_AAD[] = {'d', 'e', 'k'};

static uint8_t dek[32];
static bool open;
static bool pinOkThisBoot;
static bool timeSet;
static uint32_t timeBase, timeAtMs;

struct RecRef {
  uint8_t page;
  uint16_t offset;
  uint16_t len;
  uint16_t id;
  char type;
};

// ---------------------------------------------------------------- records

static uint16_t pageUsed(uint8_t page) {
  uint16_t used = 0;
  storageRead(page, 0, &used, 2);
  return used <= PAGE_PAYLOAD - 2 ? used : 0;
}

// Walks all records; stops early when fn returns true.
template <typename F>
static bool walk(F fn) {
  for (uint8_t p = 0; p < VAULT_PAGES; p++) {
    const uint8_t page = (uint8_t)(PAGE_VAULT0 + p);
    const uint16_t used = pageUsed(page);
    uint16_t off = 2;
    while (off + REC_OVERHEAD <= 2u + used) {
      uint8_t head[6];
      storageRead(page, off, head, sizeof(head));
      RecRef ref;
      ref.page = page;
      ref.offset = off;
      ref.len = (uint16_t)(head[0] | (head[1] << 8));
      ref.id = (uint16_t)(head[2] | (head[3] << 8));
      ref.type = (char)head[4];
      if (ref.len < REC_OVERHEAD || off + ref.len > 2u + used) break;  // corrupt: stop
      if (fn(ref)) return true;
      off = (uint16_t)(off + ref.len);
    }
  }
  return false;
}

static bool findRecord(uint16_t id, RecRef &out) {
  return walk([&](const RecRef &r) {
    if (r.id != id) return false;
    out = r;
    return true;
  });
}

// Decrypts a record into plain (PLAIN_MAX bytes). Returns plaintext length or -1.
static int openRecord(const RecRef &r, uint8_t *plain) {
  const size_t ctLen = r.len - REC_OVERHEAD;
  if (ctLen > PLAIN_MAX) return -1;
  uint8_t nonce[12], tag[16];
  const uint8_t aad[3] = {(uint8_t)r.id, (uint8_t)(r.id >> 8), (uint8_t)r.type};
  storageRead(r.page, r.offset + 6, nonce, 12);
  storageRead(r.page, r.offset + REC_HEAD, plain, ctLen);
  storageRead(r.page, r.offset + REC_HEAD + ctLen, tag, 16);
  if (!aeadOpen(dek, nonce, plain, ctLen, aad, sizeof(aad), tag)) return -1;
  return (int)ctLen;
}

// ---------------------------------------------------------------- keys

static void deriveKek(const char *pin, size_t pinLen, uint8_t kek[32]) {
  uint8_t ikm[64];
  memcpy(ikm, g_cfg.deviceSecret, 32);
  if (pin) {
    pbkdf2Sha256((const uint8_t *)pin, pinLen, g_cfg.vaultSalt, sizeof(g_cfg.vaultSalt),
                 VAULT_PBKDF2_ITER, ikm + 32);
    hkdfSha256(g_cfg.vaultSalt, sizeof(g_cfg.vaultSalt), ikm, 64, "unokey vault pin", kek, 32);
  } else {
    hkdfSha256(g_cfg.vaultSalt, sizeof(g_cfg.vaultSalt), ikm, 32, "unokey vault", kek, 32);
  }
  secureZero(ikm, sizeof(ikm));
}

static void wrapDek(const uint8_t kek[32]) {
  rngBytes(g_cfg.vaultDekNonce, sizeof(g_cfg.vaultDekNonce));
  memcpy(g_cfg.vaultDekBox, dek, 32);
  aeadSeal(kek, g_cfg.vaultDekNonce, g_cfg.vaultDekBox, 32, DEK_AAD, sizeof(DEK_AAD),
           g_cfg.vaultDekTag);
}

static bool unwrapDek(const uint8_t kek[32]) {
  uint8_t tmp[32];
  memcpy(tmp, g_cfg.vaultDekBox, 32);
  if (!aeadOpen(kek, g_cfg.vaultDekNonce, tmp, 32, DEK_AAD, sizeof(DEK_AAD), g_cfg.vaultDekTag))
    return false;
  memcpy(dek, tmp, 32);
  secureZero(tmp, sizeof(tmp));
  open = true;
  return true;
}

// Keys are made on first use: by then the host app has usually mixed its
// own randomness into ours.
static bool ensureVault() {
  if (g_cfg.vaultReady) return true;
  rngAddTiming();
  rngBytes(g_cfg.deviceSecret, 32);
  rngBytes(g_cfg.vaultSalt, sizeof(g_cfg.vaultSalt));
  rngBytes(dek, 32);
  uint8_t kek[32];
  deriveKek(nullptr, 0, kek);
  wrapDek(kek);
  secureZero(kek, sizeof(kek));
  secureZero(dek, sizeof(dek));
  g_cfg.vaultReady = 1;
  g_cfg.vaultHasPin = 0;
  g_cfg.vaultPinFails = 0;
  if (configSave()) return true;
  g_cfg.vaultReady = 0;
  return false;
}

static bool wipeVault() {
  bool ok = true;
  memset(g_pageBuf, 0, PAGE_PAYLOAD);
  for (uint8_t p = 0; p < VAULT_PAGES; p++) ok &= storageSave((uint8_t)(PAGE_VAULT0 + p), g_pageBuf);
  g_cfg.vaultReady = 0;
  secureZero(dek, sizeof(dek));
  open = false;
  pinOkThisBoot = false;
  return ensureVault() && ok;  // fresh keys, no PIN
}

static VaultStatus fromUi(UiResult r) {
  switch (r) {
    case UI_APPROVED: return VAULT_OK;
    case UI_DENIED: return VAULT_DENIED;
    case UI_CANCELLED: return VAULT_CANCELLED;
    default: return VAULT_TIMEOUT;
  }
}

// ---------------------------------------------------------------- public

void vaultBegin() {
  open = false;
  pinOkThisBoot = false;
}

bool vaultIsOpen() { return open; }
bool vaultHasPin() { return g_cfg.vaultReady && g_cfg.vaultHasPin; }

uint8_t vaultPinTriesLeft() {
  return g_cfg.vaultPinFails >= VAULT_PIN_MAX_FAILS ? 0
                                                    : (uint8_t)(VAULT_PIN_MAX_FAILS - g_cfg.vaultPinFails);
}

VaultStatus vaultUnlock(const char *who) {
  if (!ensureVault()) return VAULT_ERROR;
  if (open) return fromUi(uiConfirm("ALLOW", who, PROMPT_TIMEOUT_MS));

  if (!g_cfg.vaultHasPin) {
    VaultStatus st = fromUi(uiConfirm("UNLOCK", who, PROMPT_TIMEOUT_MS));
    if (st != VAULT_OK) return st;
    uint8_t kek[32];
    deriveKek(nullptr, 0, kek);
    const bool ok = unwrapDek(kek);
    secureZero(kek, sizeof(kek));
    return ok ? VAULT_OK : VAULT_ERROR;
  }

  char pin[VAULT_PIN_MAX + 1];
  const int len = uiEnterPin("VAULT PIN", pin, VAULT_PIN_MIN, VAULT_PIN_MAX);
  if (len == -2) return VAULT_NO_JOYSTICK;
  if (len < 0) return VAULT_CANCELLED;
  // Count the attempt before checking it, so cutting power doesn't help.
  g_cfg.vaultPinFails++;
  configSave();
  uint8_t kek[32];
  deriveKek(pin, (size_t)len, kek);
  secureZero(pin, sizeof(pin));
  const bool ok = unwrapDek(kek);
  secureZero(kek, sizeof(kek));
  if (ok) {
    g_cfg.vaultPinFails = 0;
    configSave();
    pinOkThisBoot = true;
    uiShowIcon(ICON_UNLOCK, 400);
    return VAULT_OK;
  }
  if (g_cfg.vaultPinFails >= VAULT_PIN_MAX_FAILS) {
    wipeVault();
    uiScrollOnce("VAULT WIPED");
    return VAULT_WIPED;
  }
  char msg[24];
  snprintf(msg, sizeof(msg), "WRONG PIN %u LEFT", vaultPinTriesLeft());
  uiScrollOnce(msg);
  return VAULT_BAD_PIN;
}

void vaultLock() {
  secureZero(dek, sizeof(dek));
  open = false;
  pinOkThisBoot = false;
}

VaultStatus vaultErase() {
  VaultStatus st = fromUi(uiConfirm("ERASE VAULT", "AND PIN", PROMPT_TIMEOUT_MS));
  if (st != VAULT_OK) return st;
  if (!wipeVault()) return VAULT_ERROR;
  uiShowIcon(ICON_CHECK, 500);
  return VAULT_OK;
}

bool vaultWipeAll() { return wipeVault(); }

VaultStatus vaultSetPin() {
  if (!open) {
    VaultStatus st = vaultUnlock("SET PIN");
    if (st != VAULT_OK) return st;
  }
  char a[VAULT_PIN_MAX + 1], b[VAULT_PIN_MAX + 1];
  const int la = uiEnterPin("NEW PIN", a, VAULT_PIN_MIN, VAULT_PIN_MAX);
  if (la == -2) return VAULT_NO_JOYSTICK;
  if (la < 0) return VAULT_CANCELLED;
  const int lb = uiEnterPin("REPEAT PIN", b, VAULT_PIN_MIN, VAULT_PIN_MAX);
  if (lb < 0) {
    secureZero(a, sizeof(a));
    return lb == -2 ? VAULT_NO_JOYSTICK : VAULT_CANCELLED;
  }
  const bool same = la == lb && memcmp(a, b, (size_t)la) == 0;
  secureZero(b, sizeof(b));
  if (!same) {
    secureZero(a, sizeof(a));
    uiScrollOnce("PINS DIFFER");
    return VAULT_BAD_PIN;
  }
  uint8_t kek[32];
  deriveKek(a, (size_t)la, kek);
  secureZero(a, sizeof(a));
  wrapDek(kek);
  secureZero(kek, sizeof(kek));
  g_cfg.vaultHasPin = 1;
  g_cfg.vaultPinFails = 0;
  if (!configSave()) return VAULT_ERROR;
  pinOkThisBoot = true;
  uiShowIcon(ICON_CHECK, 500);
  return VAULT_OK;
}

int vaultCount() {
  int n = 0;
  walk([&](const RecRef &) {
    n++;
    return false;
  });
  return n;
}

size_t vaultBytesUsed() {
  size_t n = 0;
  for (uint8_t p = 0; p < VAULT_PAGES; p++) n += pageUsed((uint8_t)(PAGE_VAULT0 + p));
  return n;
}

size_t vaultBytesTotal() { return (size_t)VAULT_PAGES * (PAGE_PAYLOAD - 2); }

void vaultForEach(void (*fn)(uint16_t id, char type, const char *name, size_t nameLen, void *ctx),
                  void *ctx) {
  if (!open) return;
  static uint8_t plain[PLAIN_MAX];
  walk([&](const RecRef &r) {
    const int n = openRecord(r, plain);
    if (n > 0 && plain[0] <= n - 1) fn(r.id, r.type, (const char *)plain + 1, plain[0], ctx);
    secureZero(plain, sizeof(plain));
    return false;
  });
}

VaultStatus vaultGet(uint16_t id, char &type, char *name, size_t nameCap, char *value,
                     size_t valueCap) {
  if (!open) return VAULT_LOCKED;
  RecRef r;
  if (!findRecord(id, r)) return VAULT_NOT_FOUND;
  static uint8_t plain[PLAIN_MAX];
  const int n = openRecord(r, plain);
  if (n < 1 || plain[0] > n - 1) {
    secureZero(plain, sizeof(plain));
    return VAULT_ERROR;
  }
  const size_t nameLen = plain[0];
  const size_t valueLen = (size_t)n - 1 - nameLen;
  type = r.type;
  if (name) {
    const size_t c = nameLen < nameCap - 1 ? nameLen : nameCap - 1;
    memcpy(name, plain + 1, c);
    name[c] = 0;
  }
  if (value) {
    const size_t c = valueLen < valueCap - 1 ? valueLen : valueCap - 1;
    memcpy(value, plain + 1 + nameLen, c);
    value[c] = 0;
  }
  secureZero(plain, sizeof(plain));
  return VAULT_OK;
}

bool vaultNameOf(uint16_t id, char *name, size_t cap) {
  char type;
  return vaultGet(id, type, name, cap, nullptr, 0) == VAULT_OK;
}

int vaultAdd(char type, const char *name, size_t nameLen, const char *value, size_t valueLen) {
  if (!open) return VAULT_LOCKED;
  if (type != VAULT_PASSPHRASE && type != VAULT_CODE && type != VAULT_TOTP) return VAULT_ERROR;
  if (nameLen == 0 || nameLen > VAULT_NAME_MAX || valueLen > VAULT_VALUE_MAX) return VAULT_TOO_LONG;
  const size_t plainLen = 1 + nameLen + valueLen;
  const size_t recLen = REC_OVERHEAD + plainLen;

  uint8_t page = 0xFF;
  uint16_t used = 0;
  for (uint8_t p = 0; p < VAULT_PAGES; p++) {
    used = pageUsed((uint8_t)(PAGE_VAULT0 + p));
    if (2u + used + recLen <= PAGE_PAYLOAD) {
      page = (uint8_t)(PAGE_VAULT0 + p);
      break;
    }
  }
  if (page == 0xFF) return VAULT_FULL;

  uint16_t id = g_cfg.vaultNextId++;
  if (id == 0) id = g_cfg.vaultNextId++;
  storageLoad(page, g_pageBuf);
  memcpy(g_pageBuf, &used, 2);  // trust our own count over a never-written page
  uint8_t *rec = g_pageBuf + 2 + used;
  rec[0] = (uint8_t)recLen;
  rec[1] = (uint8_t)(recLen >> 8);
  rec[2] = (uint8_t)id;
  rec[3] = (uint8_t)(id >> 8);
  rec[4] = (uint8_t)type;
  rec[5] = 0;
  rngBytes(rec + 6, 12);
  uint8_t *plain = rec + REC_HEAD;
  plain[0] = (uint8_t)nameLen;
  memcpy(plain + 1, name, nameLen);
  memcpy(plain + 1 + nameLen, value, valueLen);
  const uint8_t aad[3] = {(uint8_t)id, (uint8_t)(id >> 8), (uint8_t)type};
  aeadSeal(dek, rec + 6, plain, plainLen, aad, sizeof(aad), plain + plainLen);
  used = (uint16_t)(used + recLen);
  memcpy(g_pageBuf, &used, 2);
  const bool ok = storageSave(page, g_pageBuf);
  secureZero(g_pageBuf, PAGE_PAYLOAD);
  if (!ok) return VAULT_ERROR;
  configSave();  // keeps vaultNextId
  return id;
}

VaultStatus vaultDelete(uint16_t id) {
  if (!open) return VAULT_LOCKED;
  RecRef r;
  if (!findRecord(id, r)) return VAULT_NOT_FOUND;
  storageLoad(r.page, g_pageBuf);
  uint16_t used = pageUsed(r.page);
  const size_t tail = 2u + used - (r.offset + r.len);
  memmove(g_pageBuf + r.offset, g_pageBuf + r.offset + r.len, tail);
  used = (uint16_t)(used - r.len);
  memset(g_pageBuf + 2 + used, 0, PAGE_PAYLOAD - 2 - used);
  memcpy(g_pageBuf, &used, 2);
  const bool ok = storageSave(r.page, g_pageBuf);
  secureZero(g_pageBuf, PAGE_PAYLOAD);
  return ok ? VAULT_OK : VAULT_ERROR;
}

// ---------------------------------------------------------------- TOTP

void vaultSetTime(uint32_t unixTime) {
  timeBase = unixTime;
  timeAtMs = millis();
  timeSet = true;
}

static int base32Decode(const char *s, size_t n, uint8_t *out, size_t cap) {
  uint32_t buffer = 0;
  int bits = 0;
  size_t len = 0;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    int v;
    if (c >= 'a' && c <= 'z') c = (char)(c - 32);
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= '2' && c <= '7') v = c - '2' + 26;
    else if (c == ' ' || c == '=' || c == '-') continue;
    else return -1;
    buffer = (buffer << 5) | (uint32_t)v;
    bits += 5;
    if (bits >= 8) {
      if (len >= cap) return -1;
      out[len++] = (uint8_t)(buffer >> (bits - 8));
      bits -= 8;
    }
  }
  return (int)len;
}

// value: "SECRET" or "SECRET;digits=8;period=30;algo=SHA256"
bool vaultTotp(const char *value, char *code, size_t cap) {
  if (!timeSet) return false;
  const char *semi = strchr(value, ';');
  const size_t secretLen = semi ? (size_t)(semi - value) : strlen(value);
  unsigned digits = 6, period = 30;
  bool sha256Algo = false;
  for (const char *p = semi; p && *p; p = strchr(p + 1, ';')) {
    if (!strncmp(p, ";digits=", 8)) digits = (unsigned)atoi(p + 8);
    else if (!strncmp(p, ";period=", 8)) period = (unsigned)atoi(p + 8);
    else if (!strncmp(p, ";algo=SHA256", 12)) sha256Algo = true;
  }
  if (digits < 6 || digits > 8 || period == 0) return false;
  uint8_t key[64];
  const int keyLen = base32Decode(value, secretLen, key, sizeof(key));
  if (keyLen <= 0) return false;

  const uint32_t now = timeBase + (millis() - timeAtMs) / 1000;
  const uint64_t step = now / period;
  uint8_t msg[8];
  for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(step >> (56 - 8 * i));
  uint8_t mac[32];
  size_t macLen = 20;
  if (sha256Algo) {
    hmacSha256(key, (size_t)keyLen, msg, sizeof(msg), mac);
    macLen = 32;
  } else {
    hmacSha1(key, (size_t)keyLen, msg, sizeof(msg), mac);
  }
  secureZero(key, sizeof(key));
  const uint8_t off = mac[macLen - 1] & 0x0F;
  const uint32_t bin = ((uint32_t)(mac[off] & 0x7F) << 24) | ((uint32_t)mac[off + 1] << 16) |
                       ((uint32_t)mac[off + 2] << 8) | mac[off + 3];
  uint32_t mod = 1;
  for (unsigned i = 0; i < digits; i++) mod *= 10;
  snprintf(code, cap, "%0*lu", (int)digits, (unsigned long)(bin % mod));
  return true;
}

// ---------------------------------------------------------------- on-device browsing

static uint16_t browseIds[64];

static void collectId(uint16_t id, char, const char *, size_t, void *ctx) {
  int &n = *(int *)ctx;
  if (n < 64) browseIds[n++] = id;
}

static void labelFor(int index, char *buf, size_t cap, void *) {
  if (!vaultNameOf(browseIds[index], buf, cap)) snprintf(buf, cap, "?");
}

void vaultBrowseOnDevice() {
  if (!open) {
    if (vaultUnlock("DEVICE") != VAULT_OK) return;
  }
  int count = 0;
  vaultForEach(collectId, &count);
  if (count == 0) {
    uiScrollOnce("VAULT EMPTY");
    return;
  }
  static char value[VAULT_VALUE_MAX + 1];
  int sel = 0;
  for (;;) {
    sel = uiChooseList(count, sel, labelFor, nullptr);
    if (sel < 0) return;
    char type, name[VAULT_NAME_MAX + 1];
    if (vaultGet(browseIds[sel], type, name, sizeof(name), value, sizeof(value)) != VAULT_OK) return;
    if (type == VAULT_TOTP) {
      char code[12];
      if (vaultTotp(value, code, sizeof(code))) uiShowText(code);
      else uiShowText("OPEN APP FOR TIME");
    } else {
      uiShowText(value);
    }
    secureZero(value, sizeof(value));
  }
}
