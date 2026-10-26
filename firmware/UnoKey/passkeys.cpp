#include "passkeys.h"
#include "storage.h"
#include "crypto.h"
#include <string.h>

static uint8_t pageOf(uint8_t slot) { return (uint8_t)(PAGE_PASSKEY0 + slot / PASSKEYS_PER_PAGE); }
static size_t offsetOf(uint8_t slot) { return (size_t)(slot % PASSKEYS_PER_PAGE) * sizeof(PasskeyRecord); }

bool passkeyRead(uint8_t slot, PasskeyRecord &rec) {
  if (slot >= PASSKEY_SLOTS || !storageRead(pageOf(slot), offsetOf(slot), &rec, sizeof(rec))) {
    memset(&rec, 0, sizeof(rec));
    return false;
  }
  return rec.used == PASSKEY_USED;
}

int passkeyCount() {
  PasskeyRecord rec;
  int n = 0;
  for (uint8_t s = 0; s < PASSKEY_SLOTS; s++)
    if (passkeyRead(s, rec)) n++;
  return n;
}

int passkeyFindUser(const uint8_t rpIdHash[32], const uint8_t *userId, size_t userIdLen) {
  PasskeyRecord rec;
  for (uint8_t s = 0; s < PASSKEY_SLOTS; s++) {
    if (!passkeyRead(s, rec)) continue;
    if (memcmp(rec.rpIdHash, rpIdHash, 32) == 0 && rec.userIdLen == userIdLen &&
        memcmp(rec.userId, userId, userIdLen) == 0)
      return s;
  }
  return -1;
}

int passkeyFindNonce(const uint8_t rpIdHash[32], const uint8_t nonce[16]) {
  PasskeyRecord rec;
  for (uint8_t s = 0; s < PASSKEY_SLOTS; s++) {
    if (!passkeyRead(s, rec)) continue;
    if (memcmp(rec.rpIdHash, rpIdHash, 32) == 0 && memcmp(rec.nonce, nonce, 16) == 0) return s;
  }
  return -1;
}

int passkeyListRp(const uint8_t rpIdHash[32], uint8_t *slots, int max) {
  PasskeyRecord rec;
  uint32_t seqs[PASSKEY_SLOTS];
  int n = 0;
  for (uint8_t s = 0; s < PASSKEY_SLOTS && n < max; s++) {
    if (!passkeyRead(s, rec) || memcmp(rec.rpIdHash, rpIdHash, 32) != 0) continue;
    // Insertion sort, newest first.
    int i = n++;
    while (i > 0 && seqs[i - 1] < rec.seq) {
      seqs[i] = seqs[i - 1];
      slots[i] = slots[i - 1];
      i--;
    }
    seqs[i] = rec.seq;
    slots[i] = s;
  }
  return n;
}

static bool writeSlot(uint8_t slot, const PasskeyRecord *rec) {
  storageLoad(pageOf(slot), g_pageBuf);
  if (rec) memcpy(g_pageBuf + offsetOf(slot), rec, sizeof(*rec));
  else memset(g_pageBuf + offsetOf(slot), 0, sizeof(PasskeyRecord));
  bool ok = storageSave(pageOf(slot), g_pageBuf);
  secureZero(g_pageBuf, PAGE_PAYLOAD);
  return ok;
}

int passkeyStore(const PasskeyRecord &rec) {
  int slot = passkeyFindUser(rec.rpIdHash, rec.userId, rec.userIdLen);
  if (slot < 0) {
    PasskeyRecord tmp;
    for (uint8_t s = 0; s < PASSKEY_SLOTS; s++) {
      if (!passkeyRead(s, tmp)) {
        slot = s;
        break;
      }
    }
  }
  if (slot < 0) return -1;
  return writeSlot((uint8_t)slot, &rec) ? slot : -1;
}

bool passkeyDelete(uint8_t slot) {
  if (slot >= PASSKEY_SLOTS) return false;
  return writeSlot(slot, nullptr);
}

bool passkeyWipeAll() {
  bool ok = true;
  memset(g_pageBuf, 0, PAGE_PAYLOAD);
  for (uint8_t p = 0; p < PASSKEY_PAGES; p++) ok &= storageSave((uint8_t)(PAGE_PASSKEY0 + p), g_pageBuf);
  return ok;
}

size_t utf8Fit(const char *s, size_t n, size_t max) {
  if (n <= max) return n;
  size_t len = max;
  // s[len] is the first byte left out; if it continues a character, drop
  // that whole character.
  while (len > 0 && ((uint8_t)s[len] & 0xC0) == 0x80) len--;
  return len;
}
