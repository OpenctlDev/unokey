// Discoverable credentials ("passkeys") stored in data flash.
// Records hold the credential nonce, not the private key: keys are derived
// from the device's FIDO secret whenever they are needed.
#pragma once
#include <stdint.h>
#include <stddef.h>

struct __attribute__((packed)) PasskeyRecord {
  uint8_t used;  // PASSKEY_USED when the slot holds a credential
  uint8_t credProtect;
  uint8_t userIdLen;
  uint8_t rpIdLen;
  uint8_t userNameLen;
  uint8_t displayNameLen;
  uint8_t reserved[2];
  uint32_t seq;  // creation order, newest has the highest value
  uint8_t nonce[16];
  uint8_t rpIdHash[32];
  uint8_t userId[64];
  char rpId[40];         // shortened for display only
  char userName[32];     // shortened at a UTF-8 character boundary
  char displayName[28];  // likewise
};
static_assert(sizeof(PasskeyRecord) == 224, "passkey record layout");

static const uint8_t PASSKEY_USED = 0xA7;
static const uint8_t PASSKEYS_PER_PAGE = 4;
static const uint8_t PASSKEY_SLOTS = 12;

bool passkeyRead(uint8_t slot, PasskeyRecord &rec);  // true if the slot is used
int passkeyCount();
int passkeyFindUser(const uint8_t rpIdHash[32], const uint8_t *userId, size_t userIdLen);
int passkeyFindNonce(const uint8_t rpIdHash[32], const uint8_t nonce[16]);
// Slots for one RP, newest first. Returns how many were written to slots.
int passkeyListRp(const uint8_t rpIdHash[32], uint8_t *slots, int max);
// Stores rec, replacing an existing passkey of the same user on the same RP.
// Returns the slot, or -1 when storage is full or the write failed.
int passkeyStore(const PasskeyRecord &rec);
bool passkeyDelete(uint8_t slot);
bool passkeyWipeAll();

// Longest prefix of s (n bytes) that fits in max bytes without splitting a
// UTF-8 character.
size_t utf8Fit(const char *s, size_t n, size_t max);
