// Persistent storage in the RA4M1's 8 KB data flash.
//
// The flash is split into eight 1 KB blocks holding seven logical pages.
// Saving a page writes it to the spare block with a higher sequence number,
// so a power cut mid-write always leaves the previous copy intact.
#pragma once
#include <stdint.h>
#include <stddef.h>

static const size_t PAGE_PAYLOAD = 1008;

enum PageId : uint8_t {
  PAGE_CONFIG = 0,
  PAGE_PASSKEY0 = 1,  // 3 pages of passkeys
  PAGE_VAULT0 = 4,    // 3 pages of vault entries
  PAGE_COUNT = 7,
};
static const uint8_t PASSKEY_PAGES = 3;
static const uint8_t VAULT_PAGES = 3;

bool storageBegin();
// Copies a page into payload (PAGE_PAYLOAD bytes). Returns false and fills
// zeros if the page has never been written.
bool storageLoad(uint8_t page, uint8_t *payload);
// Reads part of a page without loading all of it.
bool storageRead(uint8_t page, size_t offset, void *out, size_t len);
bool storageSave(uint8_t page, const uint8_t *payload);

// Scratch buffer shared by modules that rewrite pages (never used re-entrantly).
extern uint8_t g_pageBuf[PAGE_PAYLOAD];
// Number of page saves that failed since power-up (reported by INFO).
extern uint16_t g_storageFailures;

// ---------------------------------------------------------------- config
// A key restored elsewhere with the emergency password: if it ever shows up
// again, the app can wipe it with this token.
struct __attribute__((packed)) RevokedKey {
  uint8_t deviceId[16];
  uint8_t token[32];
};
static const uint8_t MAX_REVOKED = 4;

// Fields are only ever appended, so older stored configs still load (new
// fields read as zero).
struct __attribute__((packed)) DeviceConfig {
  uint32_t magic;
  uint8_t version;
  uint8_t fidoReady;        // fidoSecret generated
  uint8_t vaultReady;       // vault key generated
  uint8_t vaultHasPin;
  uint8_t vaultPinFails;
  uint8_t fidoPinSet;
  uint8_t fidoPinRetries;
  uint8_t reserved0;
  uint32_t signCounter;     // persisted upper bound of the signature counter
  uint32_t passkeySeq;      // creation order of resident credentials
  uint16_t vaultNextId;
  uint16_t reserved1;
  uint8_t fidoSecret[32];   // derives credential keys; replaced on FIDO reset
  uint8_t deviceSecret[32]; // part of the vault key
  uint8_t vaultSalt[16];
  uint8_t vaultDekNonce[12];
  uint8_t vaultDekBox[32];  // vault data key, encrypted with the PIN-derived key
  uint8_t vaultDekTag[16];
  uint8_t fidoPinHash[16];  // LEFT(SHA-256(PIN), 16) per CTAP2
  uint8_t rngSeed[32];      // carried into the next boot's RNG seed
  // Backups: whoever holds this token (only in a backup's emergency slot)
  // may wipe this key without pressing anything.
  uint8_t killTokenSet;
  uint8_t revokedCount;
  uint8_t reserved2[2];
  uint8_t killToken[32];
  RevokedKey revoked[MAX_REVOKED];  // old keys this key has replaced
};

extern DeviceConfig g_cfg;
void configLoad();  // fills defaults when nothing is stored yet
bool configSave();
