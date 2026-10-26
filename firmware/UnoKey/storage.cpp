#include "storage.h"
#include "crypto.h"
#include "config.h"
#include <Arduino.h>
#include "DataFlashBlockDevice.h"
#include <string.h>

static const uint32_t PAGE_MAGIC = 0x47504B55;  // "UKPG"
static const uint32_t CONFIG_MAGIC = 0x46434B55;  // "UKCF"
static const uint8_t FORMAT_VERSION = 1;
static const size_t BLOCK_SIZE = 1024;
static const uint8_t NUM_BLOCKS = 8;

struct __attribute__((packed)) PageHeader {
  uint32_t magic;
  uint8_t pageId;
  uint8_t version;
  uint16_t reserved;
  uint32_t seq;
  uint32_t crc;  // over the first 12 header bytes and the payload
};
static_assert(sizeof(PageHeader) + PAGE_PAYLOAD == BLOCK_SIZE, "page layout");

uint8_t g_pageBuf[PAGE_PAYLOAD];
DeviceConfig g_cfg;
uint16_t g_storageFailures;

static int8_t location[PAGE_COUNT];
static uint32_t pageSeq[PAGE_COUNT];
static uint32_t maxSeq;
static uint8_t nextBlock;
static uint8_t blockBuf[BLOCK_SIZE];

static DataFlashBlockDevice &flash() { return DataFlashBlockDevice::getInstance(); }

static uint32_t pageCrc(const uint8_t *block) {
  uint32_t c = crc32(block, 12);
  return crc32(block + sizeof(PageHeader), PAGE_PAYLOAD, c);
}

bool storageBegin() {
  // Deliberately no flash().init(): the core's DataFlashBlockDevice only
  // reports success from read() and erase() when it opens the flash itself
  // for that call. Opened up front, every erase silently fails.
  if (flash().size() < (uint32_t)NUM_BLOCKS * BLOCK_SIZE) return false;
  for (uint8_t p = 0; p < PAGE_COUNT; p++) location[p] = -1;
  maxSeq = 0;
  for (uint8_t b = 0; b < NUM_BLOCKS; b++) {
    if (flash().read(blockBuf, (uint32_t)b * BLOCK_SIZE, BLOCK_SIZE) != 0) continue;
    PageHeader h;
    memcpy(&h, blockBuf, sizeof(h));
    if (h.magic != PAGE_MAGIC || h.version != FORMAT_VERSION || h.pageId >= PAGE_COUNT) continue;
    if (pageCrc(blockBuf) != h.crc) continue;
    if (location[h.pageId] < 0 || h.seq > pageSeq[h.pageId]) {
      location[h.pageId] = (int8_t)b;
      pageSeq[h.pageId] = h.seq;
    }
    if (h.seq > maxSeq) {
      maxSeq = h.seq;
      nextBlock = (uint8_t)((b + 1) % NUM_BLOCKS);
    }
  }
  return true;
}

bool storageRead(uint8_t page, size_t offset, void *out, size_t len) {
  if (page >= PAGE_COUNT || offset + len > PAGE_PAYLOAD) return false;
  if (location[page] < 0) {
    memset(out, 0, len);
    return false;
  }
  uint32_t addr = (uint32_t)location[page] * BLOCK_SIZE + sizeof(PageHeader) + offset;
  return flash().read(out, addr, len) == 0;
}

bool storageLoad(uint8_t page, uint8_t *payload) {
  return storageRead(page, 0, payload, PAGE_PAYLOAD);
}

static bool blockInUse(uint8_t b) {
  for (uint8_t p = 0; p < PAGE_COUNT; p++)
    if (location[p] == (int8_t)b) return true;
  return false;
}

bool storageSave(uint8_t page, const uint8_t *payload) {
  if (page >= PAGE_COUNT) return false;
  // Round-robin over free blocks spreads erase wear evenly.
  for (uint8_t tries = 0; tries < NUM_BLOCKS; tries++) {
    uint8_t b = nextBlock;
    nextBlock = (uint8_t)((nextBlock + 1) % NUM_BLOCKS);
    if (blockInUse(b)) continue;

    PageHeader h;
    h.magic = PAGE_MAGIC;
    h.pageId = page;
    h.version = FORMAT_VERSION;
    h.reserved = 0;
    h.seq = maxSeq + 1;
    memcpy(blockBuf, &h, sizeof(h));
    memcpy(blockBuf + sizeof(h), payload, PAGE_PAYLOAD);
    h.crc = pageCrc(blockBuf);
    memcpy(blockBuf, &h, sizeof(h));

    const uint32_t addr = (uint32_t)b * BLOCK_SIZE;
    if (flash().erase(addr, BLOCK_SIZE) != 0) continue;
    if (flash().program(blockBuf, addr, BLOCK_SIZE) != 0) continue;
    // Verify before switching over, so a bad write never replaces good data.
    static uint8_t check[64];
    bool same = true;
    for (size_t off = 0; off < BLOCK_SIZE && same; off += sizeof(check)) {
      if (flash().read(check, addr + off, sizeof(check)) != 0) same = false;
      else same = memcmp(check, blockBuf + off, sizeof(check)) == 0;
    }
    if (!same) continue;

    maxSeq = h.seq;
    location[page] = (int8_t)b;
    pageSeq[page] = h.seq;
    return true;
  }
  g_storageFailures++;
  return false;
}

// ---------------------------------------------------------------- config

void configLoad() {
  memset(&g_cfg, 0, sizeof(g_cfg));
  if (storageRead(PAGE_CONFIG, 0, &g_cfg, sizeof(g_cfg)) && g_cfg.magic == CONFIG_MAGIC &&
      g_cfg.version == FORMAT_VERSION) {
    return;
  }
  memset(&g_cfg, 0, sizeof(g_cfg));
  g_cfg.magic = CONFIG_MAGIC;
  g_cfg.version = FORMAT_VERSION;
  g_cfg.fidoPinRetries = FIDO_PIN_MAX_RETRIES;
  g_cfg.vaultNextId = 1;
}

bool configSave() {
  memset(g_pageBuf, 0, PAGE_PAYLOAD);
  memcpy(g_pageBuf, &g_cfg, sizeof(g_cfg));
  bool ok = storageSave(PAGE_CONFIG, g_pageBuf);
  secureZero(g_pageBuf, PAGE_PAYLOAD);
  return ok;
}
