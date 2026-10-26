#include "hostproto.h"
#include "config.h"
#include "crypto.h"
#include "ctap2.h"
#include "passkeys.h"
#include "storage.h"
#include "ui.h"
#include "vault.h"
#include <Arduino.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char line[1200];
static size_t lineLen;
static bool overflowed;
static bool session;
static bool exportAllowed;  // EXPORTBEGIN was confirmed on the key this session
static bool importAllowed;  // PKIMPORT was confirmed on the key this session
static bool wasConnected;
static uint32_t lastActivity;

static void endSession() {
  session = false;
  exportAllowed = false;
  importAllowed = false;
}

// ---------------------------------------------------------------- hex

static void writeHex(const uint8_t *data, size_t n) {
  static const char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    SerialUSB.write((uint8_t)HEX_DIGITS[data[i] >> 4]);
    SerialUSB.write((uint8_t)HEX_DIGITS[data[i] & 15]);
  }
}

static int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Parses exactly n bytes of hex.
static bool parseHex(const char *s, uint8_t *out, size_t n) {
  if (!s || strlen(s) != 2 * n) return false;
  for (size_t i = 0; i < n; i++) {
    const int hi = hexValue(s[2 * i]), lo = hexValue(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static void deviceId(uint8_t out[16]) { memcpy(out, R_BSP_UniqueIdGet(), 16); }

// ---------------------------------------------------------------- base64

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void writeB64(const uint8_t *data, size_t n) {
  if (n == 0) {
    SerialUSB.print('=');  // keeps the field from disappearing
    return;
  }
  char out[4];
  for (size_t i = 0; i < n; i += 3) {
    const uint32_t v = ((uint32_t)data[i] << 16) | (i + 1 < n ? (uint32_t)data[i + 1] << 8 : 0) |
                       (i + 2 < n ? data[i + 2] : 0);
    out[0] = B64[(v >> 18) & 63];
    out[1] = B64[(v >> 12) & 63];
    out[2] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
    out[3] = i + 2 < n ? B64[v & 63] : '=';
    SerialUSB.write((const uint8_t *)out, 4);
  }
}

static int b64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// Decodes in place. Returns the decoded length or -1 on bad input.
static int b64DecodeInPlace(char *s) {
  size_t out = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (char *p = s; *p; p++) {
    if (*p == '=') break;
    const int v = b64Value(*p);
    if (v < 0) return -1;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      s[out++] = (char)(acc >> bits);
    }
  }
  s[out] = 0;
  return (int)out;
}

// ---------------------------------------------------------------- replies

static void reply(const char *s) {
  SerialUSB.print(s);
  SerialUSB.print('\n');
}

static void replyStatus(VaultStatus st) {
  switch (st) {
    case VAULT_OK: reply("OK"); break;
    case VAULT_DENIED: reply("ERR DENIED"); break;
    case VAULT_TIMEOUT: reply("ERR TIMEOUT"); break;
    case VAULT_CANCELLED: reply("ERR CANCELLED"); break;
    case VAULT_WIPED: reply("ERR WIPED"); break;
    case VAULT_LOCKED: reply("ERR LOCKED"); break;
    case VAULT_FULL: reply("ERR FULL"); break;
    case VAULT_NOT_FOUND: reply("ERR NOTFOUND"); break;
    case VAULT_TOO_LONG: reply("ERR TOOLONG"); break;
    case VAULT_NO_JOYSTICK: reply("ERR NOJOYSTICK"); break;
    case VAULT_BAD_PIN: {
      char buf[24];
      snprintf(buf, sizeof(buf), "ERR PIN %u", vaultPinTriesLeft());
      reply(buf);
      break;
    }
    default: reply("ERR FAILED"); break;
  }
}

static void listEntry(uint16_t id, char type, const char *name, size_t nameLen, void *) {
  char head[16];
  snprintf(head, sizeof(head), "E %u %c ", id, type);
  SerialUSB.print(head);
  writeB64((const uint8_t *)name, nameLen);
  SerialUSB.print('\n');
}

// ---------------------------------------------------------------- commands

static bool requireSession() {
  if (session && vaultIsOpen()) return true;
  endSession();
  reply("ERR LOCKED");
  return false;
}

static void cmdInfo() {
  char buf[96];
  snprintf(buf, sizeof(buf), "OK %s %d %u %u %d %u %d %d %d %u %u %d", UNOKEY_VERSION, vaultCount(),
           (unsigned)vaultBytesUsed(), (unsigned)vaultBytesTotal(), passkeyCount(),
           (unsigned)PASSKEY_SLOTS, vaultHasPin() ? 1 : 0, g_cfg.fidoPinSet ? 1 : 0,
           vaultIsOpen() ? 1 : 0, vaultPinTriesLeft(), (unsigned)g_storageFailures,
           uiJoystickPresent() ? 1 : 0);
  reply(buf);
}

static void cmdGet(char *arg) {
  if (!requireSession() || !arg) {
    if (!arg) reply("ERR ARGS");
    return;
  }
  char type;
  char name[VAULT_NAME_MAX + 1];
  static char value[VAULT_VALUE_MAX + 1];
  VaultStatus st = vaultGet((uint16_t)atoi(arg), type, name, sizeof(name), value, sizeof(value));
  if (st != VAULT_OK) {
    replyStatus(st);
    return;
  }
  char head[8];
  snprintf(head, sizeof(head), "OK %c ", type);
  SerialUSB.print(head);
  writeB64((const uint8_t *)name, strlen(name));
  SerialUSB.print(' ');
  writeB64((const uint8_t *)value, strlen(value));
  SerialUSB.print('\n');
  secureZero(value, sizeof(value));
}

static void cmdAdd(char *type, char *name, char *value) {
  if (!requireSession()) return;
  if (!type || !name || !value || strlen(type) != 1) {
    reply("ERR ARGS");
    return;
  }
  const int nameLen = b64DecodeInPlace(name);
  const int valueLen = b64DecodeInPlace(value);
  if (nameLen < 0 || valueLen < 0) {
    reply("ERR ARGS");
    return;
  }
  const int id = vaultAdd(type[0], name, (size_t)nameLen, value, (size_t)valueLen);
  secureZero(value, (size_t)valueLen);
  if (id <= 0) {
    replyStatus((VaultStatus)id);
    return;
  }
  char buf[16];
  snprintf(buf, sizeof(buf), "OK %d", id);
  reply(buf);
}

static void cmdDel(char *arg) {
  if (!requireSession()) return;
  if (!arg) {
    reply("ERR ARGS");
    return;
  }
  const uint16_t id = (uint16_t)atoi(arg);
  char name[VAULT_NAME_MAX + 1];
  if (!vaultNameOf(id, name, sizeof(name))) {
    reply("ERR NOTFOUND");
    return;
  }
  UiResult r = uiConfirm("DELETE", name, PROMPT_TIMEOUT_MS);
  if (r != UI_APPROVED) {
    reply(r == UI_DENIED ? "ERR DENIED" : "ERR TIMEOUT");
    return;
  }
  replyStatus(vaultDelete(id));
}

static void cmdPkList() {
  if (!requireSession()) return;
  reply("OK");
  PasskeyRecord rec;
  for (uint8_t s = 0; s < PASSKEY_SLOTS; s++) {
    if (!passkeyRead(s, rec)) continue;
    char head[8];
    snprintf(head, sizeof(head), "K %u ", s);
    SerialUSB.print(head);
    writeB64((const uint8_t *)rec.rpId, rec.rpIdLen);
    SerialUSB.print(' ');
    writeB64((const uint8_t *)rec.userName, rec.userNameLen);
    SerialUSB.print(' ');
    writeB64((const uint8_t *)rec.displayName, rec.displayNameLen);
    SerialUSB.print('\n');
  }
  reply("END");
}

static void cmdPkDel(char *arg) {
  if (!requireSession()) return;
  PasskeyRecord rec;
  if (!arg || !passkeyRead((uint8_t)atoi(arg), rec)) {
    reply("ERR NOTFOUND");
    return;
  }
  char site[sizeof(rec.rpId) + 1];
  memcpy(site, rec.rpId, rec.rpIdLen);
  site[rec.rpIdLen] = 0;
  UiResult r = uiConfirm("DELETE PASSKEY", site, PROMPT_TIMEOUT_MS);
  if (r != UI_APPROVED) {
    reply(r == UI_DENIED ? "ERR DENIED" : "ERR TIMEOUT");
    return;
  }
  reply(passkeyDelete((uint8_t)atoi(arg)) ? "OK" : "ERR FAILED");
}

// ---------------------------------------------------------------- backups

// Starts a backup export. After a press on the key the app may read the
// passkey secret (PKEXPORT); it also gets this key's ID and kill token,
// which the app seals into the backup's emergency slot only.
static void cmdExportBegin() {
  if (!requireSession()) return;
  UiResult r = uiConfirm("EXPORT BACKUP", nullptr, PROMPT_TIMEOUT_MS);
  if (r != UI_APPROVED) {
    reply(r == UI_DENIED ? "ERR DENIED" : "ERR TIMEOUT");
    return;
  }
  if (!g_cfg.killTokenSet) {
    rngAddTiming();
    rngBytes(g_cfg.killToken, sizeof(g_cfg.killToken));
    g_cfg.killTokenSet = 1;
    if (!configSave()) {
      g_cfg.killTokenSet = 0;
      reply("ERR FAILED");
      return;
    }
  }
  exportAllowed = true;
  uint8_t id[16];
  deviceId(id);
  SerialUSB.print("OK ");
  writeHex(id, sizeof(id));
  SerialUSB.print(' ');
  writeHex(g_cfg.killToken, sizeof(g_cfg.killToken));
  SerialUSB.print('\n');
}

static void cmdPkExport() {
  if (!requireSession()) return;
  if (!exportAllowed) {
    reply("ERR DENIED");
    return;
  }
  char buf[24];
  snprintf(buf, sizeof(buf), "OK %d ", g_cfg.fidoReady ? 1 : 0);
  SerialUSB.print(buf);
  writeHex(g_cfg.fidoSecret, sizeof(g_cfg.fidoSecret));
  snprintf(buf, sizeof(buf), " %lu\n", (unsigned long)ctap2Counter());
  SerialUSB.print(buf);
  PasskeyRecord rec;
  for (uint8_t s = 0; s < PASSKEY_SLOTS; s++) {
    if (!passkeyRead(s, rec)) continue;
    SerialUSB.print("P ");
    writeB64((const uint8_t *)&rec, sizeof(rec));
    SerialUSB.print('\n');
  }
  secureZero(&rec, sizeof(rec));
  reply("END");
}

// Replaces this key's passkeys with a backup's. Taking over the backup's
// FIDO secret keeps the restored passkeys working on their sites.
static void cmdPkImport(const char *secretHex, const char *counterText) {
  if (!requireSession()) return;
  uint8_t secret[32];
  if (!parseHex(secretHex, secret, sizeof(secret))) {
    reply("ERR ARGS");
    return;
  }
  UiResult r = uiConfirm(passkeyCount() ? "REPLACE PASSKEYS" : "IMPORT PASSKEYS", nullptr,
                         PROMPT_TIMEOUT_MS);
  if (r != UI_APPROVED) {
    secureZero(secret, sizeof(secret));
    reply(r == UI_DENIED ? "ERR DENIED" : "ERR TIMEOUT");
    return;
  }
  bool ok = passkeyWipeAll();
  memcpy(g_cfg.fidoSecret, secret, sizeof(secret));
  secureZero(secret, sizeof(secret));
  g_cfg.fidoReady = 1;
  g_cfg.passkeySeq = 0;
  // Continue above the old key's counter so sites never see it go backwards.
  ctap2ReloadAfterImport(counterText ? (uint32_t)strtoul(counterText, nullptr, 10) + 1 : 0);
  ok &= configSave();
  importAllowed = ok;
  reply(ok ? "OK" : "ERR FAILED");
}

static void cmdPkAdd(char *b64) {
  if (!requireSession()) return;
  if (!importAllowed || !b64) {
    reply("ERR DENIED");
    return;
  }
  PasskeyRecord rec;
  if (b64DecodeInPlace(b64) != (int)sizeof(rec)) {
    reply("ERR ARGS");
    return;
  }
  memcpy(&rec, b64, sizeof(rec));
  secureZero(b64, sizeof(rec));
  if (rec.used != PASSKEY_USED || rec.userIdLen == 0 || rec.userIdLen > sizeof(rec.userId) ||
      rec.rpIdLen > sizeof(rec.rpId) || rec.userNameLen > sizeof(rec.userName) ||
      rec.displayNameLen > sizeof(rec.displayName) || rec.credProtect < 1 || rec.credProtect > 3) {
    reply("ERR ARGS");
    return;
  }
  if (rec.seq > g_cfg.passkeySeq) g_cfg.passkeySeq = rec.seq;
  const int slot = passkeyStore(rec);
  secureZero(&rec, sizeof(rec));
  if (slot < 0) {
    reply("ERR FULL");
    return;
  }
  reply(configSave() ? "OK" : "ERR FAILED");
}

// Remembers an old key that was replaced via an emergency restore, so any
// app this key meets can wipe the old one if it turns up.
static void cmdRevokeAdd(const char *idHex, const char *tokenHex) {
  if (!requireSession()) return;
  RevokedKey k;
  if (!parseHex(idHex, k.deviceId, sizeof(k.deviceId)) || !parseHex(tokenHex, k.token, sizeof(k.token))) {
    reply("ERR ARGS");
    return;
  }
  uint8_t slot = g_cfg.revokedCount < MAX_REVOKED ? g_cfg.revokedCount : MAX_REVOKED;
  for (uint8_t i = 0; i < g_cfg.revokedCount && i < MAX_REVOKED; i++)
    if (!memcmp(g_cfg.revoked[i].deviceId, k.deviceId, sizeof(k.deviceId))) slot = i;
  if (slot == MAX_REVOKED) {  // full: forget the oldest
    memmove(&g_cfg.revoked[0], &g_cfg.revoked[1], sizeof(RevokedKey) * (MAX_REVOKED - 1));
    slot = MAX_REVOKED - 1;
  } else if (slot == g_cfg.revokedCount) {
    g_cfg.revokedCount++;
  }
  g_cfg.revoked[slot] = k;
  reply(configSave() ? "OK" : "ERR FAILED");
}

static void cmdRevokeList() {
  if (!requireSession()) return;
  reply("OK");
  for (uint8_t i = 0; i < g_cfg.revokedCount && i < MAX_REVOKED; i++) {
    SerialUSB.print("R ");
    writeHex(g_cfg.revoked[i].deviceId, sizeof(g_cfg.revoked[i].deviceId));
    SerialUSB.print(' ');
    writeHex(g_cfg.revoked[i].token, sizeof(g_cfg.revoked[i].token));
    SerialUSB.print('\n');
  }
  reply("END");
}

// Wipes everything when given this key's kill token. The token only exists
// in a backup's emergency slot, so no press is needed: by then the owner
// has restored elsewhere and this key may be in the wrong hands.
static void cmdKill(const char *tokenHex) {
  uint8_t token[32];
  if (!g_cfg.killTokenSet || !parseHex(tokenHex, token, sizeof(token)) ||
      !ctEqual(token, g_cfg.killToken, sizeof(token))) {
    reply("ERR DENIED");
    return;
  }
  endSession();
  bool ok = vaultWipeAll();
  ok &= ctap2WipeAll();
  g_cfg.killTokenSet = 0;
  secureZero(g_cfg.killToken, sizeof(g_cfg.killToken));
  g_cfg.revokedCount = 0;
  memset(g_cfg.revoked, 0, sizeof(g_cfg.revoked));
  ok &= configSave();
  reply(ok ? "OK" : "ERR FAILED");
  uiShowIcon(ICON_TRASH, 1500);
}

static void cmdEntropy(const char *hex) {
  uint8_t buf[64];
  size_t n = 0;
  for (const char *p = hex; p && p[0] && p[1] && n < sizeof(buf); p += 2) {
    char tmp[3] = {p[0], p[1], 0};
    buf[n++] = (uint8_t)strtoul(tmp, nullptr, 16);
  }
  rngAddEntropy(buf, n);
  rngAddTiming();
  secureZero(buf, sizeof(buf));
  reply("OK");
}

static void handleLine(char *s) {
  char *save = nullptr;
  char *cmd = strtok_r(s, " ", &save);
  if (!cmd) return;
  char *a1 = strtok_r(nullptr, " ", &save);
  char *a2 = strtok_r(nullptr, " ", &save);
  char *a3 = strtok_r(nullptr, " ", &save);
  lastActivity = millis();

  if (!strcmp(cmd, "HELLO")) {
    char buf[64];
    snprintf(buf, sizeof(buf), "OK UNOKEY %s %s %s ", UNOKEY_VERSION, vaultIsOpen() ? "OPEN" : "LOCKED",
             session ? "SESSION" : "NOSESSION");
    SerialUSB.print(buf);
    uint8_t id[16];
    deviceId(id);
    writeHex(id, sizeof(id));
    SerialUSB.print('\n');
  } else if (!strcmp(cmd, "PING")) {
    reply("OK PONG");
  } else if (!strcmp(cmd, "DIAG")) {
    char buf[64] = "OK ";
    uiDiag(buf + 3, sizeof(buf) - 3);
    reply(buf);
  } else if (!strcmp(cmd, "INFO")) {
    cmdInfo();
  } else if (!strcmp(cmd, "ENTROPY")) {
    cmdEntropy(a1);
  } else if (!strcmp(cmd, "TIME")) {
    if (a1) vaultSetTime((uint32_t)strtoul(a1, nullptr, 10));
    reply("OK");
  } else if (!strcmp(cmd, "UNLOCK")) {
    VaultStatus st = vaultUnlock("APP");
    endSession();
    session = st == VAULT_OK;
    replyStatus(st);
  } else if (!strcmp(cmd, "LOCK")) {
    vaultLock();
    endSession();
    reply("OK");
  } else if (!strcmp(cmd, "CLOSE")) {
    endSession();
    reply("OK");
  } else if (!strcmp(cmd, "LIST")) {
    if (requireSession()) {
      reply("OK");
      vaultForEach(listEntry, nullptr);
      reply("END");
    }
  } else if (!strcmp(cmd, "GET")) {
    cmdGet(a1);
  } else if (!strcmp(cmd, "ADD")) {
    cmdAdd(a1, a2, a3);
  } else if (!strcmp(cmd, "DEL")) {
    cmdDel(a1);
  } else if (!strcmp(cmd, "PKLIST")) {
    cmdPkList();
  } else if (!strcmp(cmd, "PKDEL")) {
    cmdPkDel(a1);
  } else if (!strcmp(cmd, "SETPIN")) {
    if (requireSession()) replyStatus(vaultSetPin());
  } else if (!strcmp(cmd, "WIPEVAULT")) {
    // No session needed: this is how a forgotten PIN gets reset. The key
    // still asks for a press, and nothing is revealed.
    VaultStatus st = vaultErase();
    if (st == VAULT_OK) endSession();
    replyStatus(st);
  } else if (!strcmp(cmd, "EXPORTBEGIN")) {
    cmdExportBegin();
  } else if (!strcmp(cmd, "PKEXPORT")) {
    cmdPkExport();
  } else if (!strcmp(cmd, "PKIMPORT")) {
    cmdPkImport(a1, a2);
  } else if (!strcmp(cmd, "PKADD")) {
    cmdPkAdd(a1);
  } else if (!strcmp(cmd, "REVOKEADD")) {
    cmdRevokeAdd(a1, a2);
  } else if (!strcmp(cmd, "REVOKELIST")) {
    cmdRevokeList();
  } else if (!strcmp(cmd, "KILL")) {
    cmdKill(a1);
  } else {
    reply("ERR UNKNOWN");
  }
}

// ---------------------------------------------------------------- loop

void hostBegin() {
  lineLen = 0;
  endSession();
}

bool hostSessionOpen() { return session; }
void hostEndSession() { endSession(); }

void hostPoll() {
  const bool connected = (bool)SerialUSB;
  if (wasConnected && !connected) {
    endSession();  // app closed the port
    lineLen = 0;
  }
  wasConnected = connected;
  if (session && millis() - lastActivity > SESSION_IDLE_MS) endSession();

  while (SerialUSB.available() > 0) {
    const int c = SerialUSB.read();
    if (c < 0) break;
    if (c == '\r') continue;
    if (c == '\n') {
      if (overflowed) {
        reply("ERR TOOLONG");
      } else {
        line[lineLen] = 0;
        handleLine(line);
      }
      secureZero(line, sizeof(line));
      lineLen = 0;
      overflowed = false;
      continue;
    }
    if (lineLen < sizeof(line) - 1) line[lineLen++] = (char)c;
    else overflowed = true;
  }
}
