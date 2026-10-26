#include "ctaphid.h"
#include "ctap2.h"
#include "crypto.h"
#include "config.h"
#include "ui.h"
#include <Arduino.h>
#include "tusb.h"
#include "device/usbd_pvt.h"
#include <string.h>

// ---------------------------------------------------------------- USB hooks
// The UNO R4 core builds its USB descriptors from these weak hooks: defining
// __USBGetHIDReport adds a HID interface next to the CDC serial port, and
// __maybe_start_usb switches the USB-C port from the ESP32 bridge over to
// the RA4M1's own USB.

static const uint8_t FIDO_REPORT_DESC[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
    0x09, 0x01,        // Usage (CTAPHID)
    0xA1, 0x01,        // Collection (Application)
    0x09, 0x20,        //   Usage (Input Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x81, 0x02,        //   Input (Data, Var, Abs)
    0x09, 0x21,        //   Usage (Output Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x91, 0x02,        //   Output (Data, Var, Abs)
    0xC0,              // End Collection
};

void __USBStart();

void __maybe_start_usb() { __USBStart(); }

uint8_t *__USBGetHIDReport(size_t *len) {
  *len = sizeof(FIDO_REPORT_DESC);
  return (uint8_t *)FIDO_REPORT_DESC;
}

// Output reports arrive in the USB interrupt; queue them for the main loop.
static const uint8_t RX_SLOTS = 16;
static uint8_t rxRing[RX_SLOTS][64];
static volatile uint8_t rxHead, rxTail;

extern "C" void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                                      hid_report_type_t report_type, uint8_t const *buffer,
                                      uint16_t bufsize) {
  (void)instance;
  (void)report_id;
  if (report_type == HID_REPORT_TYPE_FEATURE || report_type == HID_REPORT_TYPE_INPUT) return;
  const uint8_t next = (uint8_t)((rxHead + 1) % RX_SLOTS);
  if (next == rxTail) return;  // full: drop, the host will time out and retry
  memset(rxRing[rxHead], 0, 64);
  memcpy(rxRing[rxHead], buffer, bufsize < 64 ? bufsize : 64);
  __DMB();
  rxHead = next;
}

extern "C" uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                                          hid_report_type_t report_type, uint8_t *buffer,
                                          uint16_t reqlen) {
  (void)instance;
  (void)report_id;
  (void)report_type;
  (void)buffer;
  (void)reqlen;
  return 0;
}

static bool popPacket(uint8_t pkt[64]) {
  if (rxTail == rxHead) return false;
  memcpy(pkt, rxRing[rxTail], 64);
  __DMB();
  rxTail = (uint8_t)((rxTail + 1) % RX_SLOTS);
  return true;
}

static bool sendPacket(const uint8_t pkt[64]) {
  const uint32_t start = millis();
  while (!tud_hid_ready()) {
    if (millis() - start > 250) return false;
  }
  // tud_task runs inside the USB interrupt on this core, so mask it while we
  // queue the transfer (the same way the core's SerialUSB does).
  usbd_int_set(false);
  const bool ok = tud_hid_report(0, pkt, 64);
  usbd_int_set(true);
  return ok;
}

// ---------------------------------------------------------------- CTAPHID

enum : uint8_t {
  CMD_PING = 0x81,
  CMD_MSG = 0x83,
  CMD_LOCK = 0x84,
  CMD_INIT = 0x86,
  CMD_WINK = 0x88,
  CMD_CBOR = 0x90,
  CMD_CANCEL = 0x91,
  CMD_KEEPALIVE = 0xBB,
  CMD_ERROR = 0xBF,
};
enum : uint8_t {
  ERR_INVALID_CMD = 0x01,
  ERR_INVALID_LEN = 0x03,
  ERR_INVALID_SEQ = 0x04,
  ERR_MSG_TIMEOUT = 0x05,
  ERR_CHANNEL_BUSY = 0x06,
  ERR_INVALID_CHANNEL = 0x0B,
};
static const uint8_t CAP_WINK = 0x01, CAP_CBOR = 0x04, CAP_NMSG = 0x08;
static const uint8_t KEEPALIVE_UPNEEDED = 2;
static const uint32_t CID_BROADCAST = 0xFFFFFFFF;

static uint8_t msg[CTAP_MAX_MSG];
static uint8_t resp[CTAP_MAX_MSG];

static struct {
  bool active;
  uint32_t cid;
  uint8_t cmd;
  uint16_t len;
  uint16_t got;
  uint8_t seq;
  uint32_t lastMs;
} rx;

static uint32_t nextCid = 1;
static uint32_t activeCid;  // channel whose CBOR request is running
static bool processing;
static bool cancelled;
static bool refused;  // a request was answered "busy" while a screen was up
static uint32_t lastKeepalive;

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void putBe32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void sendMessage(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len) {
  uint8_t pkt[64];
  memset(pkt, 0, sizeof(pkt));
  putBe32(pkt, cid);
  pkt[4] = cmd;
  pkt[5] = (uint8_t)(len >> 8);
  pkt[6] = (uint8_t)len;
  uint16_t off = len < 57 ? len : 57;
  if (off) memcpy(pkt + 7, data, off);
  if (!sendPacket(pkt)) return;
  for (uint8_t seq = 0; off < len && seq < 128; seq++) {
    memset(pkt, 0, sizeof(pkt));
    putBe32(pkt, cid);
    pkt[4] = seq;
    const uint16_t n = (uint16_t)(len - off) < 59 ? (uint16_t)(len - off) : 59;
    memcpy(pkt + 5, data + off, n);
    off = (uint16_t)(off + n);
    if (!sendPacket(pkt)) return;
  }
}

static void sendError(uint32_t cid, uint8_t code) { sendMessage(cid, CMD_ERROR, &code, 1); }

static void handleInit(uint32_t cid, const uint8_t *nonce, uint16_t bcnt) {
  if (bcnt != 8) {
    sendError(cid, ERR_INVALID_LEN);
    return;
  }
  uint8_t r[17];
  memcpy(r, nonce, 8);
  uint32_t newCid = cid;
  if (cid == CID_BROADCAST) {
    newCid = nextCid++;
    if (nextCid == CID_BROADCAST) nextCid = 1;
  } else if (rx.active && rx.cid == cid) {
    rx.active = false;  // resync aborts a half-received message
  }
  putBe32(r + 8, newCid);
  r[12] = 2;  // CTAPHID protocol version
  r[13] = UNOKEY_VERSION_MAJOR;
  r[14] = UNOKEY_VERSION_MINOR;
  r[15] = UNOKEY_VERSION_BUILD;
  r[16] = CAP_WINK | CAP_CBOR | CAP_NMSG;
  sendMessage(cid, CMD_INIT, r, sizeof(r));
}

static void dispatch(uint32_t cid, uint8_t cmd, uint16_t len) {
  switch (cmd) {
    case CMD_PING:
      sendMessage(cid, CMD_PING, msg, len);
      break;
    case CMD_WINK:
      uiWink();
      sendMessage(cid, CMD_WINK, nullptr, 0);
      break;
    case CMD_CBOR: {
      if (len == 0) {
        sendError(cid, ERR_INVALID_LEN);
        break;
      }
      rngAddTiming();
      rngAddEntropy(msg, len < 64 ? len : 64);
      activeCid = cid;
      processing = true;
      cancelled = false;
      lastKeepalive = millis();
      const size_t n = ctap2Handle(msg, len, resp, sizeof(resp));
      processing = false;
      sendMessage(cid, CMD_CBOR, resp, (uint16_t)n);
      break;
    }
    case CMD_CANCEL:
      break;  // nothing running
    default:
      sendError(cid, ERR_INVALID_CMD);  // includes U2F MSG: CTAP2 only
      break;
  }
}

static void handlePacket(const uint8_t *p) {
  const uint32_t cid = be32(p);
  if (p[4] & 0x80) {
    const uint8_t cmd = p[4];
    const uint16_t bcnt = (uint16_t)((p[5] << 8) | p[6]);
    if (cmd == CMD_INIT) {
      handleInit(cid, p + 7, bcnt);
      return;
    }
    if (cid == 0 || cid == CID_BROADCAST) {
      sendError(cid, ERR_INVALID_CHANNEL);
      return;
    }
    if (rx.active) {
      sendError(cid, rx.cid == cid ? ERR_INVALID_SEQ : ERR_CHANNEL_BUSY);
      if (rx.cid == cid) rx.active = false;
      return;
    }
    if (bcnt > sizeof(msg)) {
      sendError(cid, ERR_INVALID_LEN);
      return;
    }
    const uint16_t take = bcnt < 57 ? bcnt : 57;
    memcpy(msg, p + 7, take);
    if (take == bcnt) {
      dispatch(cid, cmd, bcnt);
      return;
    }
    rx.active = true;
    rx.cid = cid;
    rx.cmd = cmd;
    rx.len = bcnt;
    rx.got = take;
    rx.seq = 0;
    rx.lastMs = millis();
    return;
  }
  // Continuation packet; ones that don't belong to our message are ignored.
  if (!rx.active || rx.cid != cid) return;
  if (p[4] != rx.seq) {
    sendError(cid, ERR_INVALID_SEQ);
    rx.active = false;
    return;
  }
  rx.seq++;
  const uint16_t left = (uint16_t)(rx.len - rx.got);
  const uint16_t take = left < 59 ? left : 59;
  memcpy(msg + rx.got, p + 5, take);
  rx.got = (uint16_t)(rx.got + take);
  rx.lastMs = millis();
  if (rx.got == rx.len) {
    rx.active = false;
    dispatch(cid, rx.cmd, rx.len);
  }
}

void ctaphidBegin() {
  rx.active = false;
  rxHead = rxTail = 0;
}

void ctaphidPoll() {
  uint8_t pkt[64];
  refused = false;
  while (popPacket(pkt)) handlePacket(pkt);
  if (rx.active && millis() - rx.lastMs > 500) {
    sendError(rx.cid, ERR_MSG_TIMEOUT);
    rx.active = false;
  }
}

void ctaphidPollBusy() {
  uint8_t pkt[64];
  while (popPacket(pkt)) {
    if (!(pkt[4] & 0x80)) continue;  // continuation of something we refused
    const uint32_t cid = be32(pkt);
    const uint8_t cmd = pkt[4];
    if (cmd == CMD_INIT) {
      if (processing && cid == activeCid) cancelled = true;
      handleInit(cid, pkt + 7, (uint16_t)((pkt[5] << 8) | pkt[6]));
    } else if (cmd == CMD_CANCEL) {
      if (processing && cid == activeCid) cancelled = true;
    } else {
      sendError(cid, ERR_CHANNEL_BUSY);  // the host retries shortly
      refused = true;
    }
  }
  if (processing && millis() - lastKeepalive >= 100) {
    lastKeepalive = millis();
    const uint8_t status = KEEPALIVE_UPNEEDED;
    sendMessage(activeCid, CMD_KEEPALIVE, &status, 1);
  }
}

bool ctaphidCancelled() { return processing && cancelled; }
bool ctaphidRequestRefused() { return refused; }
