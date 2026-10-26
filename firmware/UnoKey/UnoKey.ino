// UnoKey: FIDO2 passkey security key + encrypted vault for the Arduino UNO R4 WiFi.
//
// Wiring (see README.md):
//   accept button   D2 <-> GND
//   joystick        SW -> D3, VRx -> A0, VRy -> A1, +5V -> 5V, GND -> GND
//
// Needs the "Arduino UNO R4 Boards" package and the ArduinoBearSSL library.

#include "config.h"
#include "app.h"
#include "crypto.h"
#include "ctap2.h"
#include "ctaphid.h"
#include "hostproto.h"
#include "passkeys.h"
#include "storage.h"
#include "ui.h"
#include "vault.h"
#include <stdio.h>

void appServiceWhileBusy() { ctaphidPollBusy(); }
bool appCancelRequested() { return ctaphidCancelled(); }
bool appInterruptPending() { return SerialUSB.available() > 0 || ctaphidRequestRefused(); }

static void onMenu(uint8_t item) {
  switch (item) {
    case MENU_VAULT:
      vaultBrowseOnDevice();
      break;
    case MENU_LOCK:
      vaultLock();
      hostEndSession();
      uiShowIcon(ICON_LOCK, 600);
      break;
    case MENU_PIN:
      vaultSetPin();
      break;
    case MENU_INFO: {
      char text[64];
      snprintf(text, sizeof(text), "PASSKEYS %d/%u  VAULT %d  V%s", passkeyCount(),
               (unsigned)PASSKEY_SLOTS, vaultCount(), UNOKEY_VERSION);
      uiScrollOnce(text);
      break;
    }
  }
}

void setup() {
  pinMode(PIN_BUTTON, INPUT_PULLUP);
  pinMode(PIN_JOY_SW, INPUT_PULLUP);
  uiBegin();

  const bool flashOk = storageBegin();
  configLoad();
  cryptoBegin(g_cfg.rngSeed);
  // Carry fresh randomness into the next boot as well. This save also tells
  // us early whether the flash can be written at all.
  rngBytes(g_cfg.rngSeed, sizeof(g_cfg.rngSeed));
  const bool saved = flashOk && configSave();

  ctap2Begin();
  vaultBegin();
  ctaphidBegin();
  hostBegin();
  SerialUSB.begin(115200);
  uiSetMenuHandler(onMenu);
  if (!saved) uiShowIcon(ICON_WARN, 3000);
}

void loop() {
  ctaphidPoll();
  hostPoll();
  uiSetIdleIcon(vaultIsOpen() ? ICON_UNLOCK : ICON_KEY);
  uiPoll();
}
