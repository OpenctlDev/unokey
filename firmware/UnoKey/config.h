// UnoKey configuration: wiring, limits and identifiers.
#pragma once
#include <Arduino.h>

#define UNOKEY_VERSION "1.0.0"
#define UNOKEY_VERSION_MAJOR 1
#define UNOKEY_VERSION_MINOR 0
#define UNOKEY_VERSION_BUILD 0

// ---------------------------------------------------------------- wiring
// Accept button: one leg to D2, the other leg to GND (internal pull-up).
static const uint8_t PIN_BUTTON = 2;
// Joystick module (KY-023 style): SW -> D3, VRx -> A0, VRy -> A1,
// +5V -> 5V, GND -> GND.
static const uint8_t PIN_JOY_SW = 3;
static const uint8_t PIN_JOY_X = A0;
static const uint8_t PIN_JOY_Y = A1;
// Flip these if the joystick directions come out wrong on the display.
static const bool JOY_SWAP_XY = false;
static const bool JOY_INVERT_X = false;
static const bool JOY_INVERT_Y = false;

// ---------------------------------------------------------------- timing
static const uint32_t UP_TIMEOUT_MS = 30000;         // FIDO "press to confirm"
static const uint32_t PROMPT_TIMEOUT_MS = 60000;     // app/vault prompts
static const uint32_t PIN_TIMEOUT_MS = 90000;        // idle time in PIN entry
static const uint32_t SESSION_IDLE_MS = 10UL * 60UL * 1000UL;
static const uint32_t FIDO_RESET_WINDOW_MS = 30000;  // reset only soon after plug-in

// ---------------------------------------------------------------- FIDO2
// AAGUID of this authenticator model (random, specific to UnoKey).
static const uint8_t UNOKEY_AAGUID[16] = {0x4f, 0x2c, 0x9b, 0x1e, 0x7a, 0x63, 0x4d, 0x0b,
                                          0x9e, 0x51, 0xc8, 0x2a, 0x6d, 0xf3, 0x10, 0xb7};
static const size_t CTAP_MAX_MSG = 1200;             // advertised maxMsgSize
static const uint8_t CTAP_MAX_CRED_IN_LIST = 8;
static const uint8_t FIDO_PIN_MAX_RETRIES = 8;
static const size_t CRED_ID_LEN = 34;

// ---------------------------------------------------------------- vault
static const uint8_t VAULT_PIN_MIN = 4;
static const uint8_t VAULT_PIN_MAX = 8;
static const uint8_t VAULT_PIN_MAX_FAILS = 10;       // wipe vault after this many
static const uint32_t VAULT_PBKDF2_ITER = 8000;
static const size_t VAULT_NAME_MAX = 32;
static const size_t VAULT_VALUE_MAX = 400;
