// LED matrix (12x8) screens and joystick/button input.
#pragma once
#include <stdint.h>
#include <stddef.h>

enum UiResult : uint8_t { UI_APPROVED, UI_DENIED, UI_TIMEOUT, UI_CANCELLED };
enum UiIcon : uint8_t { ICON_KEY, ICON_LOCK, ICON_UNLOCK, ICON_CHECK, ICON_CROSS, ICON_TRASH, ICON_WARN, ICON_SMILE };
enum UiMenuItem : uint8_t { MENU_VAULT, MENU_LOCK, MENU_PIN, MENU_INFO, MENU_COUNT };

void uiBegin();
// Idle screen and the on-device menu (opened by holding the joystick button).
// Non-blocking; call from loop().
void uiPoll();
void uiSetIdleIcon(UiIcon icon);
void uiSetMenuHandler(void (*handler)(uint8_t item));
void uiWink();
// False until the joystick button has been clicked since power-up; until
// then its axes are ignored, so floating pins can't fake key presses.
bool uiJoystickPresent();
// Raw readings for troubleshooting wiring: "x y centreX centreY present button stick".
void uiDiag(char *buf, size_t cap);

// Blocking prompts. They keep USB serviced while waiting.
// Approve with the button or a joystick click, deny with joystick left.
UiResult uiConfirm(const char *title, const char *detail, uint32_t timeoutMs);
// Joystick up/down picks a digit, click/right adds it, left deletes, the
// button submits (or cancels while nothing is entered yet). If the joystick
// hasn't been clicked since power-up it first asks for a click. Returns the
// PIN length, -1 if cancelled or timed out, -2 if there is no joystick.
int uiEnterPin(const char *title, char *pin, uint8_t minLen, uint8_t maxLen);
// Scrolls a list of labels; returns the chosen index or -1.
int uiChooseList(int count, int start, void (*label)(int index, char *buf, size_t cap, void *ctx),
                 void *ctx);
// Scrolls text until the user presses something. Lowercase letters get a dot
// underneath so passwords keep their case.
void uiShowText(const char *text);
void uiScrollOnce(const char *text);
void uiShowIcon(UiIcon icon, uint16_t ms);
