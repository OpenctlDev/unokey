#include "ui.h"
#include "config.h"
#include "app.h"
#include <Arduino.h>
#include "Arduino_LED_Matrix.h"
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------- font
// 3x5 glyphs for ASCII 32..95. Five rows of three bits, left column = 4.
#define G(a, b, c, d, e) (uint16_t)(((a) << 12) | ((b) << 9) | ((c) << 6) | ((d) << 3) | (e))
static const uint16_t FONT[64] = {
    G(0, 0, 0, 0, 0), G(2, 2, 2, 0, 2), G(5, 5, 0, 0, 0), G(5, 7, 5, 7, 5),  //  !"#
    G(3, 6, 2, 3, 6), G(5, 1, 2, 4, 5), G(2, 5, 2, 5, 3), G(2, 2, 0, 0, 0),  // $%&'
    G(1, 2, 2, 2, 1), G(4, 2, 2, 2, 4), G(0, 5, 2, 5, 0), G(0, 2, 7, 2, 0),  // ()*+
    G(0, 0, 0, 2, 4), G(0, 0, 7, 0, 0), G(0, 0, 0, 0, 2), G(1, 1, 2, 4, 4),  // ,-./
    G(3, 5, 5, 5, 6), G(2, 6, 2, 2, 2), G(6, 1, 2, 4, 7), G(6, 1, 2, 1, 6),  // 0123
    G(5, 5, 7, 1, 1), G(7, 4, 6, 1, 6), G(3, 4, 7, 5, 7), G(7, 1, 2, 4, 4),  // 4567
    G(7, 5, 7, 5, 7), G(7, 5, 7, 1, 6), G(0, 2, 0, 2, 0), G(0, 2, 0, 2, 4),  // 89:;
    G(1, 2, 4, 2, 1), G(0, 7, 0, 7, 0), G(4, 2, 1, 2, 4), G(7, 1, 3, 0, 2),  // <=>?
    G(7, 5, 7, 4, 7), G(2, 5, 7, 5, 5), G(6, 5, 6, 5, 6), G(3, 4, 4, 4, 3),  // @ABC
    G(6, 5, 5, 5, 6), G(7, 4, 7, 4, 7), G(7, 4, 7, 4, 4), G(3, 4, 7, 5, 3),  // DEFG
    G(5, 5, 7, 5, 5), G(7, 2, 2, 2, 7), G(1, 1, 1, 5, 2), G(5, 5, 6, 5, 5),  // HIJK
    G(4, 4, 4, 4, 7), G(5, 7, 7, 5, 5), G(5, 7, 7, 7, 5), G(2, 5, 5, 5, 2),  // LMNO
    G(6, 5, 6, 4, 4), G(2, 5, 5, 7, 3), G(6, 5, 7, 6, 5), G(3, 4, 2, 1, 6),  // PQRS
    G(7, 2, 2, 2, 2), G(5, 5, 5, 5, 3), G(5, 5, 5, 2, 2), G(5, 5, 7, 7, 5),  // TUVW
    G(5, 5, 2, 5, 5), G(5, 5, 2, 2, 2), G(7, 1, 2, 4, 7), G(6, 4, 4, 4, 6),  // XYZ[
    G(4, 4, 2, 1, 1), G(3, 1, 1, 1, 3), G(2, 5, 0, 0, 0), G(0, 0, 0, 0, 7),  // \]^_
};

// 5x7 digits for PIN entry, one byte per row (bit 4 = left column).
static const uint8_t BIG_DIGITS[10][7] = {
    {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E}, {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E},
    {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F}, {0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E},
    {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02}, {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E},
    {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E}, {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
    {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E}, {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C},
};

static const char *const ICONS[][8] = {
    {"............", "..###.......", ".#...#......", ".#...#######", ".#...#...#.#",
     "..###....#.#", "............", "............"},  // key
    {"....####....", "...#....#...", "...#....#...", "..########..", "..###..###..",
     "..###..###..", "..########..", "............"},  // lock
    {"....####....", "...#....#...", "...#........", "..########..", "..###..###..",
     "..###..###..", "..########..", "............"},  // unlock
    {"............", "..........#.", ".........##.", "........##..", ".##....##...",
     "..##..##....", "...####.....", "....##......"},  // check
    {"............", "..##....##..", "...##..##...", "....####....", ".....##.....",
     "....####....", "...##..##...", "..##....##.."},  // cross
    {"....####....", "..########..", "...#....#...", "...#.##.#...", "...#.##.#...",
     "...#.##.#...", "...#....#...", "....####...."},  // trash
    {".....##.....", ".....##.....", ".....##.....", ".....##.....", "............",
     ".....##.....", ".....##.....", "............"},  // warn
    {"............", "..##....##..", "..##....##..", "............", ".#........#.",
     "..#......#..", "...######...", "............"},  // smile
};

static const char *const MENU_LABELS[MENU_COUNT] = {"VAULT", "LOCK", "PIN", "INFO"};

// ---------------------------------------------------------------- display

static ArduinoLEDMatrix matrix;
static uint8_t fb[8][12];
static uint32_t lastFlush;

static void fbClear() { memset(fb, 0, sizeof(fb)); }

static void px(int x, int y) {
  if (x >= 0 && x < 12 && y >= 0 && y < 8) fb[y][x] = 1;
}

static void flush() {
  matrix.renderBitmap(fb, 8, 12);
  lastFlush = millis();
}

static void flushThrottled() {
  if (millis() - lastFlush >= 20) flush();
}

static void drawIcon(UiIcon icon) {
  fbClear();
  for (int y = 0; y < 8; y++)
    for (int x = 0; x < 12; x++)
      if (ICONS[icon][y][x] == '#') fb[y][x] = 1;
}

static uint16_t glyph(char c) {
  if (c >= 'a' && c <= 'z') c = (char)(c - 32);
  if (c >= 32 && c <= 95) return FONT[c - 32];
  switch (c) {
    case '`': return G(4, 2, 0, 0, 0);
    case '{': return G(3, 2, 6, 2, 3);
    case '|': return G(2, 2, 2, 2, 2);
    case '}': return G(6, 2, 3, 2, 6);
    case '~': return G(0, 0, 3, 6, 0);
    default: return FONT['?' - 32];
  }
}

// Draws one character at rows y0..y0+4; a lowercase letter also gets a dot
// at row y0+6 when markLower is set.
static void drawChar(char c, int x0, int y0, bool markLower) {
  uint16_t g = glyph(c);
  for (int r = 0; r < 5; r++) {
    uint8_t bits = (uint8_t)((g >> (12 - 3 * r)) & 7);
    for (int cx = 0; cx < 3; cx++)
      if (bits & (4 >> cx)) px(x0 + cx, y0 + r);
  }
  if (markLower && c >= 'a' && c <= 'z') px(x0 + 1, y0 + 6);
}

static void drawBigDigit(uint8_t d, int x0, int y0) {
  for (int r = 0; r < 7; r++)
    for (int cx = 0; cx < 5; cx++)
      if (BIG_DIGITS[d][r] & (0x10 >> cx)) px(x0 + cx, y0 + r);
}

struct Scroller {
  const char *text;
  uint16_t len;
  int16_t pos;
  uint32_t last;
  bool markLower;
};

static void scrollInit(Scroller &s, const char *text, bool markLower) {
  s.text = text;
  s.len = (uint16_t)strlen(text);
  s.pos = 0;
  s.last = millis();
  s.markLower = markLower;
}

// Short text is centred; longer text scrolls right to left. Returns true
// whenever a scrolling pass completes.
static bool scrollDraw(Scroller &s, int y0, uint16_t stepMs) {
  const int width = s.len ? s.len * 4 - 1 : 0;
  if (width <= 12) {
    const int x0 = (12 - width) / 2;
    for (uint16_t i = 0; i < s.len; i++) drawChar(s.text[i], x0 + 4 * i, y0, s.markLower);
    return false;
  }
  bool wrapped = false;
  if (millis() - s.last >= stepMs) {
    s.last = millis();
    if (++s.pos > width + 12) {
      s.pos = 0;
      wrapped = true;
    }
  }
  const int offset = 12 - s.pos;
  for (uint16_t i = 0; i < s.len; i++) {
    const int x = offset + 4 * i;
    if (x > 11) break;
    if (x >= -3) drawChar(s.text[i], x, y0, s.markLower);
  }
  return wrapped;
}

// Copies "a b" into dst in uppercase, with unsupported characters as '?'.
static void promptText(char *dst, size_t cap, const char *a, const char *b) {
  size_t n = 0;
  for (int part = 0; part < 2; part++) {
    const char *s = part ? b : a;
    if (!s || !*s) continue;
    if (n && n + 1 < cap) dst[n++] = ' ';
    for (; *s && n + 1 < cap; s++) {
      char c = *s;
      if (c >= 'a' && c <= 'z') c = (char)(c - 32);
      if (c < 32 || c > 126) c = '?';
      dst[n++] = c;
    }
  }
  dst[n] = 0;
}

// ---------------------------------------------------------------- input

enum Ev : uint8_t { EV_NONE, EV_UP, EV_DOWN, EV_LEFT, EV_RIGHT, EV_CLICK, EV_LONG, EV_OK };

static int joyCx = 512, joyCy = 512;
static bool joyPresent = false;  // set by the first click on the stick
static uint8_t joyDir, joyPending, joyPendingCount;
static uint32_t joyLastSample, joyNextRepeat;
static bool btnRaw, btnState, swRaw, swState, swLongFired;
static uint32_t btnChangeMs, swChangeMs, swDownMs;

// Measures the stick's resting position. Runs when the stick is clicked:
// unconnected analog pins float and can look like a centred stick, so the
// axes only count once a click has shown that a joystick is really there.
static void calibrateJoystick() {
  long sx = 0, sy = 0;
  for (int i = 0; i < 16; i++) {
    sx += analogRead(PIN_JOY_X);
    sy += analogRead(PIN_JOY_Y);
    delay(2);
  }
  joyCx = (int)(sx / 16);
  joyCy = (int)(sy / 16);
  joyPresent = joyCx > 200 && joyCx < 824 && joyCy > 200 && joyCy < 824;
}

static uint8_t sampleJoystick() {
  if (!joyPresent) return EV_NONE;
  int x = analogRead(PIN_JOY_X) - joyCx;
  int y = analogRead(PIN_JOY_Y) - joyCy;
  if (JOY_SWAP_XY) {
    int t = x;
    x = y;
    y = t;
  }
  if (JOY_INVERT_X) x = -x;
  if (JOY_INVERT_Y) y = -y;
  const int ax = abs(x), ay = abs(y);
  const int m = ax > ay ? ax : ay;
  if (m < 120) return EV_NONE;  // centred
  if (m < 250) return joyDir;   // between thresholds: keep what we had
  if (ax >= ay) return x < 0 ? EV_LEFT : EV_RIGHT;
  return y < 0 ? EV_UP : EV_DOWN;
}

// Forget held keys so a press from before a prompt doesn't answer it.
static void resetInput() {
  btnState = btnRaw = digitalRead(PIN_BUTTON) == LOW;
  swState = swRaw = digitalRead(PIN_JOY_SW) == LOW;
  swLongFired = true;  // a click already held down doesn't count
  joyDir = sampleJoystick();
  joyPending = joyDir;
  // A direction already held must be released first; no auto-repeat.
  joyNextRepeat = millis() + 0x7FFFFFFFUL;
}

static uint8_t pollEvent() {
  const uint32_t now = millis();

  const bool b = digitalRead(PIN_BUTTON) == LOW;
  if (b != btnRaw) {
    btnRaw = b;
    btnChangeMs = now;
  }
  if (now - btnChangeMs > 25 && btnRaw != btnState) {
    btnState = btnRaw;
    if (btnState) return EV_OK;
  }

  const bool s = digitalRead(PIN_JOY_SW) == LOW;
  if (s != swRaw) {
    swRaw = s;
    swChangeMs = now;
  }
  if (now - swChangeMs > 25 && swRaw != swState) {
    swState = swRaw;
    if (swState) {
      swDownMs = now;
      swLongFired = false;
    } else if (!swLongFired) {
      // A click proves a joystick is wired even if start-up missed it.
      if (!joyPresent) calibrateJoystick();
      return EV_CLICK;
    }
  }
  if (swState && !swLongFired && now - swDownMs > 700) {
    swLongFired = true;
    if (!joyPresent) calibrateJoystick();
    return EV_LONG;
  }

  if (now - joyLastSample >= 10) {
    joyLastSample = now;
    const uint8_t d = sampleJoystick();
    if (d != joyPending) {
      joyPending = d;
      joyPendingCount = 0;
    } else if (joyPendingCount < 2) {
      joyPendingCount++;
    } else if (d != joyDir) {
      joyDir = d;
      if (d != EV_NONE) {
        joyNextRepeat = now + 450;
        return d;
      }
    }
  }
  if (joyDir != EV_NONE && (int32_t)(now - joyNextRepeat) >= 0) {
    joyNextRepeat = now + 160;
    return joyDir;
  }
  return EV_NONE;
}

static uint8_t tick() {
  appServiceWhileBusy();
  return pollEvent();
}

// ---------------------------------------------------------------- idle / menu

enum Mode : uint8_t { MODE_IDLE, MODE_MENU };
static Mode mode = MODE_IDLE;
static UiIcon idleIcon = ICON_KEY;
static uint8_t menuSel;
static uint32_t menuSince, winkUntil;
static Scroller menuScroll;
static void (*menuHandler)(uint8_t item);

void uiBegin() {
  matrix.begin();
  resetInput();
  drawIcon(ICON_KEY);
  flush();
}

void uiSetIdleIcon(UiIcon icon) { idleIcon = icon; }
bool uiJoystickPresent() { return joyPresent; }

void uiDiag(char *buf, size_t cap) {
  snprintf(buf, cap, "%d %d %d %d %d %d %d", analogRead(PIN_JOY_X), analogRead(PIN_JOY_Y), joyCx,
           joyCy, joyPresent ? 1 : 0, digitalRead(PIN_BUTTON) == LOW ? 1 : 0,
           digitalRead(PIN_JOY_SW) == LOW ? 1 : 0);
}
void uiSetMenuHandler(void (*handler)(uint8_t item)) { menuHandler = handler; }
void uiWink() { winkUntil = millis() + 1600; }

void uiPoll() {
  const uint8_t ev = pollEvent();
  const uint32_t now = millis();
  if (mode == MODE_IDLE) {
    // Only a deliberate long press on the joystick opens the menu, so extra
    // presses around a confirmation can't wander into it.
    if (ev == EV_LONG) {
      mode = MODE_MENU;
      menuSel = 0;
      menuSince = now;
      scrollInit(menuScroll, MENU_LABELS[menuSel], false);
    } else {
      if ((int32_t)(winkUntil - now) > 0) {
        if ((now / 200) & 1) drawIcon(ICON_SMILE);
        else fbClear();
      } else {
        drawIcon(idleIcon);
      }
      flushThrottled();
      return;
    }
  }

  if (ev != EV_NONE) menuSince = now;
  if (ev == EV_UP || ev == EV_DOWN) {
    menuSel = (uint8_t)((menuSel + (ev == EV_DOWN ? 1 : MENU_COUNT - 1)) % MENU_COUNT);
    scrollInit(menuScroll, MENU_LABELS[menuSel], false);
  } else if (ev == EV_LEFT || now - menuSince > 15000 || appInterruptPending()) {
    mode = MODE_IDLE;
    return;
  } else if (ev == EV_OK || ev == EV_CLICK || ev == EV_RIGHT) {
    mode = MODE_IDLE;
    if (menuHandler) menuHandler(menuSel);
    resetInput();
    return;
  }
  fbClear();
  scrollDraw(menuScroll, 1, 70);
  px(1 + menuSel * 3, 7);  // which item of four
  px(2 + menuSel * 3, 7);
  flushThrottled();
}

// ---------------------------------------------------------------- prompts

void uiShowIcon(UiIcon icon, uint16_t ms) {
  drawIcon(icon);
  flush();
  const uint32_t start = millis();
  while (millis() - start < ms) appServiceWhileBusy();
}

UiResult uiConfirm(const char *title, const char *detail, uint32_t timeoutMs) {
  char text[80];
  promptText(text, sizeof(text), title, detail);
  Scroller s;
  scrollInit(s, text, false);
  const uint32_t start = millis();
  resetInput();
  for (;;) {
    if (appCancelRequested()) {
      uiShowIcon(ICON_CROSS, 300);
      return UI_CANCELLED;
    }
    const uint32_t elapsed = millis() - start;
    if (elapsed >= timeoutMs) {
      uiShowIcon(ICON_CROSS, 400);
      return UI_TIMEOUT;
    }
    const uint8_t ev = tick();
    if (ev == EV_OK || ev == EV_CLICK) {
      uiShowIcon(ICON_CHECK, 350);
      return UI_APPROVED;
    }
    if (ev == EV_LEFT) {
      uiShowIcon(ICON_CROSS, 350);
      return UI_DENIED;
    }
    fbClear();
    scrollDraw(s, 1, 65);
    // Countdown bar; it blinks during the last five seconds.
    const int bar = 12 - (int)((uint64_t)elapsed * 12 / timeoutMs);
    const bool lit = timeoutMs - elapsed > 5000 || ((millis() / 250) & 1);
    if (lit)
      for (int x = 0; x < bar; x++) px(x, 7);
    flushThrottled();
  }
}

// Waits for a click on the stick so we know a joystick is there. The button
// backs out. Returns true once the joystick is usable.
static bool waitForJoystick() {
  Scroller s;
  scrollInit(s, "CLICK STICK", false);
  const uint32_t start = millis();
  resetInput();
  while (!joyPresent) {
    if (appCancelRequested() || millis() - start > 30000) return false;
    if (tick() == EV_OK) return false;
    fbClear();
    scrollDraw(s, 1, 60);
    flushThrottled();
  }
  return true;
}

int uiEnterPin(const char *title, char *pin, uint8_t minLen, uint8_t maxLen) {
  if (!joyPresent && !waitForJoystick()) {
    memset(pin, 0, maxLen + 1);
    uiShowIcon(ICON_CROSS, 300);
    return -2;
  }
  char text[32];
  promptText(text, sizeof(text), title, nullptr);
  Scroller s;
  scrollInit(s, text, false);
  uint8_t len = 0, digit = 0;
  bool showTitle = true;
  uint32_t lastInput = millis();
  resetInput();
  for (;;) {
    if (appCancelRequested() || millis() - lastInput > PIN_TIMEOUT_MS) {
      memset(pin, 0, maxLen + 1);
      uiShowIcon(ICON_CROSS, 300);
      return -1;
    }
    const uint8_t ev = tick();
    if (ev != EV_NONE) {
      lastInput = millis();
      if (showTitle) {
        showTitle = false;  // first key only dismisses the title
        continue;
      }
    }
    switch (ev) {
      case EV_UP: digit = (uint8_t)((digit + 1) % 10); break;
      case EV_DOWN: digit = (uint8_t)((digit + 9) % 10); break;
      case EV_RIGHT:
      case EV_CLICK:
        if (len < maxLen) {
          pin[len++] = (char)('0' + digit);
          digit = 0;
        }
        break;
      case EV_LEFT:
        if (len == 0) {
          memset(pin, 0, maxLen + 1);
          return -1;
        }
        len--;
        break;
      case EV_OK:
      case EV_LONG:
        if (len == 0) {  // nothing entered: the button backs out
          memset(pin, 0, maxLen + 1);
          uiShowIcon(ICON_CROSS, 300);
          return -1;
        }
        if (len >= minLen) {
          pin[len] = 0;
          return len;
        }
        uiShowIcon(ICON_CROSS, 300);
        break;
      default: break;
    }
    fbClear();
    if (showTitle) {
      if (scrollDraw(s, 1, 60)) showTitle = false;
    } else {
      drawBigDigit(digit, 3, 0);
      px(10, 1);  // up/down hint
      px(9, 2);
      px(11, 2);
      px(9, 4);
      px(11, 4);
      px(10, 5);
      for (uint8_t i = 0; i < len; i++) px(i, 7);  // one dot per digit entered
    }
    flushThrottled();
  }
}

int uiChooseList(int count, int start, void (*label)(int index, char *buf, size_t cap, void *ctx),
                 void *ctx) {
  if (count <= 0) return -1;
  int sel = start % count;
  char buf[48];
  label(sel, buf, sizeof(buf), ctx);
  Scroller s;
  scrollInit(s, buf, true);
  uint32_t lastInput = millis();
  resetInput();
  for (;;) {
    if (millis() - lastInput > 60000 || appInterruptPending()) return -1;
    const uint8_t ev = tick();
    if (ev != EV_NONE) lastInput = millis();
    if (ev == EV_UP || ev == EV_DOWN) {
      sel = (sel + (ev == EV_DOWN ? 1 : count - 1)) % count;
      label(sel, buf, sizeof(buf), ctx);
      scrollInit(s, buf, true);
    } else if (ev == EV_LEFT) {
      return -1;
    } else if (ev == EV_OK || ev == EV_CLICK || ev == EV_RIGHT) {
      return sel;
    }
    fbClear();
    scrollDraw(s, 0, 60);
    px(count > 1 ? sel * 11 / (count - 1) : 0, 7);  // position in the list
    flushThrottled();
  }
}

void uiShowText(const char *text) {
  Scroller s;
  scrollInit(s, text, true);
  uint32_t start = millis();
  resetInput();
  for (;;) {
    const uint8_t ev = tick();
    if (ev == EV_LEFT || ev == EV_OK || ev == EV_CLICK || ev == EV_RIGHT) return;
    if (millis() - start > 600000) return;  // long enough for several passes of a seed phrase
    if (appInterruptPending()) return;
    fbClear();
    scrollDraw(s, 1, 90);
    flushThrottled();
  }
}

void uiScrollOnce(const char *text) {
  char upper[96];
  promptText(upper, sizeof(upper), text, nullptr);
  Scroller s;
  scrollInit(s, upper, false);
  const uint32_t start = millis();
  resetInput();
  for (;;) {
    if (tick() != EV_NONE || appInterruptPending()) return;
    fbClear();
    const bool done = scrollDraw(s, 1, 60);
    flushThrottled();
    if (done || (s.len * 4 - 1 <= 12 && millis() - start > 1500)) return;
  }
}
