#include "cbor.h"
#include <string.h>

// ---------------------------------------------------------------- writer

void cborWriterInit(CborWriter &w, uint8_t *buf, size_t cap) {
  w.buf = buf;
  w.cap = cap;
  w.len = 0;
  w.overflow = false;
}

static void putByte(CborWriter &w, uint8_t b) {
  if (w.len >= w.cap) {
    w.overflow = true;
    return;
  }
  w.buf[w.len++] = b;
}

static void putHead(CborWriter &w, uint8_t major, uint64_t v) {
  const uint8_t mt = (uint8_t)(major << 5);
  if (v < 24) {
    putByte(w, mt | (uint8_t)v);
  } else if (v <= 0xFF) {
    putByte(w, mt | 24);
    putByte(w, (uint8_t)v);
  } else if (v <= 0xFFFF) {
    putByte(w, mt | 25);
    putByte(w, (uint8_t)(v >> 8));
    putByte(w, (uint8_t)v);
  } else if (v <= 0xFFFFFFFFULL) {
    putByte(w, mt | 26);
    for (int i = 3; i >= 0; i--) putByte(w, (uint8_t)(v >> (8 * i)));
  } else {
    putByte(w, mt | 27);
    for (int i = 7; i >= 0; i--) putByte(w, (uint8_t)(v >> (8 * i)));
  }
}

void cborPutUint(CborWriter &w, uint64_t v) { putHead(w, CBOR_UINT, v); }

void cborPutInt(CborWriter &w, int64_t v) {
  if (v >= 0) putHead(w, CBOR_UINT, (uint64_t)v);
  else putHead(w, CBOR_NEGINT, (uint64_t)(-1 - v));
}

void cborPutRaw(CborWriter &w, const uint8_t *data, size_t n) {
  if (w.len + n > w.cap) {
    w.overflow = true;
    return;
  }
  memcpy(w.buf + w.len, data, n);
  w.len += n;
}

void cborPutBytes(CborWriter &w, const uint8_t *data, size_t n) {
  putHead(w, CBOR_BYTES, n);
  cborPutRaw(w, data, n);
}

void cborPutText(CborWriter &w, const char *s, size_t n) {
  putHead(w, CBOR_TEXT, n);
  cborPutRaw(w, (const uint8_t *)s, n);
}

void cborPutText(CborWriter &w, const char *s) { cborPutText(w, s, strlen(s)); }
void cborPutArray(CborWriter &w, size_t n) { putHead(w, CBOR_ARRAY, n); }
void cborPutMap(CborWriter &w, size_t n) { putHead(w, CBOR_MAP, n); }
void cborPutBool(CborWriter &w, bool b) { putByte(w, b ? 0xF5 : 0xF4); }

// ---------------------------------------------------------------- reader

void cborReaderInit(CborReader &r, const uint8_t *data, size_t n) {
  r.p = data;
  r.end = data + n;
  r.error = false;
}

bool cborAtEnd(const CborReader &r) { return r.p >= r.end; }

uint8_t cborPeekMajor(const CborReader &r) {
  if (r.error || r.p >= r.end) return CBOR_NONE;
  return (uint8_t)(r.p[0] >> 5);
}

static bool fail(CborReader &r) {
  r.error = true;
  return false;
}

// Reads an item head; returns major type and argument.
static bool getHead(CborReader &r, uint8_t &major, uint64_t &arg) {
  if (r.error || r.p >= r.end) return fail(r);
  const uint8_t ib = *r.p++;
  major = (uint8_t)(ib >> 5);
  const uint8_t ai = ib & 0x1F;
  if (ai < 24) {
    arg = ai;
    return true;
  }
  size_t n;
  switch (ai) {
    case 24: n = 1; break;
    case 25: n = 2; break;
    case 26: n = 4; break;
    case 27: n = 8; break;
    default: return fail(r);  // reserved or indefinite length
  }
  if ((size_t)(r.end - r.p) < n) return fail(r);
  arg = 0;
  for (size_t i = 0; i < n; i++) arg = (arg << 8) | *r.p++;
  return true;
}

static bool getHeadOf(CborReader &r, uint8_t want, uint64_t &arg) {
  const uint8_t *save = r.p;
  uint8_t major;
  if (!getHead(r, major, arg)) return false;
  if (major != want) {
    r.p = save;
    return fail(r);
  }
  return true;
}

bool cborGetUint(CborReader &r, uint64_t &v) { return getHeadOf(r, CBOR_UINT, v); }

bool cborGetInt(CborReader &r, int64_t &v) {
  uint8_t major;
  uint64_t arg;
  if (!getHead(r, major, arg)) return false;
  if (arg > 0x7FFFFFFFFFFFFFFFULL) return fail(r);
  if (major == CBOR_UINT) {
    v = (int64_t)arg;
    return true;
  }
  if (major == CBOR_NEGINT) {
    v = -1 - (int64_t)arg;
    return true;
  }
  return fail(r);
}

static bool getString(CborReader &r, uint8_t major, const uint8_t *&data, size_t &n) {
  uint64_t len;
  if (!getHeadOf(r, major, len)) return false;
  if (len > (uint64_t)(r.end - r.p)) return fail(r);
  data = r.p;
  n = (size_t)len;
  r.p += n;
  return true;
}

bool cborGetBytes(CborReader &r, const uint8_t *&data, size_t &n) {
  return getString(r, CBOR_BYTES, data, n);
}

bool cborGetText(CborReader &r, const char *&s, size_t &n) {
  const uint8_t *d;
  if (!getString(r, CBOR_TEXT, d, n)) return false;
  s = (const char *)d;
  return true;
}

bool cborGetArray(CborReader &r, size_t &n) {
  uint64_t v;
  if (!getHeadOf(r, CBOR_ARRAY, v)) return false;
  if (v > 0xFFFF) return fail(r);
  n = (size_t)v;
  return true;
}

bool cborGetMap(CborReader &r, size_t &n) {
  uint64_t v;
  if (!getHeadOf(r, CBOR_MAP, v)) return false;
  if (v > 0xFFFF) return fail(r);
  n = (size_t)v;
  return true;
}

bool cborGetBool(CborReader &r, bool &b) {
  if (r.error || r.p >= r.end) return fail(r);
  if (*r.p == 0xF5) b = true;
  else if (*r.p == 0xF4) b = false;
  else return fail(r);
  r.p++;
  return true;
}

static bool skipDepth(CborReader &r, int depth) {
  if (depth > 10) return fail(r);
  uint8_t major;
  uint64_t arg;
  if (!getHead(r, major, arg)) return false;
  switch (major) {
    case CBOR_UINT:
    case CBOR_NEGINT:
      return true;
    case CBOR_BYTES:
    case CBOR_TEXT:
      if (arg > (uint64_t)(r.end - r.p)) return fail(r);
      r.p += arg;
      return true;
    case CBOR_ARRAY:
      for (uint64_t i = 0; i < arg; i++)
        if (!skipDepth(r, depth + 1)) return false;
      return true;
    case CBOR_MAP:
      for (uint64_t i = 0; i < arg; i++) {
        if (!skipDepth(r, depth + 1)) return false;
        if (!skipDepth(r, depth + 1)) return false;
      }
      return true;
    case CBOR_TAG:
      return skipDepth(r, depth + 1);
    default:  // simple values and floats: getHead already consumed them
      return true;
  }
}

bool cborSkip(CborReader &r) { return skipDepth(r, 0); }

bool cborCapture(CborReader &r, const uint8_t *&start, size_t &n) {
  start = r.p;
  if (!cborSkip(r)) return false;
  n = (size_t)(r.p - start);
  return true;
}

bool cborTextEquals(const char *s, size_t n, const char *lit) {
  return strlen(lit) == n && memcmp(s, lit, n) == 0;
}
