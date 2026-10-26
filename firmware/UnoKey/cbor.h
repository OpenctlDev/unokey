// Minimal CBOR (RFC 8949) writer/reader for CTAP2.
// Writer always produces canonical encodings; callers must emit map keys in
// canonical order themselves. Reader accepts definite-length items only.
#pragma once
#include <stdint.h>
#include <stddef.h>

enum CborMajor : uint8_t {
  CBOR_UINT = 0,
  CBOR_NEGINT = 1,
  CBOR_BYTES = 2,
  CBOR_TEXT = 3,
  CBOR_ARRAY = 4,
  CBOR_MAP = 5,
  CBOR_TAG = 6,
  CBOR_SIMPLE = 7,
  CBOR_NONE = 0xFF,
};

struct CborWriter {
  uint8_t *buf;
  size_t cap;
  size_t len;
  bool overflow;
};

void cborWriterInit(CborWriter &w, uint8_t *buf, size_t cap);
void cborPutUint(CborWriter &w, uint64_t v);
void cborPutInt(CborWriter &w, int64_t v);
void cborPutBytes(CborWriter &w, const uint8_t *data, size_t n);
void cborPutText(CborWriter &w, const char *s, size_t n);
void cborPutText(CborWriter &w, const char *s);
void cborPutArray(CborWriter &w, size_t n);
void cborPutMap(CborWriter &w, size_t n);
void cborPutBool(CborWriter &w, bool b);
void cborPutRaw(CborWriter &w, const uint8_t *data, size_t n);

struct CborReader {
  const uint8_t *p;
  const uint8_t *end;
  bool error;
};

void cborReaderInit(CborReader &r, const uint8_t *data, size_t n);
bool cborAtEnd(const CborReader &r);
uint8_t cborPeekMajor(const CborReader &r);
bool cborGetUint(CborReader &r, uint64_t &v);
bool cborGetInt(CborReader &r, int64_t &v);
bool cborGetBytes(CborReader &r, const uint8_t *&data, size_t &n);
bool cborGetText(CborReader &r, const char *&s, size_t &n);
bool cborGetArray(CborReader &r, size_t &n);
bool cborGetMap(CborReader &r, size_t &n);
bool cborGetBool(CborReader &r, bool &b);
bool cborSkip(CborReader &r);
// Skips one item and returns where it started and how long it was.
bool cborCapture(CborReader &r, const uint8_t *&start, size_t &n);

bool cborTextEquals(const char *s, size_t n, const char *lit);
