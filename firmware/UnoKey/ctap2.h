// CTAP 2.0 authenticator: passkeys (resident keys), PIN protocol 1, ES256.
#pragma once
#include <stdint.h>
#include <stddef.h>

void ctap2Begin();
// Erases every passkey, the FIDO secret and the passkey PIN (no prompt).
bool ctap2WipeAll();
// Re-reads the FIDO secret after a backup import; the signature counter
// jumps to at least minCounter so sites never see it go backwards.
void ctap2ReloadAfterImport(uint32_t minCounter);
uint32_t ctap2Counter();
// Runs one request (command byte + CBOR). Writes the status byte and CBOR
// response into resp and returns its length.
size_t ctap2Handle(const uint8_t *req, size_t reqLen, uint8_t *resp, size_t respCap);
