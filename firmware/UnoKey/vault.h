// Encrypted vault for passphrases, codes and 2FA (TOTP) secrets.
//
// Every entry is sealed with ChaCha20-Poly1305 under a random data key. That
// key is stored wrapped by a key derived from the device secret and, if one
// is set, the vault PIN entered on the joystick (PBKDF2). Too many wrong
// PINs wipe the vault.
#pragma once
#include <stdint.h>
#include <stddef.h>

enum VaultStatus : int8_t {
  VAULT_OK = 0,
  VAULT_DENIED = -1,
  VAULT_TIMEOUT = -2,
  VAULT_BAD_PIN = -3,
  VAULT_WIPED = -4,
  VAULT_LOCKED = -5,
  VAULT_FULL = -6,
  VAULT_NOT_FOUND = -7,
  VAULT_TOO_LONG = -8,
  VAULT_ERROR = -9,
  VAULT_CANCELLED = -10,
  VAULT_NO_JOYSTICK = -11,
};

// Entry types.
static const char VAULT_PASSPHRASE = 'P';
static const char VAULT_CODE = 'C';
static const char VAULT_TOTP = 'T';

void vaultBegin();
bool vaultIsOpen();
bool vaultHasPin();
uint8_t vaultPinTriesLeft();
// Asks on the device: the PIN if one is set and hasn't been entered since
// plug-in, otherwise a click.
VaultStatus vaultUnlock(const char *who);
// Forgets the data key; the PIN is needed again.
void vaultLock();
VaultStatus vaultSetPin();
// Deletes every entry and the vault PIN after a confirmation on the key.
// Works while locked, so a forgotten PIN can always be reset. Passkeys stay.
VaultStatus vaultErase();
// Same without asking (used by a full wipe).
bool vaultWipeAll();
int vaultCount();
size_t vaultBytesUsed();
size_t vaultBytesTotal();

// Calls fn for each entry with its decrypted name. Needs the vault open.
void vaultForEach(void (*fn)(uint16_t id, char type, const char *name, size_t nameLen, void *ctx),
                  void *ctx);
// Copies an entry. value is NUL-terminated; valueCap should be > VAULT_VALUE_MAX.
VaultStatus vaultGet(uint16_t id, char &type, char *name, size_t nameCap, char *value,
                     size_t valueCap);
// Returns the new entry's id (> 0) or a VaultStatus.
int vaultAdd(char type, const char *name, size_t nameLen, const char *value, size_t valueLen);
VaultStatus vaultDelete(uint16_t id);
bool vaultNameOf(uint16_t id, char *name, size_t cap);

void vaultSetTime(uint32_t unixTime);
// Current TOTP code for a stored 2FA value; false if the time is unknown.
bool vaultTotp(const char *value, char *code, size_t cap);
void vaultBrowseOnDevice();
