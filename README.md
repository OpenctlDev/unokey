# UnoKey

Create passkeys and a secure vault with UnoKey on your Arduino UNO R4 WiFi.

> **Status: experimental hobby project, not security-audited.** It uses standard crypto
> (P-256, ChaCha20-Poly1305, SHA-256/HMAC, scrypt via BearSSL and Python), but an Arduino has
> no secure chip. Read [Security](#security-what-this-protects-and-what-it-doesnt) before
> trusting it with anything important, and keep paper backups of seed phrases.

Turns an **Arduino UNO R4 WiFi** into:

- a **FIDO2 security key with real passkeys** (stored on the key, protected by a PIN that
  Windows/your browser asks for),
- an **encrypted vault** for crypto seed phrases, passwords/codes and 2FA (TOTP) secrets,
  unlocked on the key itself (button, or a PIN entered with a joystick on the LED matrix),
- **encrypted backups** (`.unokey` files) with an optional emergency password that marks a
  lost key for wiping,
- plus **UnoKey Vault**, a desktop app for Windows and Linux to copy, add and delete
  vault entries, manage passkeys and make or restore backups.

```
firmware/UnoKey/   Arduino sketch (UnoKey.ino + modules)
app/               desktop app (unokey_app.py), Windows build script, Linux files
```

Licensed under the [MIT License](LICENSE).

## Wiring

All parts connect straight to the Arduino's headers. No resistors are needed: the inputs
use the chip's built-in pull-ups.

**Accept button** (any push button)

| Button leg | Arduino pin |
|---|---|
| leg 1 | **D2** |
| leg 2 | **GND** |

With a 4-leg tactile button, use two legs that are diagonally opposite.

**Joystick module** (the common 5-pin "KY-023" type: GND, +5V, VRx, VRy, SW)

| Joystick pin | Arduino pin |
|---|---|
| GND | **GND** |
| +5V | **5V** |
| VRx | **A0** |
| VRy | **A1** |
| SW  | **D3** |

```
          UNO R4 WiFi
   +---------------------------+
   |  D2 o----[ BUTTON ]----o GND
   |  D3 o-------------------- SW  \
   |  A0 o-------------------- VRx  |
   |  A1 o-------------------- VRy  |  joystick
   |  5V o-------------------- +5V  |
   | GND o-------------------- GND /
   +---------------------------+
```

If up/down or left/right come out reversed, flip `JOY_INVERT_Y`, `JOY_INVERT_X` or
`JOY_SWAP_XY` in `firmware/UnoKey/config.h` and upload again.

After each plug-in the key ignores the stick's directions until you **click the joystick
button once**, so unconnected pins can't fake presses. The key asks with `CLICK STICK`
when it needs it. Without a joystick everything except the vault PIN and the key's own menu
works with the button alone.

## Using the key

| You want to… | Do this |
|---|---|
| Approve a login, a new passkey, the app, a delete | Press the **button** (or click the joystick) |
| Decline | Push the joystick **left** |
| Open the menu (key idle) | **Hold the joystick button** down for about a second, then up/down: **VAULT**, **LOCK**, **PIN**, **INFO**. Left goes back. |
| Enter a PIN | Up/down picks a digit, **click** (or right) adds it, **left** deletes, **button** confirms. Pressing the button before any digit cancels. |

While asking, the matrix scrolls what is being requested (for example `LOGIN GITHUB.COM`),
and the bottom row is a countdown. The idle screen shows a key, or an open padlock while
the vault is unlocked.

When the app or a website needs the key, the menu and vault browsing close by themselves
so the request's prompt shows up.

**VAULT** on the key lets you read entries right on the LED matrix without a PC. Seed
phrases and passwords scroll by; lowercase letters have a dot underneath. 2FA entries show
the current code once the app has told the key the time.

## Passkeys

Use the key wherever a site offers "Create a passkey" or "Add security key". On Windows,
pick **Security key** (Sicherheitsschlüssel) in the Windows dialog. The first time, Windows
asks you to create a **security key PIN**. That PIN protects your passkeys, and Windows or
the browser asks for it at sign-in. Then press the button on the key.

- Up to **12 passkeys** fit on the key. The app lists them and can delete them.
- Windows' "Reset security key" erases all passkeys. To prevent accidents this only works
  within 30 seconds of plugging the key in. The vault is **not** affected.

## Desktop app (UnoKey Vault)

**Windows**: run `app\build_windows.bat` once to get `app\dist\UnoKeyVault.exe`, or run
`py app\unokey_app.py` directly (needs Python 3 and `pip install pyserial`).

**Linux**:

```sh
sudo apt install python3-tk python3-serial        # Debian/Ubuntu
sudo cp app/linux/70-unokey.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
sh app/linux/run_unokey.sh
```

Then plug in the key. The app finds it and asks it to unlock. Confirm on the key (and enter
your vault PIN on the joystick if you set one). After that you can:

- **Copy** an entry (double-click works too). The clipboard is cleared after 30 seconds.
- **Show** it. Seed phrases are listed word by word, and the window hides after 60 seconds.
- **Add** a passphrase, a code/password or a 2FA secret. For 2FA, paste the base32 secret or
  the `otpauth://` link behind the QR code. The app shows live 6-digit codes.
- **Delete** entries and passkeys. The key asks you to confirm each delete.
- **Set the vault PIN** (Key tab). You enter it on the key, never on the PC. This needs the
  joystick: without one the key refuses instead of getting stuck.
- **Erase vault and reset its PIN** (Key tab) if you forget the vault PIN. It deletes all
  vault entries and the PIN after you confirm on the key. Passkeys are not touched.

The PIN is needed once after each plug-in. After that, each new app session only needs a
button press, until you choose **Lock** or unplug the key.

## Backups (.unokey files)

App → **Backup** tab:

- **Export backup…** asks for a backup password (8+ characters), an optional **emergency
  password**, and whether to include passkeys. Then press the button on the key when it
  scrolls `EXPORT BACKUP`. The file is encrypted: scrypt per password, then HMAC-SHA256
  counter-mode encryption with an HMAC tag.
- **Import backup…** opens a file with either password. Vault entries that are already on
  the key are skipped. Restoring passkeys replaces the passkeys on that key, and the key asks
  you to confirm. Restored passkeys keep working on their websites.
- **Emergency password:** opens the same backup and also marks the old key as **lost**. The
  new key and the app remember that. The moment the old key is plugged into a computer
  running UnoKey Vault that knows about it, the old key is **wiped completely**: vault,
  passkeys and PINs. This happens without a button press, using a secret stored only in the
  backup's emergency slot. The computer that knows about it is the one where you restored,
  or any other where you later use the new key.
- **Limit:** a lost key that never gets plugged into such a computer can't be wiped. Your
  vault PIN is what protects it then. Until it's wiped it also still holds the same
  passkeys, so after an emergency restore consider replacing the passkeys at important sites.

## Security: what this protects and what it doesn't

- Everything in the vault is encrypted (ChaCha20-Poly1305). The key for it is derived from
  a random device secret and your vault PIN (PBKDF2, 8000 rounds). **10 wrong PINs wipe the
  vault.**
- Nothing is released without a physical press on the key, so software on the PC can't
  silently read your vault or use your passkeys.
- **Set a vault PIN.** Without one, anyone holding the key can unlock the vault with a
  single press.
- **Limits:** an Arduino has no secure element. Someone who steals the board and knows how
  to read out its flash with debugging tools can attack a short PIN offline. Treat UnoKey
  as a convenient, private second copy, and **keep paper backups of your seed phrases**.
  For large crypto amounts, use a real hardware wallet.
- When you copy or show a secret, it is on your PC for that moment. Only do that on a PC
  you trust.
- **Randomness:** the RA4M1's hardware random generator isn't available through the
  Arduino core. Keys come from an HMAC-DRBG seeded with ADC noise and clock jitter, a seed
  carried over from the previous boot, and randomness sent by the desktop app. Long-term
  secrets are only created on first use, after the app has contributed its share.
- **Backups:** scrypt (N=2^16, r=8, p=1) per password, then HMAC-SHA-256 in counter mode with
  an HMAC-SHA-256 tag (encrypt-then-MAC). A backup is only as strong as its password.
  Including passkeys in a backup makes them copyable by whoever has the file and password.
- **Not audited, not FIDO-certified.** The CTAP 2.0 implementation was written for this
  project. Reviews and issue reports are welcome.

## Building and flashing the firmware

1. Arduino IDE → Boards Manager → install **Arduino UNO R4 Boards**.
   Library Manager → install **ArduinoBearSSL** (accept its dependency ArduinoECCX08).
2. Open `firmware/UnoKey/UnoKey.ino`, select **Arduino UNO R4 WiFi**, click **Upload**.

Or from a terminal:

```sh
arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi firmware/UnoKey
arduino-cli upload  --fqbn arduino:renesas_uno:unor4wifi -p <port> firmware/UnoKey
```

If an upload can't find the board, **double-press the RESET button** and upload again. The
board then shows up as "UNO R4 WiFi" on a different COM port. When running Windows in a
virtual machine, that bootloader mode is a different USB device (2341:1002), so pass the
whole USB port through to the VM, not just the device ID.

## Troubleshooting

- **App says "isn't running UnoKey"**: the Arduino still has other firmware. Flash UnoKey.
- **Forgot the vault PIN**: app → Key tab → **Erase vault and reset its PIN**, then press
  the button on the key. **Forgot the passkey PIN**: Windows Settings → Accounts → Sign-in
  options → Security key → Manage → Reset (re-plug the key first; it erases the passkeys).
- **Power lost while setting a PIN**: nothing is half-saved. The key keeps either the old or
  the new PIN.
- **Linux: "No permission to open /dev/ttyACM0"**: install the udev rule above and re-plug
  the key, or add yourself to the `dialout` group.
- **Matrix shows "!" at start-up**: the flash storage couldn't be opened. Re-flash the firmware.
- **Joystick moves by itself or drifts**: unplug and plug in again while not touching it.
