#!/usr/bin/env python3
"""UnoKey Vault: desktop app for the UnoKey security key (Arduino UNO R4 WiFi).

Plug in the key and confirm on it (button, or the vault PIN on the joystick).
Then copy, add or delete passphrases, codes and 2FA secrets, manage the
passkeys stored on the key, and make or restore encrypted .unokey backups.
Runs on Windows and Linux with Python 3.9+, tkinter and pyserial.
"""

import base64
import binascii
import datetime
import hashlib
import hmac
import json
import os
import queue
import struct
import sys
import threading
import time
import tkinter as tk
import urllib.parse
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover - shown to the user instead
    serial = None

APP_NAME = "UnoKey Vault"
USB_VID, USB_PID = 0x2341, 0x006D  # UNO R4 WiFi running its own USB
CLIPBOARD_CLEAR_SECONDS = 30
NAME_MAX, VALUE_MAX = 32, 400
TYPES = {"P": "Passphrase", "C": "Code / password", "T": "2FA code (TOTP)"}
DEVICE_ERRORS = {
    "DENIED": "You declined on the key.",
    "TIMEOUT": "Nothing was pressed on the key in time.",
    "CANCELLED": "Cancelled on the key.",
    "WIPED": "Too many wrong PINs: the key wiped its vault.",
    "LOCKED": "The vault is locked. Unlock it on the key first.",
    "FULL": "The key's vault is full.",
    "TOOLONG": "That is too long for the key.",
    "NOTFOUND": "That entry no longer exists.",
    "NOJOYSTICK": "Entering a PIN needs the joystick. When the key scrolls CLICK STICK, click "
                  "the joystick button. No joystick yet? Wire it up first "
                  "(VRx → A0, VRy → A1, SW → D3, +5V → 5V, GND → GND).",
}


# ---------------------------------------------------------------- helpers

def b64e(text: str) -> str:
    data = text.encode("utf-8")
    return base64.b64encode(data).decode("ascii") if data else "="


def b64d(field: str) -> str:
    if field in ("", "="):
        return ""
    return base64.b64decode(field + "=" * (-len(field) % 4)).decode("utf-8", "replace")


def describe_error(err: Exception) -> str:
    text = str(err)
    if text.startswith("PIN"):
        left = text.split(" ")[-1]
        return f"Wrong PIN. {left} tries left before the vault is wiped."
    return DEVICE_ERRORS.get(text, text)


def parse_totp(value: str):
    """Splits a stored 2FA value ("SECRET;digits=8;...") into its parts."""
    secret, *params = value.split(";")
    digits, period, algo = 6, 30, "SHA1"
    for p in params:
        key, _, val = p.partition("=")
        if key == "digits":
            digits = int(val)
        elif key == "period":
            period = int(val)
        elif key == "algo":
            algo = val.upper()
    clean = secret.replace(" ", "").upper().rstrip("=")
    key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    return key, digits, period, algo


def totp_now(value: str):
    """Returns (code, seconds left) for a stored 2FA value."""
    key, digits, period, algo = parse_totp(value)
    now = time.time()
    digest = hashlib.sha256 if algo == "SHA256" else hashlib.sha1
    mac = hmac.new(key, struct.pack(">Q", int(now // period)), digest).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits), period - int(now) % period


def normalize_totp(text: str):
    """Accepts a base32 secret or an otpauth:// link. Returns (value, label)."""
    text = text.strip()
    label = ""
    digits, period, algo = 6, 30, "SHA1"
    if text.lower().startswith("otpauth://"):
        url = urllib.parse.urlparse(text)
        query = urllib.parse.parse_qs(url.query)
        if "secret" not in query:
            raise ValueError("The otpauth link has no secret in it.")
        secret = query["secret"][0]
        digits = int(query.get("digits", ["6"])[0])
        period = int(query.get("period", ["30"])[0])
        algo = query.get("algorithm", ["SHA1"])[0].upper()
        label = urllib.parse.unquote(url.path.lstrip("/"))
    else:
        secret = text
    secret = secret.replace(" ", "").upper().rstrip("=")
    if algo not in ("SHA1", "SHA256"):
        raise ValueError("Only SHA1 and SHA256 2FA codes are supported.")
    if digits not in (6, 7, 8) or period <= 0:
        raise ValueError("Unsupported 2FA settings.")
    try:
        if not base64.b32decode(secret + "=" * (-len(secret) % 8)):
            raise ValueError
    except (binascii.Error, ValueError):
        raise ValueError("That doesn't look like a 2FA secret (base32 letters A-Z and 2-7).")
    value = secret
    if digits != 6:
        value += f";digits={digits}"
    if period != 30:
        value += f";period={period}"
    if algo == "SHA256":
        value += ";algo=SHA256"
    return value, label


# ---------------------------------------------------------------- backup files
#
# A .unokey file is JSON. The payload (vault entries and, optionally, the
# passkeys) is encrypted with a random content key. Each password "slot"
# holds that content key, encrypted with a key derived from the password by
# scrypt. The emergency slot additionally holds the old key's ID and kill
# token, so only the emergency password can mark the old key as lost.
# Encryption is HMAC-SHA256 in counter mode with an HMAC-SHA256 tag
# (encrypt-then-MAC): Python's standard library has no AES, and this keeps
# the app free of extra dependencies.

BACKUP_FORMAT = "unokey-backup"
BACKUP_KDF = {"name": "scrypt", "n": 2 ** 16, "r": 8, "p": 1}
MIN_BACKUP_PASSWORD = 8


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


def _derive_key(password: str, salt: bytes, kdf: dict) -> bytes:
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    if kdf.get("name") != "scrypt" or not (2 ** 10 <= n <= 2 ** 20 and 1 <= r <= 32 and 1 <= p <= 4):
        raise ValueError("Unsupported key derivation settings in this file.")
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=1024 * 1024 * 1024, dklen=32)


def _stream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    mixed = int.from_bytes(data, "big") ^ int.from_bytes(bytes(stream[:len(data)]), "big")
    return mixed.to_bytes(len(data), "big")


def _seal(key: bytes, data: bytes, context: bytes) -> dict:
    enc = hmac.new(key, b"unokey-backup enc", hashlib.sha256).digest()
    mac = hmac.new(key, b"unokey-backup mac", hashlib.sha256).digest()
    nonce = os.urandom(16)
    ciphertext = _stream_xor(enc, nonce, data)
    tag = hmac.new(mac, context + nonce + ciphertext, hashlib.sha256).digest()
    return {"nonce": _b64(nonce), "data": _b64(ciphertext), "mac": _b64(tag)}


def _unseal(key: bytes, box: dict, context: bytes) -> bytes:
    enc = hmac.new(key, b"unokey-backup enc", hashlib.sha256).digest()
    mac = hmac.new(key, b"unokey-backup mac", hashlib.sha256).digest()
    nonce, ciphertext = _unb64(box["nonce"]), _unb64(box["data"])
    expected = hmac.new(mac, context + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _unb64(box["mac"])):
        raise ValueError("wrong key")
    return _stream_xor(enc, nonce, ciphertext)


def _slot_context(kind: str, salt: bytes) -> bytes:
    return b"slot:" + kind.encode("ascii") + b":" + salt


def write_backup(path, payload, password, emergency_password=None, old_key=None):
    """old_key: (device_id, kill_token) bytes, stored in the emergency slot only."""
    content_key = os.urandom(32)
    secrets = [("main", password, content_key)]
    if emergency_password:
        device_id, kill_token = old_key
        secrets.append(("emergency", emergency_password, content_key + kill_token + device_id))
    slots = []
    for kind, pw, secret in secrets:
        salt = os.urandom(16)
        box = _seal(_derive_key(pw, salt, BACKUP_KDF), secret, _slot_context(kind, salt))
        slots.append({"kind": kind, "salt": _b64(salt), **box})
    doc = {
        "format": BACKUP_FORMAT,
        "version": 1,
        "kdf": BACKUP_KDF,
        "slots": slots,
        "payload": _seal(content_key, json.dumps(payload).encode("utf-8"), b"payload"),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    os.replace(tmp, path)


def read_backup(path, password):
    """Returns (payload, emergency) where emergency is None or
    {"device_id": bytes, "kill_token": bytes} when the emergency password was used."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        raise ValueError("That file can't be read as an UnoKey backup.")
    if doc.get("format") != BACKUP_FORMAT or doc.get("version") != 1:
        raise ValueError("That isn't an UnoKey backup (or it was made by a newer version).")
    for slot in doc.get("slots", []):
        salt = _unb64(slot["salt"])
        try:
            secret = _unseal(_derive_key(password, salt, doc["kdf"]), slot, _slot_context(slot["kind"], salt))
        except ValueError:
            continue
        emergency = None
        if slot["kind"] == "emergency" and len(secret) >= 80:
            emergency = {"kill_token": secret[32:64], "device_id": secret[64:80]}
        try:
            payload = json.loads(_unseal(secret[:32], doc["payload"], b"payload").decode("utf-8"))
        except ValueError:
            raise ValueError("The backup file is damaged.")
        return payload, emergency
    raise ValueError("Wrong password for this backup.")


# Keys reported lost by an emergency restore: device ID -> kill token (hex).
# If one of them is plugged in, the app wipes it.

def _config_dir():
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "UnoKey")


REVOKED_FILE = os.path.join(_config_dir(), "revoked-keys.json")


def load_revoked():
    try:
        with open(REVOKED_FILE, "r", encoding="utf-8") as f:
            return {str(k).lower(): str(v).lower() for k, v in json.load(f).items()}
    except (OSError, ValueError, AttributeError):
        return {}


def save_revoked(revoked):
    os.makedirs(os.path.dirname(REVOKED_FILE), exist_ok=True)
    with open(REVOKED_FILE, "w", encoding="utf-8") as f:
        json.dump(revoked, f, indent=1)


# ---------------------------------------------------------------- device link

class DeviceError(Exception):
    pass


class Device:
    """An open serial connection to an UnoKey."""

    def __init__(self, port: str):
        kwargs = {"baudrate": 115200, "timeout": 0.2, "write_timeout": 3}
        if os.name == "posix":
            kwargs["exclusive"] = True  # keep other programs off the port
        self.port = port
        self.ser = serial.Serial(port, **kwargs)
        self.buf = b""
        time.sleep(0.1)
        self.ser.reset_input_buffer()

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def _line(self, deadline: float):
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line, self.buf = self.buf[:nl], self.buf[nl + 1:]
                return line.decode("ascii", "replace").strip()
            if time.monotonic() > deadline:
                return None
            chunk = self.ser.read(self.ser.in_waiting or 1)
            if chunk:
                self.buf += chunk

    def command(self, *words, timeout=5.0):
        """Sends one request and returns the words after OK."""
        self.buf = b""
        self.ser.reset_input_buffer()
        self.ser.write((" ".join(str(w) for w in words) + "\n").encode("ascii"))
        self.ser.flush()
        deadline = time.monotonic() + timeout
        while True:
            reply = self._line(deadline)
            if reply is None:
                raise DeviceError("The key didn't answer.")
            if reply.startswith("OK") or reply.startswith("ERR"):
                break
        parts = reply.split(" ")
        if parts[0] == "ERR":
            raise DeviceError(" ".join(parts[1:]) or "error")
        return parts[1:]

    def rows(self, *words, timeout=8.0, with_head=False):
        """Sends a listing request and returns its rows as word lists
        (and the words after OK too, if with_head)."""
        head = self.command(*words, timeout=timeout)
        rows, deadline = [], time.monotonic() + timeout
        while True:
            line = self._line(deadline)
            if line is None:
                raise DeviceError("The key stopped answering.")
            if line == "END":
                return (head, rows) if with_head else rows
            if line:
                rows.append(line.split(" "))


def find_ports():
    return [p.device for p in list_ports.comports() if p.vid == USB_VID and p.pid == USB_PID]


class Worker(threading.Thread):
    """Owns the serial port. Runs jobs one at a time and reports to the UI."""

    def __init__(self, events: queue.Queue):
        super().__init__(daemon=True)
        self.events = events
        self.jobs = queue.Queue()
        self.dev = None
        self.stopping = False
        self.retry_at = {}  # port -> when to try opening it again

    def submit(self, fn, on_done=None, on_error=None):
        self.jobs.put((fn, on_done, on_error))

    def stop(self):
        self.stopping = True
        self.jobs.put(None)

    def _post(self, *event):
        self.events.put(event)

    def _drop(self, reason=""):
        if self.dev:
            self.dev.close()
            self.dev = None
            self._post("disconnected", reason)

    def _connect(self):
        now = time.monotonic()
        for port in find_ports():
            if self.retry_at.get(port, 0) > now:
                continue
            dev = None
            try:
                dev = Device(port)
                hello = dev.command("HELLO", timeout=4.0)
                if not hello or hello[0] != "UNOKEY":
                    raise DeviceError("NOTUNOKEY")
                self._kill_if_revoked(dev, hello[4].lower() if len(hello) > 4 else "")
                dev.command("ENTROPY", os.urandom(32).hex())
                dev.command("TIME", int(time.time()))
                self.dev = dev
                self.retry_at.pop(port, None)
                self._post("connected", port, hello)
                return
            except DeviceError as exc:
                if dev:
                    dev.close()
                if str(exc) in ("NOTUNOKEY", "UNKNOWN"):
                    self.retry_at[port] = now + 30
                    self._post("problem", f"An Arduino is plugged in at {port}, but it isn't running UnoKey.")
                else:
                    self.retry_at[port] = now + 3  # busy with a prompt on the key, try again
            except (serial.SerialException, OSError) as exc:
                if dev:
                    dev.close()
                self.retry_at[port] = now + 3
                text = str(exc)
                if "ermission" in text or "Errno 13" in text or "denied" in text:
                    if os.name == "posix":
                        hint = f"No permission to open {port}. Install the udev rule from the README, then re-plug the key."
                    else:
                        hint = f"{port} is used by another program (for example the Arduino IDE's Serial Monitor). Close it."
                    self._post("problem", hint)

    def _kill_if_revoked(self, dev, device_id):
        """Wipes a key that was reported lost by an emergency restore."""
        revoked = load_revoked()
        token = revoked.get(device_id)
        if not device_id or not token:
            return
        try:
            dev.command("KILL", token, timeout=30)
            self._post("killed", device_id)
        except DeviceError:
            pass  # token no longer valid: the key was already wiped or re-made
        revoked.pop(device_id, None)
        try:
            save_revoked(revoked)
        except OSError:
            pass

    def run(self):
        last_check = 0.0
        while not self.stopping:
            try:
                job = self.jobs.get(timeout=0.5)
            except queue.Empty:
                job = False
            if job is None:
                break
            if self.dev is None:
                if time.monotonic() - last_check > 1.0:
                    last_check = time.monotonic()
                    self._connect()
                if job:
                    fn, _, on_error = job
                    if on_error:
                        self._post("call", on_error, DeviceError("The key is not connected."))
                continue
            if job is False:
                if self.dev.port not in find_ports():
                    self._drop("unplugged")
                continue
            fn, on_done, on_error = job
            try:
                result = fn(self.dev)
                if on_done:
                    self._post("call", on_done, result)
            except serial.SerialException as exc:
                self._drop(str(exc))
                if on_error:
                    self._post("call", on_error, DeviceError("The key was disconnected."))
            except Exception as exc:  # key refusals, wrong backup password, file errors
                if on_error:
                    self._post("call", on_error, exc)
        if self.dev:
            try:
                self.dev.command("CLOSE", timeout=1.0)
            except Exception:
                pass
            self.dev.close()


# ---------------------------------------------------------------- dialogs

class AddDialog(tk.Toplevel):
    def __init__(self, parent, on_save):
        super().__init__(parent)
        self.title("Add to vault")
        self.transient(parent)
        self.resizable(False, False)
        self.on_save = on_save
        frame = ttk.Frame(self, padding=14)
        frame.grid(sticky="nsew")

        ttk.Label(frame, text="Type").grid(row=0, column=0, sticky="w")
        self.kind = tk.StringVar(value=TYPES["P"])
        kind = ttk.Combobox(frame, textvariable=self.kind, values=list(TYPES.values()), state="readonly", width=30)
        kind.grid(row=0, column=1, sticky="we", pady=4)
        kind.bind("<<ComboboxSelected>>", lambda _e: self._update_hint())

        ttk.Label(frame, text="Name").grid(row=1, column=0, sticky="w")
        self.name = ttk.Entry(frame, width=34)
        self.name.grid(row=1, column=1, sticky="we", pady=4)

        ttk.Label(frame, text="Value").grid(row=2, column=0, sticky="nw", pady=4)
        self.value = tk.Text(frame, width=48, height=6, wrap="word")
        self.value.grid(row=2, column=1, sticky="we", pady=4)

        self.hint = ttk.Label(frame, foreground="#666", wraplength=380, justify="left")
        self.hint.grid(row=3, column=1, sticky="w")

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=1, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Save to key", command=self._save).pack(side="right", padx=6)
        self._update_hint()
        self.name.focus_set()
        self.grab_set()

    def _kind_code(self):
        return next(k for k, v in TYPES.items() if v == self.kind.get())

    def _update_hint(self):
        hints = {
            "P": "A recovery/seed phrase or long passphrase. Words separated by spaces.",
            "C": "Any code or password, e.g. backup codes or a PIN.",
            "T": "The 2FA secret (base32) or the otpauth:// link from the QR code. "
                 "The app and the key will show the 6-digit codes.",
        }
        self.hint.configure(text=hints[self._kind_code()])

    def _save(self):
        kind = self._kind_code()
        name = self.name.get().strip()
        value = self.value.get("1.0", "end").strip()
        if kind == "P":
            value = " ".join(value.split())
        try:
            if kind == "T":
                value, label = normalize_totp(value)
                if not name and label:
                    name = label[:NAME_MAX]
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        if not name:
            messagebox.showerror(APP_NAME, "Please give it a name.", parent=self)
            return
        if len(name.encode()) > NAME_MAX:
            messagebox.showerror(APP_NAME, f"The name can be at most {NAME_MAX} bytes.", parent=self)
            return
        if not value or len(value.encode()) > VALUE_MAX:
            messagebox.showerror(APP_NAME, f"The value must be 1 to {VALUE_MAX} bytes.", parent=self)
            return
        self.on_save(kind, name, value)
        self.destroy()


class RevealDialog(tk.Toplevel):
    """Shows a secret for a limited time."""

    def __init__(self, parent, title, text, on_copy):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        box = tk.Text(frame, width=56, height=min(14, max(3, text.count("\n") + 2)), wrap="word",
                      font=("Consolas" if os.name == "nt" else "Monospace", 11))
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True)
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(10, 0))
        self.countdown = ttk.Label(row, foreground="#666")
        self.countdown.pack(side="left")
        ttk.Button(row, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(row, text="Copy", command=on_copy).pack(side="right", padx=6)
        self.left = 60
        self._tick()

    def _tick(self):
        if not self.winfo_exists():
            return
        if self.left <= 0:
            self.destroy()
            return
        self.countdown.configure(text=f"Hides in {self.left} s")
        self.left -= 1
        self.after(1000, self._tick)


class ExportDialog(tk.Toplevel):
    """Asks for the backup passwords and where to save the file."""

    def __init__(self, parent, on_ok):
        super().__init__(parent)
        self.title("Export backup")
        self.transient(parent)
        self.resizable(False, False)
        self.on_ok = on_ok
        frame = ttk.Frame(self, padding=14)
        frame.grid(sticky="nsew")
        self.fields = {}
        labels = [("pw", "Backup password"), ("pw2", "Repeat it"),
                  ("em", "Emergency password (optional)"), ("em2", "Repeat it")]
        for row, (key, label) in enumerate(labels):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
            entry = ttk.Entry(frame, width=32, show="•")
            entry.grid(row=row, column=1, sticky="we", pady=3, padx=(8, 0))
            self.fields[key] = entry
        self.with_passkeys = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Include passkeys", variable=self.with_passkeys).grid(
            row=4, column=1, sticky="w", pady=(8, 0))
        ttk.Label(frame, foreground="#666", wraplength=440, justify="left", text=(
            f"Use at least {MIN_BACKUP_PASSWORD} characters. Anyone who has the file and one of its "
            "passwords can restore your vault (and passkeys, if included), so keep the passwords "
            "strong and away from the file.\n\n"
            "The emergency password restores the same backup and also marks this key as lost: it gets "
            "wiped as soon as it's plugged into a computer running UnoKey Vault that knows about the restore.")
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Choose file and export…", command=self._ok).pack(side="right", padx=6)
        self.fields["pw"].focus_set()
        self.grab_set()

    def _ok(self):
        pw, pw2 = self.fields["pw"].get(), self.fields["pw2"].get()
        em, em2 = self.fields["em"].get(), self.fields["em2"].get()
        error = None
        if len(pw) < MIN_BACKUP_PASSWORD:
            error = f"The backup password needs at least {MIN_BACKUP_PASSWORD} characters."
        elif pw != pw2:
            error = "The two backup passwords don't match."
        elif em and len(em) < MIN_BACKUP_PASSWORD:
            error = f"The emergency password needs at least {MIN_BACKUP_PASSWORD} characters."
        elif em != em2:
            error = "The two emergency passwords don't match."
        elif em and em == pw:
            error = "The emergency password must be different from the backup password."
        if error:
            messagebox.showerror(APP_NAME, error, parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Save backup", defaultextension=".unokey",
            filetypes=[("UnoKey backup", "*.unokey")], initialfile=f"unokey-{datetime.date.today()}.unokey")
        if not path:
            return
        self.on_ok(path, pw, em or None, self.with_passkeys.get())
        self.destroy()


class ImportDialog(tk.Toplevel):
    """Shows what a backup holds and how restoring it will go."""

    def __init__(self, parent, payload, emergency, passkeys_on_key, same_key, on_ok):
        super().__init__(parent)
        self.title("Import backup")
        self.transient(parent)
        self.resizable(False, False)
        self.on_ok = on_ok
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        source = payload.get("source") or {}
        pk_count = len((payload.get("passkeys") or {}).get("records", []))
        ttk.Label(frame, justify="left", text="\n".join([
            f"Made: {str(payload.get('created', '?')).replace('T', ' ')}",
            f"From key: {str(source.get('device_id', '?'))[:12]}…",
            f"Vault entries: {len(payload.get('entries', []))} (ones already on this key are skipped)",
            f"Passkeys: {pk_count}",
        ])).pack(anchor="w")
        self.with_passkeys = tk.BooleanVar(value=pk_count > 0)
        if pk_count:
            text = "Restore the passkeys"
            if passkeys_on_key:
                text += f" (replaces the {passkeys_on_key} passkey(s) now on this key)"
            ttk.Checkbutton(frame, text=text, variable=self.with_passkeys).pack(anchor="w", pady=(10, 0))
        if emergency:
            if same_key:
                note = "Emergency password used, but the backup came from this same key, so nothing is marked as lost."
            else:
                note = ("Emergency password used: the old key will be marked as lost. It gets wiped completely "
                        "(vault, passkeys, PINs) as soon as it's plugged into a computer running UnoKey Vault "
                        "that knows about this restore: this one, or any other where you use this key. "
                        "Until then it still holds the same passkeys, so consider replacing them at important sites.")
            ttk.Label(frame, text=note, foreground="#b35900", wraplength=440, justify="left").pack(anchor="w", pady=(10, 0))
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Import", command=self._ok).pack(side="right", padx=6)
        self.grab_set()

    def _ok(self):
        self.on_ok(self.with_passkeys.get())
        self.destroy()


# ---------------------------------------------------------------- main window

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.events = queue.Queue()
        self.worker = Worker(self.events)
        self.entries = {}      # id -> (type, name)
        self.totp = {}         # id -> stored 2FA value, only while unlocked
        self.passkeys = {}     # slot -> (site, user, display)
        self.connected = False
        self.unlocked = False
        self.clip_value = None
        self.device_id = ""
        self.firmware = ""

        root.title(APP_NAME)
        root.geometry("720x520")
        root.minsize(620, 420)
        self._build()
        self._set_state("Plug in your UnoKey…", "#555")
        self.worker.start()
        root.after(100, self._pump)
        root.after(1000, self._tick)
        root.protocol("WM_DELETE_WINDOW", self._quit)

    # ---- layout

    def _build(self):
        style = ttk.Style()
        if os.name != "nt" and "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Status.TLabel", font=("Segoe UI" if os.name == "nt" else "Sans", 12, "bold"))
        style.configure("Treeview", rowheight=26)

        top = ttk.Frame(self.root, padding=(14, 12, 14, 6))
        top.pack(fill="x")
        self.status = ttk.Label(top, style="Status.TLabel")
        self.status.pack(side="left")
        self.lock_btn = ttk.Button(top, text="Lock", command=self.lock)
        self.lock_btn.pack(side="right")
        self.unlock_btn = ttk.Button(top, text="Unlock", command=self.unlock)
        self.unlock_btn.pack(side="right", padx=6)
        self.detail = ttk.Label(self.root, foreground="#666", padding=(14, 0, 14, 8))
        self.detail.pack(fill="x")

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        vault = ttk.Frame(tabs, padding=8)
        tabs.add(vault, text="Vault")
        self.tree = ttk.Treeview(vault, columns=("type", "code"), selectmode="browse")
        self.tree.heading("#0", text="Name")
        self.tree.heading("type", text="Type")
        self.tree.heading("code", text="2FA code")
        self.tree.column("#0", width=260)
        self.tree.column("type", width=150)
        self.tree.column("code", width=140)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _e: self.copy_selected())
        buttons = ttk.Frame(vault)
        buttons.pack(fill="x", pady=(8, 0))
        self.vault_buttons = [
            ttk.Button(buttons, text="Copy", command=self.copy_selected),
            ttk.Button(buttons, text="Show", command=self.show_selected),
            ttk.Button(buttons, text="Add…", command=self.add_entry),
            ttk.Button(buttons, text="Delete", command=self.delete_selected),
        ]
        for b in self.vault_buttons:
            b.pack(side="left", padx=(0, 6))

        pk = ttk.Frame(tabs, padding=8)
        tabs.add(pk, text="Passkeys")
        self.pk_tree = ttk.Treeview(pk, columns=("user", "display"), selectmode="browse")
        self.pk_tree.heading("#0", text="Website")
        self.pk_tree.heading("user", text="Account")
        self.pk_tree.heading("display", text="Display name")
        self.pk_tree.column("#0", width=240)
        self.pk_tree.pack(fill="both", expand=True)
        pk_buttons = ttk.Frame(pk)
        pk_buttons.pack(fill="x", pady=(8, 0))
        self.pk_delete = ttk.Button(pk_buttons, text="Delete passkey", command=self.delete_passkey)
        self.pk_delete.pack(side="left")
        ttk.Label(pk_buttons, foreground="#666",
                  text="Passkeys are created by websites (\"Create a passkey\" → Security key).").pack(side="left", padx=10)

        key = ttk.Frame(tabs, padding=14)
        tabs.add(key, text="Key")
        self.info = ttk.Label(key, justify="left")
        self.info.pack(anchor="w")
        self.pin_btn = ttk.Button(key, text="Set or change vault PIN (on the key)", command=self.set_pin)
        self.pin_btn.pack(anchor="w", pady=(14, 4))
        self.erase_btn = ttk.Button(key, text="Erase vault and reset its PIN…", command=self.erase_vault)
        self.erase_btn.pack(anchor="w", pady=(0, 8))
        ttk.Label(key, foreground="#666", wraplength=640, justify="left", text=(
            "The vault PIN is entered on the key with the joystick: up/down picks a digit, "
            "click (or right) adds it, left deletes, and the button confirms. Pressing the button "
            "before entering any digit cancels. After 10 wrong PINs the vault is wiped, so keep a "
            "paper backup of seed phrases.\n\n"
            "Forgot the vault PIN? \"Erase vault\" deletes all vault entries and the PIN (you confirm "
            "on the key). Your passkeys are not touched.\n\n"
            "The passkey PIN is separate: Windows or your browser asks for it when you use a passkey.")
        ).pack(anchor="w")

        backup = ttk.Frame(tabs, padding=14)
        tabs.add(backup, text="Backup")
        ttk.Label(backup, wraplength=640, justify="left", text=(
            "Export makes an encrypted .unokey file with your vault entries and, if you like, your passkeys. "
            "Import it on another UnoKey (or this one) with the backup password.\n\n"
            "Optional emergency password: it opens the same backup, and also marks the old key as lost. "
            "That key is then wiped completely (vault, passkeys and PINs) the moment it's plugged into a "
            "computer running UnoKey Vault that knows about the restore. A lost key that never gets plugged "
            "into such a computer can't be wiped, so keep a vault PIN set.")
        ).pack(anchor="w")
        backup_buttons = ttk.Frame(backup)
        backup_buttons.pack(anchor="w", pady=(14, 0))
        self.export_btn = ttk.Button(backup_buttons, text="Export backup…", command=self.export_backup)
        self.export_btn.pack(side="left")
        self.import_btn = ttk.Button(backup_buttons, text="Import backup…", command=self.import_backup)
        self.import_btn.pack(side="left", padx=6)
        self._refresh_controls()

    # ---- state

    def _set_state(self, text, color, detail=""):
        self.status.configure(text=text, foreground=color)
        self.detail.configure(text=detail)

    def _refresh_controls(self):
        on = self.connected and self.unlocked
        for b in self.vault_buttons + [self.pk_delete, self.pin_btn, self.lock_btn,
                                       self.export_btn, self.import_btn]:
            b.state(["!disabled"] if on else ["disabled"])
        self.unlock_btn.state(["!disabled"] if self.connected and not self.unlocked else ["disabled"])
        self.erase_btn.state(["!disabled"] if self.connected else ["disabled"])

    def _clear_data(self):
        self.entries.clear()
        self.totp.clear()
        self.passkeys.clear()
        self.tree.delete(*self.tree.get_children())
        self.pk_tree.delete(*self.pk_tree.get_children())
        self.info.configure(text="")

    def _pump(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "connected":
                    hello = event[2]
                    self.connected = True
                    self.firmware = hello[1]
                    self.device_id = hello[4].lower() if len(hello) > 4 else ""
                    self._set_state("UnoKey connected", "#1a7f37", f"Port {event[1]}, firmware {event[2][1]}")
                    self.worker.submit(lambda d: d.command("INFO"), self._show_info)
                    self.unlock()
                elif kind == "killed":
                    messagebox.showwarning(APP_NAME, (
                        f"This UnoKey ({event[1][:12]}…) was reported lost: a backup of it was restored "
                        "elsewhere with the emergency password.\n\nIt has been wiped completely: vault, "
                        "passkeys and PINs. It now works like a new key."), parent=self.root)
                elif kind == "disconnected":
                    self.connected = self.unlocked = False
                    self._clear_data()
                    self._set_state("Plug in your UnoKey…", "#555")
                    self._refresh_controls()
                elif kind == "problem":
                    if not self.connected:
                        self._set_state("UnoKey not found", "#b35900", event[1])
                elif kind == "call":
                    event[1](event[2])
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    def _tick(self):
        for item_id, value in self.totp.items():
            iid = str(item_id)
            if self.tree.exists(iid):
                try:
                    code, left = totp_now(value)
                    self.tree.set(iid, "code", f"{code[:3]} {code[3:]}   {left:2d}s")
                except Exception:
                    self.tree.set(iid, "code", "invalid")
        self.root.after(1000, self._tick)

    def _error(self, exc):
        messagebox.showerror(APP_NAME, describe_error(exc), parent=self.root)

    # ---- unlock / lock

    def unlock(self):
        if not self.connected:
            return
        self._set_state("Confirm on your UnoKey", "#0b5cad",
                        "Press the button on the key. If you set a vault PIN, enter it with the joystick first.")
        self.unlock_btn.state(["disabled"])
        self.worker.submit(lambda d: d.command("UNLOCK", timeout=180), self._unlocked, self._unlock_failed)

    def _unlocked(self, _):
        self.unlocked = True
        self._set_state("Unlocked", "#1a7f37", "Double-click an entry to copy it. The clipboard is cleared after 30 seconds.")
        self._refresh_controls()
        self.refresh()

    def _unlock_failed(self, exc):
        self.unlocked = False
        self._refresh_controls()
        if self.connected:
            self._set_state("Locked", "#b35900", describe_error(exc) + " Click Unlock to try again.")

    def lock(self):
        def done(_):
            self.unlocked = False
            self._clear_data()
            self._set_state("Locked", "#555", "The key forgot its vault key. The PIN is needed to unlock again.")
            self._refresh_controls()
        self.worker.submit(lambda d: d.command("LOCK"), done, self._error)

    # ---- data

    def refresh(self):
        def load(dev):
            entries = [(int(r[1]), r[2], b64d(r[3])) for r in dev.rows("LIST") if len(r) >= 4 and r[0] == "E"]
            totp = {}
            for eid, kind, _ in entries:
                if kind == "T":
                    totp[eid] = b64d(dev.command("GET", eid)[2])
            passkeys = [(int(r[1]), b64d(r[2]), b64d(r[3]), b64d(r[4]))
                        for r in dev.rows("PKLIST") if len(r) >= 5 and r[0] == "K"]
            info = dev.command("INFO")
            self._sync_revoked(dev)
            return entries, totp, passkeys, info
        self.worker.submit(load, self._loaded, self._load_failed)

    def _sync_revoked(self, dev):
        """Learns which lost keys this key replaced, so this computer can wipe them too."""
        try:
            rows = dev.rows("REVOKELIST")
        except DeviceError:
            return
        store = load_revoked()
        changed = False
        for row in rows:
            if len(row) >= 3 and row[0] == "R" and row[1].lower() != self.device_id:
                if store.get(row[1].lower()) != row[2].lower():
                    store[row[1].lower()] = row[2].lower()
                    changed = True
        if changed:
            try:
                save_revoked(store)
            except OSError:
                pass

    def _load_failed(self, exc):
        if str(exc) == "LOCKED":
            self.unlocked = False
            self._clear_data()
            self._set_state("Locked", "#555", "The key was locked. Click Unlock to open it again.")
            self._refresh_controls()
        else:
            self._error(exc)

    def _loaded(self, result):
        entries, totp, passkeys, info = result
        self._clear_data()
        self.totp = totp
        for eid, kind, name in sorted(entries, key=lambda e: e[2].lower()):
            self.entries[eid] = (kind, name)
            self.tree.insert("", "end", iid=str(eid), text=name,
                             values=(TYPES.get(kind, kind), "" if kind == "T" else "••••••"))
        for slot, site, user, display in passkeys:
            self.passkeys[slot] = (site, user, display)
            self.pk_tree.insert("", "end", iid=str(slot), text=site or "(unknown site)", values=(user, display))
        self._show_info(info)
        self._tick()

    def _show_info(self, info):
        version, count, used, total, pks, pk_max, vpin, fpin, _open, tries = info[:10]
        failed_saves = info[10] if len(info) > 10 else "0"
        joystick = info[11] if len(info) > 11 else "1"
        text = (
            f"Firmware: {version}\n"
            f"Key ID: {self.device_id or '?'}\n"
            f"Vault: {count} entries, {used} of {total} bytes used\n"
            f"Passkeys: {pks} of {pk_max}\n"
            f"Vault PIN: {'set' if vpin == '1' else 'not set (anyone holding the key can unlock it!)'}\n"
            f"Passkey PIN: {'set' if fpin == '1' else 'not set yet (Windows asks to create one)'}\n"
            f"Vault PIN tries left: {tries}\n"
            f"Joystick: {'ready' if joystick == '1' else 'not clicked yet since plug-in (needed for the vault PIN and the key menu)'}")
        if failed_saves != "0":
            text += f"\n\nWarning: the key failed to save to its memory {failed_saves} times since it was plugged in."
        self.info.configure(text=text)

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select an entry first.", parent=self.root)
            return None
        return int(sel[0])

    def _copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.clip_value = text
        self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, lambda: self._clear_clip(text))

    def _clear_clip(self, text):
        try:
            if self.root.clipboard_get() == text:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
        except tk.TclError:
            pass

    def copy_selected(self):
        eid = self._selected()
        if eid is None:
            return
        kind, name = self.entries[eid]
        if kind == "T":
            self._copy(totp_now(self.totp[eid])[0])
            self.detail.configure(text=f"Copied the 2FA code for {name}.")
            return

        def done(reply):
            self._copy(b64d(reply[2]))
            self.detail.configure(text=f"Copied {name}. The clipboard is cleared in {CLIPBOARD_CLEAR_SECONDS} s.")
        self.worker.submit(lambda d: d.command("GET", eid), done, self._error)

    def show_selected(self):
        eid = self._selected()
        if eid is None:
            return
        kind, name = self.entries[eid]

        def done(reply):
            value = b64d(reply[2])
            if kind == "P" and len(value.split()) >= 12:
                words = value.split()
                text = "\n".join(f"{i + 1:2d}. {w}" for i, w in enumerate(words))
            elif kind == "T":
                text = f"Current code: {totp_now(value)[0]}\n\nSecret: {value}"
            else:
                text = value
            RevealDialog(self.root, name, text, lambda: self._copy(value))
        self.worker.submit(lambda d: d.command("GET", eid), done, self._error)

    def add_entry(self):
        def save(kind, name, value):
            self.detail.configure(text="Saving to the key…")
            self.worker.submit(lambda d: d.command("ADD", kind, b64e(name), b64e(value), timeout=10),
                               lambda _: self.refresh(), self._error)
        AddDialog(self.root, save)

    def delete_selected(self):
        eid = self._selected()
        if eid is None:
            return
        _, name = self.entries[eid]
        if not messagebox.askyesno(APP_NAME, f"Delete \"{name}\" from the key?\n\nYou'll confirm on the key itself.",
                                   parent=self.root):
            return
        self.detail.configure(text="Confirm the deletion on the key (press the button).")
        self.worker.submit(lambda d: d.command("DEL", eid, timeout=90), lambda _: self.refresh(), self._error)

    def delete_passkey(self):
        sel = self.pk_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a passkey first.", parent=self.root)
            return
        slot = int(sel[0])
        site, user, _ = self.passkeys[slot]
        if not messagebox.askyesno(APP_NAME, f"Delete the passkey for {user or 'this account'} on {site}?\n\n"
                                   "You won't be able to sign in with it anymore. You'll confirm on the key.",
                                   parent=self.root):
            return
        self.detail.configure(text="Confirm the deletion on the key (press the button).")
        self.worker.submit(lambda d: d.command("PKDEL", slot, timeout=90), lambda _: self.refresh(), self._error)

    def set_pin(self):
        messagebox.showinfo(APP_NAME, "Look at the key's display: enter the new vault PIN with the joystick "
                            "(4 to 8 digits), press the button, then enter it again.", parent=self.root)
        self.detail.configure(text="Set the PIN on the key…")
        self.worker.submit(lambda d: d.command("SETPIN", timeout=400),
                           lambda _: (messagebox.showinfo(APP_NAME, "Vault PIN saved.", parent=self.root), self.refresh()),
                           self._error)

    def erase_vault(self):
        if not messagebox.askyesno(
                APP_NAME, "Erase the vault?\n\nThis deletes ALL vault entries (passphrases, codes, 2FA secrets) "
                "and removes the vault PIN. Your passkeys are not touched.\n\n"
                "You'll confirm on the key by pressing its button.", icon="warning", parent=self.root):
            return
        self.detail.configure(text="Confirm on the key: press the button when it scrolls ERASE VAULT.")

        def done(_):
            self.unlocked = False
            self._clear_data()
            self._set_state("Vault erased", "#1a7f37", "The vault is empty and has no PIN now. Click Unlock to use it.")
            self._refresh_controls()
            self.worker.submit(lambda d: d.command("INFO"), self._show_info)
        self.worker.submit(lambda d: d.command("WIPEVAULT", timeout=90), done, self._error)

    # ---- backups

    def export_backup(self):
        def start(path, password, emergency, with_passkeys):
            self.detail.configure(text="Confirm on the key: press the button when it scrolls EXPORT BACKUP.")
            firmware = self.firmware

            def job(dev):
                device_id, kill_token = dev.command("EXPORTBEGIN", timeout=90)[:2]
                entries = []
                for row in dev.rows("LIST"):
                    if len(row) >= 4 and row[0] == "E":
                        reply = dev.command("GET", row[1])
                        entries.append({"type": reply[0], "name": b64d(reply[1]), "value": b64d(reply[2])})
                passkeys = None
                if with_passkeys:
                    head, rows = dev.rows("PKEXPORT", with_head=True)
                    records = [r[1] for r in rows if len(r) >= 2 and r[0] == "P"]
                    if len(head) >= 3 and head[0] == "1" and records:
                        passkeys = {"fido_secret": head[1], "counter": int(head[2]), "records": records}
                payload = {
                    "created": datetime.datetime.now().isoformat(timespec="seconds"),
                    "source": {"device_id": device_id.lower(), "firmware": firmware},
                    "entries": entries,
                    "passkeys": passkeys,
                }
                old_key = (bytes.fromhex(device_id), bytes.fromhex(kill_token)) if emergency else None
                write_backup(path, payload, password, emergency, old_key)
                return len(entries), len(passkeys["records"]) if passkeys else 0

            def done(counts):
                text = f"Backup saved to:\n{path}\n\n{counts[0]} vault entries, {counts[1]} passkeys."
                if emergency:
                    text += ("\n\nKeep the emergency password safe and apart from the file. Restoring with it "
                             "marks this key as lost.")
                self.detail.configure(text="Backup saved.")
                messagebox.showinfo(APP_NAME, text, parent=self.root)
            self.worker.submit(job, done, self._error)
        ExportDialog(self.root, start)

    def import_backup(self):
        path = filedialog.askopenfilename(parent=self.root, title="Open backup",
                                          filetypes=[("UnoKey backup", "*.unokey"), ("All files", "*.*")])
        if not path:
            return
        password = simpledialog.askstring(APP_NAME, "Password for this backup\n(or its emergency password):",
                                          show="•", parent=self.root)
        if not password:
            return
        self.detail.configure(text="Opening the backup…")

        def job(dev):
            payload, emergency = read_backup(path, password)
            on_key = len([r for r in dev.rows("PKLIST") if r and r[0] == "K"])
            return payload, emergency, on_key
        self.worker.submit(job, lambda r: self._confirm_import(*r), self._error)

    def _confirm_import(self, payload, emergency, passkeys_on_key):
        self.detail.configure(text="")
        same_key = bool(emergency) and emergency["device_id"].hex() == self.device_id

        def start(with_passkeys):
            self.detail.configure(text="Importing… confirm on the key when it asks.")

            def job(dev):
                existing = set()
                for row in dev.rows("LIST"):
                    if len(row) >= 4 and row[0] == "E":
                        reply = dev.command("GET", row[1])
                        existing.add((reply[0], b64d(reply[1]), b64d(reply[2])))
                added = skipped = 0
                full = False
                for entry in payload.get("entries", []):
                    item = (entry["type"], entry["name"], entry["value"])
                    if item in existing:
                        skipped += 1
                        continue
                    try:
                        dev.command("ADD", item[0], b64e(item[1]), b64e(item[2]), timeout=10)
                    except DeviceError as exc:
                        if str(exc) != "FULL":
                            raise
                        full = True
                        break
                    added += 1
                restored = 0
                passkeys = payload.get("passkeys")
                if with_passkeys and passkeys:
                    dev.command("PKIMPORT", passkeys["fido_secret"], int(passkeys.get("counter", 0)), timeout=90)
                    for record in passkeys["records"]:
                        dev.command("PKADD", record, timeout=10)
                        restored += 1
                revoked = False
                if emergency and not same_key:
                    old_id, token = emergency["device_id"].hex(), emergency["kill_token"].hex()
                    dev.command("REVOKEADD", old_id, token)
                    store = load_revoked()
                    store[old_id] = token
                    save_revoked(store)
                    revoked = True
                return added, skipped, full, restored, revoked

            def done(result):
                added, skipped, full, restored, revoked = result
                text = f"Imported {added} vault entries"
                if skipped:
                    text += f" ({skipped} were already on this key)"
                text += f" and {restored} passkeys."
                if full:
                    text += "\n\nThe vault on this key got full, so not everything was imported."
                if revoked:
                    text += ("\n\nThe old key is now marked as lost. It gets wiped the moment it's plugged into "
                             "this computer, or any other computer where you use this key with UnoKey Vault.")
                self.detail.configure(text="Backup imported.")
                messagebox.showinfo(APP_NAME, text, parent=self.root)
                self.refresh()
            self.worker.submit(job, done, self._error)
        ImportDialog(self.root, payload, emergency, passkeys_on_key, same_key, start)

    def _quit(self):
        try:
            if self.clip_value and self.root.clipboard_get() == self.clip_value:
                self.root.clipboard_clear()
        except tk.TclError:
            pass
        self.worker.stop()
        self.root.after(300, self.root.destroy)


def main():
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    if serial is None:
        root.withdraw()
        messagebox.showerror(APP_NAME, "pyserial is missing. Install it with:\n\npip install pyserial")
        return 1
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
