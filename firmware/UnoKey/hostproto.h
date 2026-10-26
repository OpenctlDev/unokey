// Line-based protocol spoken with the UnoKey desktop app over USB serial.
//
// Requests are one line of space-separated words; text fields are base64.
// Replies start with "OK" or "ERR <reason>". Listing commands send their
// rows after "OK" and finish with "END". Vault and passkey commands work only
// after UNLOCK has been approved on the device for this connection.
//
//   HELLO                       -> OK UNOKEY <version> <OPEN|LOCKED> <SESSION|NOSESSION> <deviceId hex>
//   INFO                        -> OK <version> <entries> <usedBytes> <totalBytes>
//                                     <passkeys> <maxPasskeys> <vaultPin 0|1> <fidoPin 0|1>
//                                     <vaultOpen 0|1> <pinTriesLeft> <failedSaves>
//                                     <joystick 0|1>
//   DIAG                        -> OK <x> <y> <centreX> <centreY> <joystick 0|1> <button 0|1> <stick 0|1>
//   ENTROPY <hex>               -> OK          (host randomness for the RNG)
//   TIME <unix seconds>         -> OK          (lets the key show 2FA codes)
//   UNLOCK                      -> OK | ERR DENIED|TIMEOUT|CANCELLED|PIN <left>|WIPED
//   LOCK                        -> OK          (PIN needed again)
//   CLOSE                       -> OK          (ends this app session only)
//   LIST                        -> OK, then "E <id> <type> <name>" rows, END
//   GET <id>                    -> OK <type> <name> <value>
//   ADD <type> <name> <value>   -> OK <id> | ERR FULL|TOOLONG
//   DEL <id>                    -> OK | ERR DENIED   (confirmed on the device)
//   PKLIST                      -> OK, then "K <slot> <site> <user> <displayName>" rows, END
//   PKDEL <slot>                -> OK | ERR DENIED   (confirmed on the device)
//   SETPIN                      -> OK | ERR NOJOYSTICK|...  (entered on the device)
//   WIPEVAULT                   -> OK | ERR DENIED   (erases entries and vault PIN,
//                                                     confirmed on the device; no unlock needed)
//
// Backups (.unokey files are made and read by the app):
//   EXPORTBEGIN                 -> OK <deviceId hex> <killToken hex>   (confirmed on the device)
//   PKEXPORT                    -> OK <fidoReady 0|1> <fidoSecret hex> <counter>, then
//                                  "P <record b64>" rows, END        (only after EXPORTBEGIN)
//   PKIMPORT <secret hex> <ctr> -> OK   (confirmed on the device; replaces all passkeys)
//   PKADD <record b64>          -> OK | ERR FULL                      (only after PKIMPORT)
//   REVOKEADD <id hex> <token>  -> OK   (remember a key replaced by an emergency restore)
//   REVOKELIST                  -> OK, then "R <id hex> <token hex>" rows, END
//   KILL <token hex>            -> OK   (wipes the whole key; no session, no press needed)
#pragma once

void hostBegin();
void hostPoll();
bool hostSessionOpen();
void hostEndSession();
