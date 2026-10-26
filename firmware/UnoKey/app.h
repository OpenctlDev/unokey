// Glue that lets blocking UI loops keep USB alive while they wait.
#pragma once

// Called on every iteration of a blocking prompt: answers USB traffic,
// sends FIDO keepalives and turns other requests away as busy.
void appServiceWhileBusy();
// True when the host cancelled the FIDO request the prompt belongs to.
bool appCancelRequested();
// True when the desktop app or a website is waiting for the key. Screens
// that only show things (menu, vault browsing) give way so the request's
// prompt can appear.
bool appInterruptPending();
