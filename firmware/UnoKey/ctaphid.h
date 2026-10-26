// CTAPHID transport: FIDO messages framed into 64-byte USB HID reports.
#pragma once
#include <stdint.h>

void ctaphidBegin();
// Normal processing: assembles requests and runs them.
void ctaphidPoll();
// While a prompt blocks: answers INIT, sends keepalives, notes CANCEL and
// turns other requests away as busy.
void ctaphidPollBusy();
bool ctaphidCancelled();
// True if a FIDO request was turned away as busy since the main loop last ran.
bool ctaphidRequestRefused();
