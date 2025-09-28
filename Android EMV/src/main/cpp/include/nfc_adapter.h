#ifndef NFC_ADAPTER_H
#define NFC_ADAPTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Android NFC Hardware Abstraction Layer
 * 
 * These functions provide a bridge between the ported Proxmark EMV code
 * and Android's NFC APIs, replacing hardware-specific Proxmark calls.
 */

// APDU exchange function for Android NFC
int android_emv_exchange_apdu(const uint8_t* apdu, size_t apdu_len, 
                             uint8_t* response, size_t max_resp_len, 
                             size_t* resp_len);

// Field control functions (mostly no-ops on Android)
int android_activate_field(bool activate);

// Card connection management
int android_connect_card(void** handle);
int android_disconnect_card(void* handle);

#ifdef __cplusplus
}
#endif

#endif // NFC_ADAPTER_H