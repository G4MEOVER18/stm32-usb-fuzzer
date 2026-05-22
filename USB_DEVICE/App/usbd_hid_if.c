/**
 * usbd_hid_if.c — HID Interface callbacks
 *
 * The fuzzer sends a single zeroed 8-byte keyboard report (no keys pressed).
 * The actual fuzzing happens in the descriptor layer (usbd_desc.c),
 * not in the report data — we want Windows to crash during enumeration,
 * not during HID report parsing.
 */

#include "usbd_hid_if.h"

static int8_t HID_Init_FS(void);
static int8_t HID_DeInit_FS(void);
static int8_t HID_OutEvent_FS(uint8_t event_idx, uint8_t state);

USBD_HID_ItfTypeDef USBD_HID_fops_FS = {
    HID_Init_FS,
    HID_DeInit_FS,
    HID_OutEvent_FS
};

static int8_t HID_Init_FS(void) {
    return USBD_OK;
}

static int8_t HID_DeInit_FS(void) {
    return USBD_OK;
}

/* Called when host sends LED output report (Caps Lock etc.) — ignored */
static int8_t HID_OutEvent_FS(uint8_t event_idx, uint8_t state) {
    (void)event_idx;
    (void)state;
    return USBD_OK;
}
