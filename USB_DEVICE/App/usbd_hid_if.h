#ifndef __USBD_HID_IF_H
#define __USBD_HID_IF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "usbd_hid.h"

#define DEVICE_FS 0

/* HID-Interface-Callback-Tabelle. Die Standard-STM32-HID-Klasse kennt diesen
 * Typ nicht; hier lokal definiert, damit das Interface-Boilerplate baut.
 * (Das eigentliche Fuzzing passiert in usbd_desc.c / usbd_fuzzer.c.) */
typedef struct {
    int8_t (*Init)(void);
    int8_t (*DeInit)(void);
    int8_t (*OutEvent)(uint8_t event_idx, uint8_t state);
} USBD_HID_ItfTypeDef;

extern USBD_HID_ItfTypeDef USBD_HID_fops_FS;

#ifdef __cplusplus
}
#endif
#endif /* __USBD_HID_IF_H */
