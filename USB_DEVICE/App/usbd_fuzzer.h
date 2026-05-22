/**
 * usbd_fuzzer.h — Custom USB class giving full descriptor control
 *
 * Replaces usbd_hid.c. Implements USBD_ClassTypeDef with its own
 * GetFSCfgDesc() so FUZZ_MODE manipulations actually reach the host.
 *
 * Standard usbd_hid.c has a hardcoded GetFSCfgDesc() that ignores
 * whatever is in usbd_desc.c — this class fixes that.
 */
#ifndef __USBD_FUZZER_H
#define __USBD_FUZZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "usbd_def.h"
#include "main.h"

/* HID class descriptor lengths */
#define FUZZER_HID_REPORT_DESC_SIZE    26U
#define FUZZER_KBD_REPORT_DESC_SIZE    45U
#define FUZZER_CFG_DESC_SIZE           34U
#define FUZZER_IAD_CFG_DESC_SIZE       99U   /* Mode 26: IAD conflict composite */
#define FUZZER_MSC_CFG_DESC_SIZE       32U   /* Mode 27: USB MSC */

/* Endpoint addresses */
#define FUZZER_EPIN_ADDR               0x81U
#define FUZZER_EPIN_SIZE               0x08U
#define FUZZER_EPOUT_ADDR              0x01U  /* Mode 27 MSC bulk OUT */
#define FUZZER_BULK_SIZE               0x40U  /* 64 bytes */

/* Standard HID bInterfaceProtocol */
#define HID_SUBCLASS_NONE              0x00U
#define HID_PROTOCOL_NONE              0x00U
#define HID_PROTOCOL_KEYBOARD          0x01U

/* morph phase — shared with main.c (Mode 25) */
extern uint8_t g_morph_phase;

extern USBD_ClassTypeDef USBD_FUZZER;

/* Expose report descriptor for HAL */
extern const uint8_t FUZZER_ReportDesc[FUZZER_HID_REPORT_DESC_SIZE];

/* Send data over the interrupt IN endpoint (used by Mode 17 in main.c) */
void USBD_FUZZER_Transmit(USBD_HandleTypeDef *pdev, uint8_t *buf, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* __USBD_FUZZER_H */
