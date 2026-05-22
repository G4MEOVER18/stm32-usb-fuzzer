#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stm32f1xx_hal.h"

/* -----------------------------------------------------------------------
 * Fuzz mode constants — selected at RUNTIME, not compile time
 *
 * Mode selection — 3 methods (priority order):
 *
 * 1. UART command (jederzeit, kein Reset):
 *    '1'–'9' = Modus 1–9,  'a'–'g' = Modus 10–16  (PA10 RX, 115200)
 *    's' = USB-Reconnect ohne Moduswechsel
 *    '?' = Status ausgeben
 *
 * 2. PB2 (BOOT1-Header) = GND → Modus EINGEFROREN:
 *    Reset zählt NICHT hoch. LED blinkt Modus-Nr. alle 3s als Heartbeat.
 *    PB3/PB4 wählen zusätzlich die Modus-Bank (4er-Gruppen):
 *      PB4=open PB3=open  → Bank 3 (Modi 13–16)
 *      PB4=open PB3=GND   → Bank 2 (Modi 9–12)
 *      PB4=GND  PB3=open  → Bank 1 (Modi 5–8)
 *      PB4=GND  PB3=GND   → Bank 0 (Modi 1–4)
 *    BKP-Wert (1–4) = Intra-Bank-Offset
 *
 * 3. PB2 = offen (Standard) → Reset-Zähler:
 *    Jeder Reset: Modus 1→2→…→16→1
 *    BKP->DR1 überlebt Reset (kein Strom = Verlust, keine Batterie nötig)
 * ----------------------------------------------------------------------- */

/* Group 1: Device Descriptor attacks (Windows reads these first) */
#define FUZZ_MODE_HUB_IMPERSONATE      1   /* bDeviceClass=0x09 (Hub class)  */
#define FUZZ_MODE_BCDUSB_30            2   /* bcdUSB=0x0300 on FS device     */
#define FUZZ_MODE_NUMCONFIG_ZERO       3   /* bNumConfigurations=0           */
#define FUZZ_MODE_ENDPOINT_MAXPACKET   4   /* bMaxPacketSize0=0xFF + EP size */

/* Group 2: Config / Interface / Endpoint descriptor attacks */
#define FUZZ_MODE_WTOTALLENGTH_SMALL   5   /* wTotalLength=5   (underread)   */
#define FUZZ_MODE_WTOTALLENGTH_LARGE   6   /* wTotalLength=0xFFFF (overread) */
#define FUZZ_MODE_NUMINTERFACES_OVER   7   /* bNumInterfaces=16              */
#define FUZZ_MODE_NUMEP_ZERO           8   /* bNumEndpoints=0 lie            */
#define FUZZ_MODE_BMATTR_ZERO          9   /* bmAttributes=0+bInterval=0     */

/* Group 3: String descriptor attacks */
#define FUZZ_MODE_STRING_BLEN_OVERFLOW 10  /* Mfr string bLength=0xFE CVE-2024-21429 */

/* Group 4: HID descriptor / report attacks */
#define FUZZ_MODE_HID_DESCLEN_MAX      11  /* wDescriptorLength=0xFFFF       */
#define FUZZ_MODE_HID_BCDVER           12  /* wTotalLength=0xFFFF+bNumDescs=16 */
#define FUZZ_MODE_HID_REPORT_FUZZ      13  /* Malformed HID Report Desc      */

/* Group 5: Special / Timing / Meta modes */
#define FUZZ_MODE_RECONNECT_LOOP       14  /* D+ rapid disconnect/reconnect  */
#define FUZZ_MODE_RANDOM               15  /* LCG full-descriptor random     */
#define FUZZ_MODE_AUTO_SEQUENCE        16  /* Sequencer: all modes 1–15      */

/* Group 6: Manual-only keyboard crash (NOT in auto-sequencer) */
#define FUZZ_MODE_KBD_CRASH            17  /* Keyboard Initiated Crash (0xE2) */

/* Group 7: BIOS POST / Boot disruption — active only while plugged in */
#define FUZZ_MODE_POST_RECONNECT       18  /* 10ms reconnect bomb — BIOS can't enumerate    */
#define FUZZ_MODE_NUMCONFIG_FLOOD      19  /* bNumConfigs=254 + wTotal=0xFFFF               */
#define FUZZ_MODE_LANGID_BOMB          20  /* LangID bLength=0xFF — BIOS string-parser OOB  */
#define FUZZ_MODE_DEVQUAL_BOMB         21  /* DevQual bLength=0xFF + bcdUSB=0x0300          */
#define FUZZ_MODE_BOOT_DISRUPT         22  /* Boot sequencer: 19→20→21→1→2→6→10 + reconnect bursts */

/* Group 8: EP0 / Protocol attacks */
#define FUZZ_MODE_EP0_STALL_MID        23  /* EP0 stall at status phase → usbport.sys retry loop   */
#define FUZZ_MODE_MS_OS_DESC           24  /* MS OS String + Compat ID wTotalLength=0xFFFF          */
#define FUZZ_MODE_DESC_MORPH           25  /* Same VID/PID morphs class each reconnect              */

/* Group 9: Composite / Class attacks */
#define FUZZ_MODE_IAD_CONFLICT         26  /* IAD overlap: 3 IADs claim iface 0, count 2/255        */
#define FUZZ_MODE_MSC_SCSI_BOMB        27  /* USB MSC + malformed CBW/CSW → usbstor.sys reset loop  */

/* Group 10: Flood / Rapid-fire attacks */
#define FUZZ_MODE_HID_FLOOD            28  /* HID keyboard report flood 1000 rpt/s                  */
#define FUZZ_MODE_RAPID_SEQ            29  /* 50ms rapid-fire sequencer: all modes, no settle        */
#define FUZZ_MODE_OMNI_BOMB            30  /* All descriptor attacks simultaneously                  */

#define FUZZ_MODE_MAX                  30

/* Runtime mode — set in main() by reading GPIO/BKP, read by usbd_fuzzer.c */
extern uint8_t g_active_fuzz_mode;

/* Mode selection pins */
#define MODE_SEL_PIN0   GPIO_PIN_2   /* PB2 — BOOT1 header: GND=freeze */
#define MODE_SEL_PIN1   GPIO_PIN_3   /* PB3 — bank bit 0               */
#define MODE_SEL_PIN2   GPIO_PIN_4   /* PB4 — bank bit 1               */
#define MODE_SEL_PORT   GPIOB

/* BKP register — persists mode counter across Reset */
#define MODE_BKP_REG    BKP_DR1

/* Blue Pill USB D+ (PA12) — software reconnect */
#define USB_DP_PIN      GPIO_PIN_12
#define USB_DP_PORT     GPIOA

/* Onboard LED (PC13, active low) */
#define LED_PIN         GPIO_PIN_13
#define LED_PORT        GPIOC

/* Timing */
#define USB_RESET_PULSE_MS       10
#define USB_RECONNECT_DELAY_MS  500
#define AUTO_SEQ_STEP_MS       3000U   /* normal dwell: enum OK   */
#define AUTO_SEQ_STEP_MS_SLOW  5000U   /* slow dwell:  enum FAIL  */
#define IWDG_KICK_INTERVAL_MS  1000U

void Error_Handler(void);
void MX_USB_DEVICE_Init(void);

#ifdef __cplusplus
}
#endif
#endif /* __MAIN_H */
