/**
 * usb_device.c — USB Device middleware initialization
 *
 * Registers USBD_FUZZER (custom class) instead of the standard HID class.
 * USBD_FUZZER implements its own GetFSCfgDesc() so fuzz patches in
 * usbd_fuzzer.c actually reach the host — unlike usbd_hid.c which has
 * a hardcoded configuration descriptor that ignores usbd_desc.c.
 */

#include "usb_device.h"
#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_fuzzer.h"

USBD_HandleTypeDef hUsbDeviceFS;

void MX_USB_DEVICE_Init(void)
{
    USBD_Init(&hUsbDeviceFS, &FS_Desc, DEVICE_FS);
    USBD_RegisterClass(&hUsbDeviceFS, &USBD_FUZZER);
    USBD_Start(&hUsbDeviceFS);
}
