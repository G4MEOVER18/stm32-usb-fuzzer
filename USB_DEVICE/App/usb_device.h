#ifndef __USB_DEVICE_H
#define __USB_DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stm32f1xx.h"
#include "stm32f1xx_hal.h"
#include "usbd_def.h"

extern USBD_HandleTypeDef hUsbDeviceFS;

void MX_USB_DEVICE_Init(void);

#ifdef __cplusplus
}
#endif
#endif /* __USB_DEVICE_H */
