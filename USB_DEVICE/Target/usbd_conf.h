#ifndef __USBD_CONF_H
#define __USBD_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stm32f1xx.h"
#include "stm32f1xx_hal.h"

/* Device instance index */
#define DEVICE_FS                     0U

/* USB Core config */
#define USBD_MAX_NUM_INTERFACES       1U
#define USBD_MAX_NUM_CONFIGURATION    1U
#define USBD_MAX_STR_DESC_SIZ         512U
#define USBD_SELF_POWERED             1U
#define USBD_DEBUG_LEVEL              0U

/* HID Class config */
#define USBD_CUSTOMHID_OUTREPORT_BUF_SIZE  0x02U
#define USBD_CUSTOM_HID_REPORT_DESC_SIZE   63U

/* Memory management macros */
#define USBD_malloc         malloc
#define USBD_free           free
#define USBD_memset         memset
#define USBD_memcpy         memcpy
#define USBD_Delay          HAL_Delay

/* Debug macros — disabled */
#if (USBD_DEBUG_LEVEL > 0)
#define USBD_UsrLog(...)   printf(__VA_ARGS__)
#else
#define USBD_UsrLog(...)
#endif
#define USBD_ErrLog(...)
#define USBD_DbgLog(...)

#ifdef __cplusplus
}
#endif
#endif /* __USBD_CONF_H */
