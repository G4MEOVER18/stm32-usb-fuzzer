/* HAL configuration — enable only modules needed for USB fuzzer */
#ifndef __STM32F1XX_HAL_CONF_H
#define __STM32F1XX_HAL_CONF_H

#define HAL_MODULE_ENABLED
#define HAL_CORTEX_MODULE_ENABLED
#define HAL_GPIO_MODULE_ENABLED
#define HAL_RCC_MODULE_ENABLED
#define HAL_PCD_MODULE_ENABLED
#define HAL_UART_MODULE_ENABLED   /* for UART debug logging */
#define HAL_DMA_MODULE_ENABLED    /* required by UART HAL */
#define HAL_FLASH_MODULE_ENABLED  /* required for FLASH_LATENCY_2 */
#define HAL_IWDG_MODULE_ENABLED   /* watchdog */
#define HAL_PWR_MODULE_ENABLED    /* required for HAL_PWR_EnableBkUpAccess / BKP register */

/* HSE crystal on Blue Pill = 8 MHz */
#define HSE_VALUE    8000000U
#define HSE_STARTUP_TIMEOUT    100U
#define HSI_VALUE    8000000U
#define LSI_VALUE    40000U
#define LSE_VALUE    32768U
#define LSE_STARTUP_TIMEOUT    5000U

#define  VDD_VALUE                    3300U
#define  TICK_INT_PRIORITY            15U
#define  USE_RTOS                     0U
#define  PREFETCH_ENABLE              1U

/* Includes */
#include "stm32f1xx_hal_rcc.h"
#include "stm32f1xx_hal_gpio.h"
#include "stm32f1xx_hal_dma.h"
#include "stm32f1xx_hal_cortex.h"
#include "stm32f1xx_hal_flash.h"
#include "stm32f1xx_hal_pcd.h"
#include "stm32f1xx_hal_uart.h"
#include "stm32f1xx_hal_iwdg.h"
#include "stm32f1xx_hal_pwr.h"

/* Assert — disabled for production, enable for debug */
#define USE_FULL_ASSERT 0
#if (USE_FULL_ASSERT == 1U)
  #define assert_param(expr) ((expr) ? (void)0U : assert_failed((uint8_t *)__FILE__, __LINE__))
  void assert_failed(uint8_t *file, uint32_t line);
#else
  #define assert_param(expr) ((void)0U)
#endif

#endif /* __STM32F1XX_HAL_CONF_H */
