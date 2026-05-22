/**
 * stm32f1xx_it.c — Interrupt Service Routines
 *
 * USB_LP_CAN1_RX0_IRQHandler is the USB FS interrupt on STM32F103.
 * All other handlers are minimal — HardFault loops for debugging.
 */

#include "stm32f1xx_it.h"
#include "stm32f1xx_hal.h"
#include "usb_device.h"

/* Declared in usbd_conf.c */
extern PCD_HandleTypeDef hpcd_USB_FS;

/* ---- Cortex-M3 Core Exception Handlers ---- */

void NMI_Handler(void) {
    while (1) {}
}

void HardFault_Handler(void) {
    /* Loop here — connect debugger to inspect registers */
    while (1) {}
}

void MemManage_Handler(void) {
    while (1) {}
}

void BusFault_Handler(void) {
    while (1) {}
}

void UsageFault_Handler(void) {
    while (1) {}
}

void SVC_Handler(void) {}

void DebugMon_Handler(void) {}

void PendSV_Handler(void) {}

void SysTick_Handler(void) {
    HAL_IncTick();
}

/* ---- USB FS Interrupt ---- */

/**
 * USB_LP_CAN1_RX0_IRQHandler
 *
 * On STM32F103, the USB Low Priority interrupt shares the vector with
 * CAN RX0. Since CAN is not used here, this handler is dedicated to USB.
 */
void USB_LP_CAN1_RX0_IRQHandler(void) {
    HAL_PCD_IRQHandler(&hpcd_USB_FS);
}
