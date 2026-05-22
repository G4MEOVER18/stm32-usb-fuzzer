/**
 * stm32f1xx_hal_msp.c — HAL MSP (MCU Support Package) callbacks
 *
 * HAL_Init() calls HAL_MspInit() — used here to set interrupt priority
 * grouping. USB peripheral MSP init/deinit is in usbd_conf.c.
 */

#include "stm32f1xx_hal.h"

void HAL_MspInit(void) {
    /* Set priority grouping: 4 bits preemption, 0 bits sub-priority */
    HAL_NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_4);

    /* SysTick at lowest priority — USB IRQ must be higher */
    HAL_NVIC_SetPriority(SysTick_IRQn, 15, 0);
}
