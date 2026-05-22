/**
 * system_stm32f1xx.c — System initialization stub
 *
 * Called by Reset_Handler before main().
 * Actual clock config happens in SystemClock_Config() inside main.c.
 * This stub satisfies the linker — the HAL SDK version is more complete
 * but requires CMSIS device headers that come with STM32CubeIDE.
 */

#include "stm32f1xx_hal.h"

uint32_t SystemCoreClock = 8000000UL; /* Updated after SystemClock_Config() */

/* Required by HAL RCC driver — prescaler lookup tables */
const uint8_t AHBPrescTable[16U] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 6, 7, 8, 9};
const uint8_t APBPrescTable[8U]  = {0, 0, 0, 0, 1, 2, 3, 4};

void SystemInit(void) {
    /* Reset RCC to defaults (HSI on, PLL off) */
    /* The HAL SystemClock_Config in main.c then configures 72 MHz */
    RCC->CR |= RCC_CR_HSION;
    RCC->CFGR = 0x00000000U;
    RCC->CR &= ~(RCC_CR_HSEON | RCC_CR_CSSON | RCC_CR_PLLON);
    RCC->CR &= ~(RCC_CR_HSEBYP);
    RCC->CFGR &= 0xFF80FFFFU; /* Reset PLL bits */
    RCC->CIR = 0x00000000U;   /* Disable all clock interrupts */
}

void SystemCoreClockUpdate(void) {
    /* Not needed — HAL tracks SystemCoreClock internally */
}
