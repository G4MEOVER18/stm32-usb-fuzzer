/**
 * startup_stm32f103xb.s — Reset handler + interrupt vector table
 * STM32F103C8T6 / STM32F103CBT6 (Cortex-M3)
 */

  .syntax unified
  .cpu cortex-m3
  .thumb

  .global g_pfnVectors
  .global Default_Handler

/* Stack and heap sizes (4KB stack, 512B heap) */
  .section .stack
  .align 3
  .equ    Stack_Size, 0x00001000
  .space  Stack_Size

  .section .heap
  .align 3
  .equ    Heap_Size, 0x00000200
  .space  Heap_Size

/* Reset handler */
  .text
  .thumb_func
  .global Reset_Handler
  .type Reset_Handler, %function
Reset_Handler:
  /* Copy .data from FLASH to RAM */
  ldr   r0, =_sdata
  ldr   r1, =_edata
  ldr   r2, =_sidata
  movs  r3, #0
  b     LoopCopyDataInit

CopyDataInit:
  ldr   r4, [r2, r3]
  str   r4, [r0, r3]
  adds  r3, r3, #4

LoopCopyDataInit:
  adds  r4, r0, r3
  cmp   r4, r1
  bcc   CopyDataInit

  /* Zero .bss */
  ldr   r2, =_sbss
  ldr   r4, =_ebss
  movs  r3, #0
  b     LoopFillZerobss

FillZerobss:
  str   r3, [r2]
  adds  r2, r2, #4

LoopFillZerobss:
  cmp   r2, r4
  bcc   FillZerobss

  bl    SystemInit
  bl    main
  bx    lr
  .size Reset_Handler, .-Reset_Handler

  .thumb_func
Default_Handler:
  b     Default_Handler
  .size Default_Handler, .-Default_Handler

/* Weak aliases — override by defining the function in C */
  .macro  WeakIRQ name
  .weak   \name
  .thumb_set \name, Default_Handler
  .endm

/* Vector table */
  .section .isr_vector,"a",%progbits
  .type g_pfnVectors, %object

g_pfnVectors:
  .word   _estack                   /* Initial SP */
  .word   Reset_Handler
  .word   NMI_Handler
  .word   HardFault_Handler
  .word   MemManage_Handler
  .word   BusFault_Handler
  .word   UsageFault_Handler
  .word   0
  .word   0
  .word   0
  .word   0
  .word   SVC_Handler
  .word   DebugMon_Handler
  .word   0
  .word   PendSV_Handler
  .word   SysTick_Handler
  /* External interrupts */
  .word   Default_Handler           /* WWDG */
  .word   Default_Handler           /* PVD */
  .word   Default_Handler           /* TAMPER */
  .word   Default_Handler           /* RTC */
  .word   Default_Handler           /* FLASH */
  .word   Default_Handler           /* RCC */
  .word   Default_Handler           /* EXTI0 */
  .word   Default_Handler           /* EXTI1 */
  .word   Default_Handler           /* EXTI2 */
  .word   Default_Handler           /* EXTI3 */
  .word   Default_Handler           /* EXTI4 */
  .word   Default_Handler           /* DMA1_CH1 */
  .word   Default_Handler           /* DMA1_CH2 */
  .word   Default_Handler           /* DMA1_CH3 */
  .word   Default_Handler           /* DMA1_CH4 */
  .word   Default_Handler           /* DMA1_CH5 */
  .word   Default_Handler           /* DMA1_CH6 */
  .word   Default_Handler           /* DMA1_CH7 */
  .word   Default_Handler           /* ADC1_2 */
  .word   USB_HP_CAN1_TX_IRQHandler /* USB_HP / CAN1_TX */
  .word   USB_LP_CAN1_RX0_IRQHandler/* USB_LP / CAN1_RX0 ← USB FS IRQ */
  .word   Default_Handler           /* CAN1_RX1 */
  .word   Default_Handler           /* CAN1_SCE */
  .word   Default_Handler           /* EXTI9_5 */
  .word   Default_Handler           /* TIM1_BRK */
  .word   Default_Handler           /* TIM1_UP */
  .word   Default_Handler           /* TIM1_TRG_COM */
  .word   Default_Handler           /* TIM1_CC */
  .word   Default_Handler           /* TIM2 */
  .word   Default_Handler           /* TIM3 */
  .word   Default_Handler           /* TIM4 */
  .word   Default_Handler           /* I2C1_EV */
  .word   Default_Handler           /* I2C1_ER */
  .word   Default_Handler           /* I2C2_EV */
  .word   Default_Handler           /* I2C2_ER */
  .word   Default_Handler           /* SPI1 */
  .word   Default_Handler           /* SPI2 */
  .word   Default_Handler           /* USART1 */
  .word   Default_Handler           /* USART2 */
  .word   Default_Handler           /* USART3 */
  .word   Default_Handler           /* EXTI15_10 */
  .word   Default_Handler           /* RTCAlarm */
  .word   USBWakeUp_IRQHandler      /* USBWakeUp */

  .size g_pfnVectors, .-g_pfnVectors

  WeakIRQ NMI_Handler
  WeakIRQ HardFault_Handler
  WeakIRQ MemManage_Handler
  WeakIRQ BusFault_Handler
  WeakIRQ UsageFault_Handler
  WeakIRQ SVC_Handler
  WeakIRQ DebugMon_Handler
  WeakIRQ PendSV_Handler
  WeakIRQ SysTick_Handler
  WeakIRQ USB_HP_CAN1_TX_IRQHandler
  WeakIRQ USB_LP_CAN1_RX0_IRQHandler
  WeakIRQ USBWakeUp_IRQHandler
