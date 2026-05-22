/**
 * uart_log.h — USART1 debug logger (PA9=TX, PA10=RX, 115200 8N1)
 */
#ifndef __UART_LOG_H
#define __UART_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void    UART_Log_Init(void);
void    UART_Log(const char *msg);       /* prepends [Xms] timestamp */
void    UART_LogU32(const char *prefix, uint32_t val);

/* Non-blocking RX command parser.
 * Returns: 1–30 = mode switch, 's' = reconnect, '?' = status, 0 = nothing */
uint8_t UART_TryReadCmd(void);

#ifdef __cplusplus
}
#endif

#endif /* __UART_LOG_H */
