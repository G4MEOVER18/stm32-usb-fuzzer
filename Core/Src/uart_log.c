/**
 * uart_log.c — USART1 debug output + command input
 *
 * PA9 = TX (AF push-pull), PA10 = RX (input floating)
 * 115200 8N1, polling TX/RX, no DMA/IRQ.
 *
 * All UART_Log() output is prefixed with [Xms] timestamp.
 */

#include "uart_log.h"
#include "stm32f1xx_hal.h"

static UART_HandleTypeDef huart1;

/* -----------------------------------------------------------------------
 * UART_TransmitByte / UART_TransmitStr helpers (no malloc/printf)
 * ----------------------------------------------------------------------- */
static void UART_TxByte(uint8_t b)
{
    HAL_UART_Transmit(&huart1, &b, 1, 2);
}

static void UART_TxStr(const char *s)
{
    while (*s) { UART_TxByte((uint8_t)*s++); }
}

/* Transmit uint32_t as decimal digits */
static void UART_TxDec(uint32_t val)
{
    char buf[11];
    uint8_t i = 10;
    buf[i] = '\0';
    if (val == 0) { UART_TxByte('0'); return; }
    while (val > 0 && i > 0) {
        buf[--i] = (char)('0' + (val % 10));
        val /= 10;
    }
    UART_TxStr(&buf[i]);
}

/* Transmit uint32_t as 0xXXXXXXXX */
static void UART_TxHex(uint32_t val)
{
    const char hex[] = "0123456789ABCDEF";
    char s[11] = "0x00000000";
    for (int i = 9; i >= 2; i--) {
        s[i] = hex[val & 0xF];
        val >>= 4;
    }
    UART_TxStr(s);
}

/* -----------------------------------------------------------------------
 * Init — TX + RX, UART_MODE_TX_RX
 * ----------------------------------------------------------------------- */
void UART_Log_Init(void)
{
    __HAL_RCC_USART1_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitTypeDef gpio = {0};

    /* PA9 = TX */
    gpio.Pin   = GPIO_PIN_9;
    gpio.Mode  = GPIO_MODE_AF_PP;
    gpio.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOA, &gpio);

    /* PA10 = RX */
    gpio.Pin  = GPIO_PIN_10;
    gpio.Mode = GPIO_MODE_INPUT;
    gpio.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOA, &gpio);

    huart1.Instance          = USART1;
    huart1.Init.BaudRate     = 115200;
    huart1.Init.WordLength   = UART_WORDLENGTH_8B;
    huart1.Init.StopBits     = UART_STOPBITS_1;
    huart1.Init.Parity       = UART_PARITY_NONE;
    huart1.Init.Mode         = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl    = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart1);
}

/* -----------------------------------------------------------------------
 * UART_Log — prepends "[Xms] " timestamp, appends CRLF
 * ----------------------------------------------------------------------- */
void UART_Log(const char *msg)
{
    if (!msg) return;
    UART_TxByte('[');
    UART_TxDec(HAL_GetTick());
    UART_TxStr("ms] ");
    UART_TxStr(msg);
    UART_TxStr("\r\n");
}

/* -----------------------------------------------------------------------
 * UART_LogU32 — "[Xms] prefix 0xVALUE"
 * ----------------------------------------------------------------------- */
void UART_LogU32(const char *prefix, uint32_t val)
{
    if (!prefix) return;
    UART_TxByte('[');
    UART_TxDec(HAL_GetTick());
    UART_TxStr("ms] ");
    UART_TxStr(prefix);
    UART_TxHex(val);
    UART_TxStr("\r\n");
}

/* -----------------------------------------------------------------------
 * UART_TryReadCmd — non-blocking RX, single byte
 *
 * Returns:
 *   1–16  → mode number ('1'–'9' = 1–9, 'a'–'g' = 10–16)
 *   's'   → force USB reconnect (0x73)
 *   '?'   → print status    (0x3F)
 *   0     → nothing received
 * ----------------------------------------------------------------------- */
uint8_t UART_TryReadCmd(void)
{
    uint8_t c = 0;
    if (HAL_UART_Receive(&huart1, &c, 1, 0) != HAL_OK) return 0;

    /* Echo received char */
    UART_TxByte(c);
    UART_TxStr("\r\n");

    if (c >= '1' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'm') return (uint8_t)(c - 'a' + 10);   /* a=10..m=22 */
    if (c >= 'n' && c <= 'r') return (uint8_t)(c - 'n' + 23);   /* n=23..r=27 */
    if (c >= 't' && c <= 'v') return (uint8_t)(c - 't' + 28);   /* t=28..v=30 */
    if (c == 's' || c == '?') return c;
    return 0;
}
