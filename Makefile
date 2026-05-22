######################################
# STM32 USB Fuzzer — Universal Build
# Target: STM32F103C8T6 (Blue Pill)
# Mode selected at runtime via GPIO jumpers — no recompile needed
######################################

TARGET = stm32-usb-fuzzer

# Toolchain (PlatformIO install — Windows paths for Windows binary)
TOOLCHAIN = C:/Users/Yanis/.platformio/packages/toolchain-gccarmnoneeabi/bin
CC      = $(TOOLCHAIN)/arm-none-eabi-gcc
OBJCOPY = $(TOOLCHAIN)/arm-none-eabi-objcopy
SIZE    = $(TOOLCHAIN)/arm-none-eabi-size

# MCU flags
MCU = -mcpu=cortex-m3 -mthumb

# Compiler flags
CFLAGS  = $(MCU) -Wall -Wextra -O2 -g
CFLAGS += -DSTM32F103xB
CFLAGS += -DUSE_HAL_DRIVER
CFLAGS += -ffunction-sections -fdata-sections

# Include paths
CUBE_SDK ?= D:/Projekte/Firmware/STM32CubeF1
HAL_PATH  = $(CUBE_SDK)/Drivers/STM32F1xx_HAL_Driver
CMSIS_PATH= $(CUBE_SDK)/Drivers/CMSIS
USB_PATH  = $(CUBE_SDK)/Middlewares/ST/STM32_USB_Device_Library

INCLUDES  = -ICore/Inc
INCLUDES += -IUSB_DEVICE/App
INCLUDES += -IUSB_DEVICE/Target
INCLUDES += -I$(HAL_PATH)/Inc
INCLUDES += -I$(CMSIS_PATH)/Device/ST/STM32F1xx/Include
INCLUDES += -I$(CMSIS_PATH)/Include
INCLUDES += -I$(USB_PATH)/Core/Inc
INCLUDES += -I$(USB_PATH)/Class/HID/Inc

# Linker
LDSCRIPT = STM32F103C8TX_FLASH.ld
LDFLAGS  = $(MCU) -specs=nano.specs -T$(LDSCRIPT) -Wl,--gc-sections -Wl,-Map=$(TARGET).map

# Source files
SRCS  = Core/Src/main.c
SRCS += Core/Src/stm32f1xx_hal_msp.c
SRCS += Core/Src/stm32f1xx_it.c
SRCS += Core/Src/system_stm32f1xx.c
SRCS += Core/Src/uart_log.c
SRCS += USB_DEVICE/App/usb_device.c
SRCS += USB_DEVICE/App/usbd_desc.c
SRCS += USB_DEVICE/App/usbd_fuzzer.c
SRCS += USB_DEVICE/Target/usbd_conf.c

# HAL sources (from STM32CubeF1 SDK)
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_cortex.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_gpio.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_pcd.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_pcd_ex.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_rcc.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_rcc_ex.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_uart.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_iwdg.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_hal_pwr.c
SRCS += $(HAL_PATH)/Src/stm32f1xx_ll_usb.c

# USB Device Library (Core only)
SRCS += $(USB_PATH)/Core/Src/usbd_core.c
SRCS += $(USB_PATH)/Core/Src/usbd_ctlreq.c
SRCS += $(USB_PATH)/Core/Src/usbd_ioreq.c

# Startup (assembly)
ASM_SRCS = Core/Src/startup_stm32f103xb.s

C_OBJS   = $(SRCS:.c=.o)
ASM_OBJS = $(ASM_SRCS:.s=.o)
OBJS     = $(C_OBJS) $(ASM_OBJS)

.PHONY: all clean flash

all: $(TARGET).elf $(TARGET).bin
	$(SIZE) $(TARGET).elf

$(TARGET).elf: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.s
	$(CC) $(MCU) -x assembler-with-cpp -c $< -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

# Flash via OpenOCD + ST-Link V2
flash: $(TARGET).bin
	openocd -f interface/stlink.cfg -f target/stm32f1x.cfg \
	    -c "program $(TARGET).bin 0x08000000 verify reset exit"

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).bin $(TARGET).map
