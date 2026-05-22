# STM32 USB Descriptor Fuzzer

A hardware USB fuzzer running on the STM32F103C8T6 (Blue Pill) that sends malformed USB descriptors to probe vulnerabilities in Windows USB driver stacks (`usbport.sys`, `usbhub.sys`, `usbccgp.sys`, `kbdhid.sys`, `usbstor.sys`, `hidparse.sys`).

**30 runtime-selectable attack modes** — no reflashing required. Modes cover Device, Configuration, Interface, Endpoint, String, HID, Hub, BOS, LangID, Device Qualifier descriptors, EP0 protocol attacks, composite device confusion, USB MSC exploitation, and autonomous BSOD triggering.

> **For authorized security research and penetration testing only.**

---

## Hardware

| Component | Details |
|-----------|---------|
| MCU | STM32F103C8T6 (Blue Pill, 128KB Flash, 20KB RAM) |
| USB | Full-Speed USB 2.0 (PA11/PA12) |
| UART debug | USART1, PA9=TX, PA10=RX, 115200 8N1 |
| Mode select | PB2 (freeze), PB3/PB4 (bank), BKP_DR1 (counter) |
| LED | PC13 (active low, blink-encodes active mode) |
| Watchdog | IWDG ~26s timeout |

---

## Attack Modes

### Group 1 — Device Descriptor
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 1 | `1` | `bDeviceClass=0x09` Hub impersonation + 255-port hub descriptor | `usbhub.sys` pool OOB read |
| 2 | `2` | `bcdUSB=0x0300` fake USB 3.0 + malformed BOS (85→45 bytes, cap `bLength=255`) | USB 3.0 stack overread |
| 3 | `3` | `bNumConfigurations=0` | USB enumeration logic error |
| 4 | `4` | `bMaxPacketSize0=0xFF` + EP `wMaxPacketSize=255` | Packet size constraint violation |

### Group 2 — Config / Interface / Endpoint
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 5 | `5` | `wTotalLength=5` (underread) | Config descriptor underread |
| 6 | `6` | `wTotalLength=0xFFFF` (65535) | 64KB kernel buffer overread |
| 7 | `7` | `bNumInterfaces=16` | `usbccgp.sys` interface array overflow |
| 8 | `8` | `bNumEndpoints=0` lie (EP still open) | Class driver EP confusion |
| 9 | `9` | `bmAttributes=0x00` + `bInterval=0` + `iface.bLength=0` | Parser infinite loop |

### Group 3 — String Descriptors
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 10 | `a` | Manufacturer string `bLength=0xFE`, 252 Unicode chars sent | CVE-2024-21429: `usbhub.sys` kernel buffer overflow |

### Group 4 — HID Descriptors
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 11 | `b` | `wDescriptorLength=0xFFFF` | Huge HID report buffer alloc |
| 12 | `c` | `wTotalLength=0xFFFF` + HID `bNumDescriptors=16` | Double overread |
| 13 | `d` | Multi-vector HID report: nesting underflow + PUSH bomb + Long Item + `REPORT_SIZE=255×REPORT_COUNT=255` | `hidparse.sys` corruption |

### Group 5 — Special / Timing
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 14 | `e` | 200ms reconnect loop + malformed HID descriptor | UAF race condition |
| 15 | `f` | LCG full-descriptor random patch every reconnect | Stochastic fuzzing |
| 16 | `g` | Auto-sequencer: all modes 1–15 ordered by crash probability | Automated sweep |

### Group 6 — Keyboard BSOD (Manual Only)
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 17 | `h` | **Autonomous**: enumerate as keyboard → set `CrashOnCtrlScroll=1` registry key via HID → USB reconnect → `RCtrl+ScrollLock×2` | `MANUALLY_INITIATED_CRASH (0xE2)` |

### Group 7 — BIOS/POST Disruption
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 18 | `i` | 10ms reconnect hammer | BIOS USB enumeration timeout |
| 19 | `j` | `bNumConfigs=254` + `wTotalLength=0xFFFF` | BIOS config enum loop |
| 20 | `k` | LangID `bLength=0xFF` (4 real bytes) | BIOS string parser OOB |
| 21 | `l` | DevQual `bLength=0xFF` + `bcdUSB=0x0300` | HS negotiation crash |
| 22 | `m` | Boot disruption sequencer: modes 19→20→21→1→2→6→10 + rapid reconnect bursts | Full BIOS disruption |

### Group 8 — EP0 / Protocol Attacks
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 23 | `n` | EP0 STALL at status phase: descriptor data sent, handshake aborted | `usbport.sys` retry loop |
| 24 | `o` | MS OS String `MSFT100` → Extended Compat ID `dwLength=0xFFFF` | Windows kernel pool OOB |
| 25 | `p` | Descriptor morph: HID→Hub→random per reconnect, same VID/PID | Driver re-bind confusion |

### Group 9 — Composite / Class Attacks
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 26 | `q` | IAD conflict: 3 IADs all claim Interface 0 (HID+CDC+Hub, counts 2/2/255) | `usbccgp.sys` interface-map aliasing |
| 27 | `r` | USB MSC (BOT/SCSI) + malformed CSW (`dCSWSignature=0xBAADC0DE`, Phase Error) | `usbstor.sys` BOT reset loop |

### Group 10 — Flood / Rapid-Fire
| Mode | Key | Attack | Target |
|------|-----|--------|--------|
| 28 | `t` | HID boot keyboard flood: 1000 reports/s, all keys pressed/released | Input subsystem stall |
| 29 | `u` | Rapid-fire sequencer: all 24 modes at 50ms each, no recovery time | No USB stack recovery |
| 30 | `v` | OMNI BOMB: all descriptor attacks simultaneously + EP0 STALL | Maximum simultaneous load |

---

## Mode Selection

### UART (PA9/PA10, 115200 8N1)
```
1–9   → Mode 1–9
a–m   → Mode 10–22
n–r   → Mode 23–27
t–v   → Mode 28–30
s     → Force USB reconnect (no mode change)
?     → Print current status
```

### Hardware Pins
- **PB2 = GND** → Mode FROZEN (no counter advance on reset)
  - PB3/PB4 select bank: `00`=modes 1–4, `01`=5–8, `10`=9–12, `11`=13–16
  - BKP_DR1 intra-bank offset (1–4)
- **PB2 = open** → Reset counter: each reset advances mode 1→2→…→30→1

### LED Encoding
```
Modes  1–8  : N short blinks
Modes 9–16  : 1 long + (mode−8) short
Mode  17    : 4 long blinks (⚠ BSOD warning)
Modes 18–22 : 2 long + (mode−17) short
Modes 23–30 : 3 long + (mode−22) short
```

---

## Build & Flash

```bash
# Prerequisites: arm-none-eabi-gcc, make, openocd
# STM32CubeF1 HAL library expected at D:/Projekte/Firmware/STM32CubeF1
# (adjust Makefile paths as needed)

make            # build → stm32-usb-fuzzer.elf / .bin
make flash      # flash via OpenOCD + ST-Link
```

**Toolchain:** arm-none-eabi-gcc, OpenOCD with ST-Link v2

**Flash usage:** ~23KB of 128KB

---

## Architecture

```
Core/
  Inc/main.h          — Mode constants (FUZZ_MODE_*), pin/timing defines
  Src/main.c          — Mode dispatch, GPIO/BKP mode selection, LED, IWDG
  Src/uart_log.c      — USART1 TX/RX, timestamped logging, command parser

USB_DEVICE/App/
  usbd_fuzzer.c       — USBD_ClassTypeDef: all descriptor patching, EP0_TxSent,
                        DataOut (MSC), ApplyFuzzPatches(), descriptor arrays
  usbd_fuzzer.h       — Sizes, endpoint addresses, extern declarations
  usbd_desc.c         — Device/String/LangID descriptor callbacks, runtime patches
```

Key design: all 30 modes in a **single binary**. No compile-time `#ifdef`. Mode is selected at runtime from GPIO/BKP/UART. `GetFSCfgDesc()` is fully overridden so every byte the host receives is under fuzzer control.

---

## Findings / CVEs Targeted

| CVE | Description | Mode |
|-----|-------------|------|
| CVE-2024-21429 | `usbhub.sys` heap overflow via oversized string descriptor | 10 |
| — | `usbhub.sys` OOB read via Hub descriptor with 255 ports | 1 |
| — | `hidparse.sys` nesting counter underflow | 13 |
| — | `usbccgp.sys` interface-map corruption via IAD overlap | 26 |
| — | `usbstor.sys` BOT protocol confusion loop | 27 |

---

## Safety

- Only use on systems you own or have explicit written authorization to test
- Mode 17 (keyboard BSOD) will crash the target system — use in isolated test environments
- Modes 18–22 (BIOS disruption) affect the target at firmware level during POST
- Not responsible for any damage caused by misuse

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Part of ongoing USB driver security research. Contributions and bug reports welcome.*

---

## Support

If this tool saved you time or helped with your research, consider a small donation:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)
