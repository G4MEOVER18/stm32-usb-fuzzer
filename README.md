# STM32 USB Descriptor Fuzzer

Ein Hardware-USB-Fuzzer auf Basis des STM32F103C8T6 (Blue Pill), der fehlerhafte USB-Deskriptoren sendet, um Schwachstellen in Windows-USB-Treiber-Stacks zu finden (`usbport.sys`, `usbhub.sys`, `usbccgp.sys`, `kbdhid.sys`, `usbstor.sys`, `hidparse.sys`).

**30 zur Laufzeit wählbare Angriffsmodi** — kein erneutes Flashen nötig. Die Modi decken Device-, Configuration-, Interface-, Endpoint-, String-, HID-, Hub-, BOS-, LangID- und Device-Qualifier-Deskriptoren ab, außerdem EP0-Protokollangriffe, Composite-Device-Confusion, USB-MSC-Exploitation und autonomes BSOD-Triggering.

> **Nur für autorisierte Sicherheitsforschung und Penetrationstests.**

---

## Hardware

| Komponente | Details |
|-----------|---------|
| MCU | STM32F103C8T6 (Blue Pill, 128KB Flash, 20KB RAM) |
| USB | Full-Speed USB 2.0 (PA11/PA12) |
| UART-Debug | USART1, PA9=TX, PA10=RX, 115200 8N1 |
| Modusauswahl | PB2 (Freeze), PB3/PB4 (Bank), BKP_DR1 (Zähler) |
| LED | PC13 (active low, blinkt den aktiven Modus) |
| Watchdog | IWDG ~26s Timeout |

---

## Angriffsmodi

### Gruppe 1 — Device Descriptor
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 1 | `1` | `bDeviceClass=0x09` Hub-Impersonation + Hub-Deskriptor mit 255 Ports | `usbhub.sys` Pool-OOB-Read |
| 2 | `2` | `bcdUSB=0x0300` gefälschtes USB 3.0 + fehlerhafter BOS (85→45 Bytes, Cap `bLength=255`) | USB-3.0-Stack-Overread |
| 3 | `3` | `bNumConfigurations=0` | Logikfehler bei der USB-Enumeration |
| 4 | `4` | `bMaxPacketSize0=0xFF` + EP `wMaxPacketSize=255` | Verletzung der Paketgrößenbeschränkung |

### Gruppe 2 — Config / Interface / Endpoint
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 5 | `5` | `wTotalLength=5` (Underread) | Config-Deskriptor-Underread |
| 6 | `6` | `wTotalLength=0xFFFF` (65535) | 64KB Kernel-Buffer-Overread |
| 7 | `7` | `bNumInterfaces=16` | `usbccgp.sys` Interface-Array-Overflow |
| 8 | `8` | `bNumEndpoints=0` Lüge (EP trotzdem offen) | Class-Driver-EP-Confusion |
| 9 | `9` | `bmAttributes=0x00` + `bInterval=0` + `iface.bLength=0` | Parser-Endlosschleife |

### Gruppe 3 — String Descriptors
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 10 | `a` | Manufacturer-String `bLength=0xFE`, 252 Unicode-Zeichen gesendet | CVE-2024-21429: `usbhub.sys` Kernel-Buffer-Overflow |

### Gruppe 4 — HID Descriptors
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 11 | `b` | `wDescriptorLength=0xFFFF` | Übergroße HID-Report-Buffer-Allokation |
| 12 | `c` | `wTotalLength=0xFFFF` + HID `bNumDescriptors=16` | Doppelter Overread |
| 13 | `d` | Multi-Vektor-HID-Report: Nesting-Underflow + PUSH-Bomb + Long Item + `REPORT_SIZE=255×REPORT_COUNT=255` | `hidparse.sys`-Korruption |

### Gruppe 5 — Sonderfälle / Timing
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 14 | `e` | 200ms-Reconnect-Loop + fehlerhafter HID-Deskriptor | UAF-Race-Condition |
| 15 | `f` | LCG-Vollzufalls-Deskriptor-Patch bei jedem Reconnect | Stochastisches Fuzzing |
| 16 | `g` | Auto-Sequencer: alle Modi 1–15 nach Absturzwahrscheinlichkeit sortiert | Automatisierter Sweep |

### Gruppe 6 — Keyboard BSOD (nur manuell)
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 17 | `h` | **Autonom**: als Tastatur enumerieren → `CrashOnCtrlScroll=1` Registry-Key per HID setzen → USB-Reconnect → `RCtrl+ScrollLock×2` | `MANUALLY_INITIATED_CRASH (0xE2)` |

### Gruppe 7 — BIOS/POST-Disruption
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 18 | `i` | 10ms-Reconnect-Hammer | BIOS-USB-Enumerierungs-Timeout |
| 19 | `j` | `bNumConfigs=254` + `wTotalLength=0xFFFF` | BIOS Config-Enum-Schleife |
| 20 | `k` | LangID `bLength=0xFF` (4 echte Bytes) | BIOS-String-Parser-OOB |
| 21 | `l` | DevQual `bLength=0xFF` + `bcdUSB=0x0300` | HS-Negotiation-Crash |
| 22 | `m` | Boot-Disruption-Sequencer: Modi 19→20→21→1→2→6→10 + schnelle Reconnect-Bursts | Vollständige BIOS-Disruption |

### Gruppe 8 — EP0 / Protokollangriffe
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 23 | `n` | EP0 STALL in der Status-Phase: Deskriptordaten gesendet, Handshake abgebrochen | `usbport.sys`-Retry-Schleife |
| 24 | `o` | MS OS String `MSFT100` → Extended Compat ID `dwLength=0xFFFF` | Windows Kernel-Pool-OOB |
| 25 | `p` | Deskriptor-Morph: HID→Hub→zufällig bei jedem Reconnect, gleiche VID/PID | Driver-Re-Bind-Confusion |

### Gruppe 9 — Composite / Class-Angriffe
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 26 | `q` | IAD-Konflikt: 3 IADs beanspruchen alle Interface 0 (HID+CDC+Hub, Counts 2/2/255) | `usbccgp.sys` Interface-Map-Aliasing |
| 27 | `r` | USB MSC (BOT/SCSI) + fehlerhafter CSW (`dCSWSignature=0xBAADC0DE`, Phase Error) | `usbstor.sys` BOT-Reset-Schleife |

### Gruppe 10 — Flood / Rapid-Fire
| Modus | Taste | Angriff | Ziel |
|------|-----|--------|--------|
| 28 | `t` | HID-Boot-Keyboard-Flood: 1000 Reports/s, alle Tasten gedrückt/losgelassen | Input-Subsystem-Stall |
| 29 | `u` | Rapid-Fire-Sequencer: alle 24 Modi je 50ms, keine Erholungszeit | Kein USB-Stack-Recovery |
| 30 | `v` | OMNI BOMB: alle Deskriptor-Angriffe gleichzeitig + EP0 STALL | Maximale Gleichzastlast |

---

## Modusauswahl

### UART (PA9/PA10, 115200 8N1)
```
1–9   → Modus 1–9
a–m   → Modus 10–22
n–r   → Modus 23–27
t–v   → Modus 28–30
s     → Erzwingt USB-Reconnect (kein Moduswechsel)
?     → Aktuellen Status ausgeben
```

### Hardware-Pins
- **PB2 = GND** → Modus EINGEFROREN (kein Zählerfortschritt beim Reset)
  - PB3/PB4 wählen Bank: `00`=Modi 1–4, `01`=5–8, `10`=9–12, `11`=13–16
  - BKP_DR1 Intra-Bank-Offset (1–4)
- **PB2 = offen** → Reset-Zähler: jeder Reset schaltet einen Modus weiter 1→2→…→30→1

### LED-Kodierung
```
Modi  1–8  : N kurze Blinks
Modi  9–16 : 1 langer + (Modus−8) kurze
Modus 17   : 4 lange Blinks (⚠ BSOD-Warnung)
Modi 18–22 : 2 lange + (Modus−17) kurze
Modi 23–30 : 3 lange + (Modus−22) kurze
```

---

## Fertige Firmware

Vorkompilierte Images unter [**Releases**](https://github.com/G4MEOVER18/stm32-usb-fuzzer/releases/latest):

```bash
# .bin an Flash-Basis flashen (ST-Link):
st-flash write stm32-usb-fuzzer_STM32F103C8_v2.0.0.bin 0x08000000
# oder .hex via ST-Link Utility / OpenOCD
```

## Build & Flash

### PlatformIO (empfohlen — lädt Toolchain + HAL automatisch)

```bash
pio run                       # bauen (ARM-GCC + STM32Cube-HAL werden geladen)
pio run -t upload             # flashen (ST-Link)
pio device monitor -b 115200  # UART-Debug
```

Plattform/Board sind in `platformio.ini` gepinnt (`ststm32`, `bluepill_f103c8`). Kein manuelles CUBE-SDK nötig.

### Makefile (Alternative)

```bash
# Prerequisites: arm-none-eabi-gcc, make, openocd + STM32CubeF1 HAL
# (CUBE_SDK-Pfad im Makefile anpassen)
make            # build → .elf / .bin
make flash      # flash via OpenOCD + ST-Link
```

**Flash-Belegung:** ~21 KB von 128 KB

---

## Architektur

```
Core/
  Inc/main.h          — Moduskonstanten (FUZZ_MODE_*), Pin-/Timing-Defines
  Src/main.c          — Modus-Dispatch, GPIO/BKP-Modusauswahl, LED, IWDG
  Src/uart_log.c      — USART1 TX/RX, zeitgestempeltes Logging, Befehls-Parser

USB_DEVICE/App/
  usbd_fuzzer.c       — USBD_ClassTypeDef: gesamtes Deskriptor-Patching, EP0_TxSent,
                        DataOut (MSC), ApplyFuzzPatches(), Deskriptor-Arrays
  usbd_fuzzer.h       — Größen, Endpoint-Adressen, Extern-Deklarationen
  usbd_desc.c         — Device/String/LangID-Deskriptor-Callbacks, Laufzeit-Patches
```

Kerndesign: alle 30 Modi in einem **einzigen Binary**. Kein `#ifdef` zur Compile-Zeit. Der Modus wird zur Laufzeit über GPIO/BKP/UART ausgewählt. `GetFSCfgDesc()` ist vollständig überschrieben, sodass jedes Byte, das der Host empfängt, unter der Kontrolle des Fuzzers liegt.

---

## Findings / Gezielte CVEs

| CVE | Beschreibung | Modus |
|-----|-------------|------|
| CVE-2024-21429 | `usbhub.sys` Heap-Overflow über überlangen String-Deskriptor | 10 |
| — | `usbhub.sys` OOB-Read über Hub-Deskriptor mit 255 Ports | 1 |
| — | `hidparse.sys` Nesting-Counter-Underflow | 13 |
| — | `usbccgp.sys` Interface-Map-Korruption über IAD-Overlap | 26 |
| — | `usbstor.sys` BOT-Protokoll-Confusion-Schleife | 27 |

---

## Sicherheitshinweise

- Nur auf Systemen verwenden, die dir gehören oder für die eine ausdrückliche schriftliche Genehmigung vorliegt
- Modus 17 (Keyboard BSOD) bringt das Zielsystem zum Absturz — nur in isolierten Testumgebungen einsetzen
- Die Modi 18–22 (BIOS-Disruption) greifen das Ziel auf Firmware-Ebene während des POST an
- Für Schäden durch Missbrauch wird keine Haftung übernommen

---

## Lizenz

MIT License — siehe [LICENSE](LICENSE)

---

*Teil laufender Sicherheitsforschung zu USB-Treibern. Beiträge und Bug-Reports sind willkommen.*

---

## Support

Falls dieses Tool dir Zeit gespart oder bei deiner Forschung geholfen hat, freue ich mich über eine kleine Spende:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`

**Kontakt:** [g4me.over.18@gmail.com](mailto:g4me.over.18@gmail.com)
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)
