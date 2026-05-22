# STM32 Blue Pill USB Fuzzer — Vollständiges Konzept
**Ziel:** Windows 11 USB-Kerneltreiber (usbhub.sys / usbccgp.sys) in isolierter VM auf Robustheit gegen fehlerhafte Deskriptoren prüfen.
**Datum:** 2026-05-21 | **Node:** CyberNode (192.168.0.63)

---

## 1. Hardware-Analyse: STM32F103C8T6 (Blue Pill)

### Mikrocontroller-Kern
| Parameter | Wert |
|---|---|
| Core | ARM Cortex-M3 |
| Takt | 72 MHz (8 MHz ext. Quarz → PLL ×9) |
| Flash | 64 KB (C8-Variante) / 128 KB (CB-Variante) |
| RAM | 20 KB SRAM |
| USB | Full-Speed (FS), 12 Mbps, integrierte USB-Peripherie |
| USB-Pins | PA11 = D− (DM), PA12 = D+ (DP) |

### Bekannte Hardware-Probleme (kritisch!)
**Problem 1 — R10 Pull-Up-Widerstand (häufigster Fehler):**
- USB Full-Speed erfordert 1.5 kΩ Pull-Up auf D+ (PA12)
- Viele Blue Pill Boards haben **10 kΩ** verbaut → USB-Erkennung schlägt fehl / instabil
- **Lösung A (Hardware):** R10 durch 1.5 kΩ ersetzen (Lötarbeit, einmalig, bevorzugt)
- **Lösung B (Software):** PA12 als GPIO-Output konfigurieren, kurz HIGH ziehen dann USB-Peripherie übergeben (im Code implementiert)

**Problem 2 — Boot-Jumper:**
- BOOT0=0, BOOT1=0 → normaler Flash-Boot (Zielzustand nach Flashen)
- BOOT0=1 → Bootloader-Modus (zum Flashen via UART, nicht für ST-Link nötig)
- ST-Link funktioniert unabhängig von BOOT-Jumpern

**Problem 3 — 3.3V Spannungsregler:**
- Onboard AMS1117-3.3 liefert max. 800mA — für dieses Projekt ausreichend
- USB-Bus stellt 5V bereit, Regler wandelt auf 3.3V für MCU

### USB-Peripherie Details
- USB Device FS: eingebaut, keine externe PHY nötig
- Unterstützte Klassen: HID, CDC, MSC, Audio, DFU
- Für Fuzzing optimal: **HID (Keyboard)** — Windows lädt `kbdhid.sys` ohne Treiber-Install
- Endpoints: bis zu 8 bidirektionale Endpoints (EP0-EP7)
- EP0: Control (Pflicht, 64 Byte Paketgröße für FS)
- EP1-EP7: konfigurierbar (Interrupt, Bulk, Isochronous)

### ST-Link V2 Verbindung (SWD)
```
ST-Link V2    →    Blue Pill
SWDIO         →    PA13
SWCLK         →    PA14
GND           →    GND
3.3V          →    3V3 (OPTIONAL — besser USB-Versorgung nutzen)
```

---

## 2. Systemarchitektur

```
┌─────────────────┐    USB    ┌──────────────────────┐    ┌─────────────────────┐
│  STM32 Blue Pill│──────────▶│  Host-PC / Hypervisor │──▶│   Windows 11 VM     │
│  (USB Fuzzer)   │           │  (USB Passthrough)    │    │   (Zielsystem)      │
│                 │           │                       │    │                     │
│  Firmware:      │           │  Hyper-V / VirtualBox │    │  usbhub.sys         │
│  • USB HID FS   │           │  USB passthrough      │    │  usbccgp.sys        │
│  • Manipulierte │           │  aktiviert            │    │  kbdhid.sys         │
│    Deskriptoren │           │                       │    │  WinDbg (Analyse)   │
└─────────────────┘           └──────────────────────┘    └─────────────────────┘
```

**Datenfluss:**
1. Blue Pill enumeriert sich als "USB HID Keyboard" — mit absichtlich korrupten Deskriptoren
2. Host-PC reicht das USB-Gerät per Passthrough an die Windows 11 VM weiter
3. Windows 11 VM versucht Enumeration → `usbhub.sys` verarbeitet die fehlerhaften Deskriptoren
4. Ergebnis: Crash (BSOD), Freeze, oder stabiler Betrieb (Treiber ist robust)

---

## 3. Fuzzing-Strategie: Angriffsvektoren

### Angriff 1 — wTotalLength Mismatch (Configuration Descriptor)
```c
// Configuration Descriptor
0x09,        // bLength = 9 Bytes
0x02,        // bDescriptorType = Configuration
0x05, 0x00,  // wTotalLength = 5 (MANIPULIERT: echte Größe ist 34 Bytes)
             // → Windows liest weniger als vorhanden → Heap-Underread
             // ODER: wTotalLength = 0xFF → Windows liest über Ende hinaus → Heap-Overread
```
**Erwarteter Fehler:** `PAGE_FAULT_IN_NONPAGED_AREA` oder `BUGCODE_USB_DRIVER`

### Angriff 2 — String Descriptor bLength Overflow
```c
// String Descriptor (Manufacturer "YANIS")
0xFF,        // bLength = 255 (MANIPULIERT: echte Länge = 12 Bytes)
0x03,        // bDescriptorType = String
'Y',0,'A',0,'N',0,'I',0,'S',0  // 10 Bytes Nutzdaten
             // → Windows reserviert 255-Byte-Buffer, bekommt nur 12 Bytes
             // → Buffer-Underread / Garbage nach Ende des Descriptors
```
**Erwarteter Fehler:** `MEMORY_MANAGEMENT` oder Kernel-Datenleck

### Angriff 3 — wMaxPacketSize Ungültig
```c
// Endpoint Descriptor für Interrupt EP
0x07,        // bLength
0x05,        // bDescriptorType = Endpoint
0x81,        // bEndpointAddress = EP1 IN
0x03,        // bmAttributes = Interrupt
0xFF, 0x00,  // wMaxPacketSize = 255 (MANIPULIERT: FS Interrupt max = 64 Bytes)
             // → Windows/Host-Controller akzeptiert ungültige Größe
```
**Erwarteter Fehler:** `BUGCODE_USB_DRIVER` oder Host-Controller-Reset

### Angriff 4 — bNumInterfaces Overflow
```c
// Configuration Descriptor
0x09, 0x02, 0x22, 0x00,
0x10,        // bNumInterfaces = 16 (MANIPULIERT: nur 1 Interface definiert)
             // → Windows sucht 15 weitere Interface-Deskriptoren → liest Garbage
```
**Erwarteter Fehler:** Kernel-Null-Pointer oder BSOD

### Angriff 5 — D+ Reconnect Loop (Timing-Angriff)
```c
// USB-Bus Reset in schneller Schleife (< 100ms Intervalle)
// → Windows USB-Stack Zustandsautomat in ungültigen Zustand bringen
// → Race Condition in usbhub.sys möglich
```

---

## 4. Ausführungsplan (Schritt für Schritt)

### Phase 0: Vorbereitung (einmalig, ~30 Min)
- [ ] Blue Pill auf R10-Wert prüfen (Multimeter zwischen PA12 und 3.3V)
  - 10 kΩ → entweder Hardware-Mod ODER Software-Workaround nutzen
  - 1.5 kΩ → optimal, kein Eingriff nötig
- [ ] ST-Link V2 via SWD verbinden
- [ ] STM32CubeIDE installieren (falls nicht vorhanden)
- [ ] VM-Snapshot erstellen (sauberer Zustand als Backup)
- [ ] WinDbg in VM installieren + Kernel-Debugging aktivieren

### Phase 1: Firmware entwickeln (~2 Std)
1. STM32CubeIDE Projekt erstellen (STM32F103C8T6)
2. USB FS Device aktivieren, HID-Klasse wählen
3. Code generieren (CubeMX)
4. Manipulierte Deskriptoren einbauen (usbd_desc.c)
5. D+ Reconnect-Logik in main.c implementieren
6. Kompilieren + Flashen via ST-Link

### Phase 2: Testumgebung (~30 Min)
1. VM (Hyper-V/VirtualBox) mit USB-Passthrough konfigurieren
2. Blue Pill einstecken → Gerät in VM weiterleiten
3. VM-Snapshot als Basis sichern

### Phase 3: Fuzzing-Durchläufe (~1-2 Std pro Angriff)
- Pro Angriffsvektor: separates Firmware-Build + Test
- BSOD protokollieren (Screenshot + MEMORY.DMP)
- VM nach jedem Test auf Snapshot zurücksetzen

### Phase 4: Crash-Analyse
1. MEMORY.DMP aus VM kopieren
2. WinDbg öffnen: `!analyze -v`
3. Stack Trace auswerten: welcher Treiber, welche Funktion
4. Ergebnisse dokumentieren

---

## 5. Vollständige Abhängigkeitsliste

### Hardware
| Komponente | Typ | Zweck |
|---|---|---|
| STM32F103C8T6 Blue Pill | MCU-Board | Fuzzer-Hardware |
| ST-Link V2 | Debugger/Programmer | Flashen + Debugging |
| Micro-USB Kabel | Verbindung | Blue Pill → Host (Fuzzing-Angriff) |
| USB-A Verlängerung | optional | Bessere Handhabung |
| 1.5 kΩ Widerstand | optional | R10-Fix falls 10 kΩ verbaut |

### Entwicklungssoftware (CyberNode Windows)
| Tool | Version | Bezug |
|---|---|---|
| STM32CubeIDE | ≥1.15 | st.com/stm32cubeide (free) |
| arm-none-eabi-gcc | (in CubeIDE integriert) | Compiler für ARM Cortex-M |
| OpenOCD | (in CubeIDE integriert) | Flash/Debug via ST-Link |
| STM32CubeProgrammer | ≥2.16 | st.com (alternativ zu CubeIDE zum Flashen) |
| Git | latest | Versionskontrolle |

### STM32-Bibliotheken (automatisch in CubeIDE)
| Bibliothek | Zweck |
|---|---|
| STM32Cube HAL F1 | Hardware Abstraction Layer |
| STM32_USB_Device_Library | USB Device Stack |
| CMSIS | ARM Core Definitionen |

### Analyse-Tools (Windows 11 VM)
| Tool | Zweck |
|---|---|
| WinDbg (Windows SDK) | Crash-Dump Analyse |
| Process Monitor (Sysinternals) | Treiber-Aktivität live |
| USBPcap + Wireshark | USB-Traffic mitschneiden (optional) |
| DebugView | Kernel-Debug-Output |

### Virtualisierung
| Tool | Konfiguration |
|---|---|
| Hyper-V ODER VirtualBox | USB Passthrough aktiviert |
| Windows 11 ISO | Ziel-VM |
| VM Snapshots | Vor jedem Test-Run |

---

## 6. Projektstruktur (Dateien die Claude Code erstellt)

```
stm32-usb-fuzzer/
├── Core/
│   ├── Inc/
│   │   ├── main.h
│   │   └── stm32f1xx_hal_conf.h
│   └── Src/
│       ├── main.c                  ← Hauptprogramm + USB-Init + Reconnect-Loop
│       └── stm32f1xx_hal_msp.c    ← HAL MSP Konfiguration
├── USB_DEVICE/
│   ├── App/
│   │   ├── usb_device.c           ← USB Device Initialisierung
│   │   ├── usbd_desc.c            ← FUZZING-ZIEL: Manipulierte Deskriptoren
│   │   └── usbd_hid_if.c         ← HID Interface Callbacks
│   └── Target/
│       └── usbd_conf.c            ← USB Low-Level Konfiguration
├── docs/
│   ├── KONZEPT.md                 ← Dieses Dokument
│   └── ERGEBNISSE.md             ← Crash-Protokoll (wird gefüllt)
├── scripts/
│   ├── flash.sh                   ← Automatisches Flashen via OpenOCD
│   └── analyze_dump.py           ← WinDbg-Automation (optional)
├── Makefile                       ← Build-System (arm-none-eabi-make)
└── STM32F103C8TX_FLASH.ld        ← Linker-Script
```

---

## 7. Risikobewertung

| Risiko | Wahrscheinlichkeit | Mitigation |
|---|---|---|
| R10-Widerstand falsch | Hoch (>70% aller Blue Pills) | Software-Workaround im Code |
| VM-Crash beschädigt Host | Sehr niedrig | USB-Passthrough isoliert Host |
| Blue Pill liefert 5V auf Datenleitungen | Nein (USB-Spec konform) | Nicht relevant |
| Windows erkennt korrupte Deskriptoren und ignoriert Gerät | Möglich | Mehrere Angriffsvektoren, variieren |
| STM32CubeIDE generiert inkompatibler Code | Niedrig | HAL direkt, ohne CubeIDE möglich |

---

## 8. Erwartete Ergebnisse

### Best Case (Schwachstelle gefunden)
- BSOD mit `BUGCODE_USB_DRIVER` oder `PAGE_FAULT_IN_NONPAGED_AREA`
- WinDbg Stack Trace zeigt: `usbhub!UsbhTtClearTtBuffer` o.ä.
- Dokumentierbare Kernel-Schwachstelle

### Likely Case (Treiber robust)
- Windows ignoriert das Gerät oder deinstalliert es mit Fehlercode
- Gerätestatus: "Windows konnte das Gerät nicht starten (Code 10/43)"
- Kein Crash → Windows 11 USB-Stack ist gegen diese Angriffe gehärtet

### Interessant Case (Teilabsturz)
- USB-Subsystem friert ein ohne BSOD
- Gerät verschwindet aus Geräte-Manager
- Andere USB-Geräte in VM werden deaktiviert

---

*Dieses Konzept basiert auf der Datei: `\\GAMING-NODE\Optane\STM32 FUZZER TEST.txt`*
