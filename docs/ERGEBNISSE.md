# USB Fuzzer — Crash-Protokoll

| Datum | Fuzz Mode | Windows Reaktion | BSOD Code | WinDbg Stack | Bewertung |
|-------|-----------|-----------------|-----------|--------------|-----------|
| - | - | - | - | - | - |

## WinDbg Kommandos

Crash-Dump öffnen:
```
windbg -z C:\Windows\MEMORY.DMP
```

Automatische Analyse:
```
!analyze -v
```

USB-Treiber-Stack:
```
!devstack @$teb
lm m usbhub
lm m usbccgp
```

Stack Trace:
```
kb
kv
```

## Erwartete BSOD Codes
- `BUGCODE_USB_DRIVER` (0x000000FE) — USB-Stack intern
- `PAGE_FAULT_IN_NONPAGED_AREA` (0x00000050) — Kernel liest ungültige Adresse
- `MEMORY_MANAGEMENT` (0x0000001A) — Heap-Korruption
- `IRQL_NOT_LESS_OR_EQUAL` (0x0000000A) — IRQL-Verletzung im Treiber

## VM Setup Checkliste
- [ ] Hyper-V / VirtualBox installiert
- [ ] USB Passthrough für Blue Pill aktiviert
- [ ] VM-Snapshot vor jedem Test gespeichert
- [ ] Kernel Crash Dumps aktiviert: `wmic RECOVEROS set DebugInfoType=1`
- [ ] WinDbg installiert (Windows SDK)
