#!/usr/bin/env pwsh
# flash.ps1 — Flash STM32 Blue Pill via ST-Link + OpenOCD
# Usage: .\flash.ps1 [-FuzzMode 1]

param(
    [ValidateRange(1,6)]
    [int]$FuzzMode = 1
)

$ModeNames = @{
    1 = "wTotalLength TOO SMALL"
    2 = "wTotalLength TOO LARGE"
    3 = "String bLength=0xFF Overflow"
    4 = "wMaxPacketSize=0xFF"
    5 = "bNumInterfaces=16 (Overflow)"
    6 = "D+ Reconnect Loop"
}

Write-Host ""
Write-Host "=== STM32 USB Fuzzer Flash Script ==="
Write-Host "Mode $FuzzMode : $($ModeNames[$FuzzMode])"
Write-Host ""

# Build
Write-Host "[1/2] Building..."
$env:FUZZ_MODE = $FuzzMode
make FUZZ_MODE=$FuzzMode clean all
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed!"
    exit 1
}

# Flash via OpenOCD
Write-Host "[2/2] Flashing via ST-Link..."
openocd -f interface/stlink-v2.cfg -f target/stm32f1x.cfg `
    -c "program stm32-usb-fuzzer.bin 0x08000000 verify reset exit"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "SUCCESS: Blue Pill flashed with Fuzz Mode $FuzzMode" -ForegroundColor Green
    Write-Host "Next steps:"
    Write-Host "  1. Connect Blue Pill Micro-USB to test machine"
    Write-Host "  2. Pass USB device through to Windows 11 VM"
    Write-Host "  3. Watch for BSOD or Event Viewer errors"
    Write-Host "  4. Copy C:\Windows\MEMORY.DMP from VM for WinDbg analysis"
} else {
    Write-Error "Flash failed! Is ST-Link connected? Is OpenOCD installed?"
}
