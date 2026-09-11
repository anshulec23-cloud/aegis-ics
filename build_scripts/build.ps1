Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Aegis ICS v2.5.0 — Standalone Executable Build" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Clean previous build artifacts
Write-Host "[1/3] Purging previous build artifacts..." -ForegroundColor Yellow
if (Test-Path "build") { Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" -ErrorAction SilentlyContinue }

# Execute PyInstaller compilation
Write-Host "[2/3] Compiling AegisICS.exe with PyInstaller..." -ForegroundColor Yellow
python -m PyInstaller build_scripts/AegisICS.spec --noconfirm --clean

# Verify binary output
Write-Host "[3/3] Verifying output binary..." -ForegroundColor Yellow
$targetExe = "dist\AegisICS.exe"
if (Test-Path $targetExe) {
    $fileInfo = Get-Item $targetExe
    $sizeMB = $fileInfo.Length / 1MB
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host " BUILD SUCCESS: $targetExe" -ForegroundColor Green
    Write-Host (" File size: {0:N2} MB ({1:N0} bytes)" -f $sizeMB, $fileInfo.Length) -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
} else {
    Write-Host "==================================================" -ForegroundColor Red
    Write-Host " BUILD FAILED: $targetExe not found!" -ForegroundColor Red
    Write-Host "==================================================" -ForegroundColor Red
    exit 1
}
