# Aegis ICS - One-Click Service Launcher

$ErrorActionPreference = "Stop"

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         AEGIS ICS ONE-CLICK SERVICE LAUNCHER             " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Select the build version to launch:"
Write-Host " [1] Aegis Version 1.0.0 (Zero-Trust OT System, TLS, Trust Engine)"
Write-Host " [2] Aegis Version 2.0.0 (Stuxnet-Proof SCADA, SQL Auditing, Stats)"
Write-Host " [3] Clean up and stop all running Aegis services"
Write-Host " [4] Exit"
Write-Host ""

$choice = Read-Host "Enter option [1-4]"

if ($choice -eq "1") {
    Write-Host "[*] Initializing Aegis Version 1.0.0..." -ForegroundColor Yellow
    
    # 1. Environment Setup (.env)
    if (-not (Test-Path ".env")) {
        Write-Host " -> Creating default .env configuration..." -ForegroundColor Yellow
        Copy-Item ".env.example" ".env"
        (Get-Content ".env") `
            -replace "FLASK_SECRET_KEY=", "FLASK_SECRET_KEY=aegis_v1_super_secret" `
            -replace "DEVICE_KEY_ESP32_001=", "DEVICE_KEY_ESP32_001=device_key_001" `
            -replace "DEVICE_KEY_ESP32_002=", "DEVICE_KEY_ESP32_002=device_key_002" | Set-Content ".env"
    }

    # 2. Cryptographic Certificates Generation
    if (-not (Test-Path "certs/ca.crt")) {
        Write-Host " -> Generating TLS certs for device simulator..." -ForegroundColor Yellow
        & .\.venv\Scripts\python.exe certs/generate_certs.py --out-dir certs --device-id ESP32_001 --device-id ESP32_002
    }

    # 3. Start MQTT Broker (Mosquitto with TLS)
    Write-Host " -> Starting Mosquitto MQTT Broker..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "Write-Host '--- Mosquitto MQTT Broker (TLS Enabled) ---' -ForegroundColor Green; mosquitto -c server/mqtt_broker/mosquitto.conf"

    # 4. Start Flask Server (V1 API)
    Write-Host " -> Starting Flask API Server..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "Write-Host '--- Aegis V1 API Server ---' -ForegroundColor Cyan; .\.venv\Scripts\python.exe -m server.api.app"

    # 5. Start Device Simulator
    Write-Host " -> Starting ESP32 Device Simulator..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "Write-Host '--- ESP32 Telemetry Simulator ---' -ForegroundColor Magenta; .\.venv\Scripts\python.exe esp32_sim/simulator.py --config esp32_sim/device_config.json"

    # 6. Launch browser
    Write-Host "[+] Launching web browser..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:5000"
}
elseif ($choice -eq "2") {
    Write-Host "[*] Initializing Aegis Version 2.0.0 (Hardened Build)..." -ForegroundColor Yellow
    
    # 1. Start MQTT Broker (Plain MQTT for V2)
    Write-Host " -> Starting Mosquitto MQTT Broker..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "Write-Host '--- Mosquitto MQTT Broker (Plain) ---' -ForegroundColor Green; mosquitto"

    # 2. Start Flask Server (Version 2 App)
    Write-Host " -> Starting V2 SCADA Server..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "Write-Host '--- Aegis V2 SCADA Server ---' -ForegroundColor Cyan; cd version-two; ..\.venv\Scripts\python.exe app.py"

    # 3. Start Simulator (Version 2 Simulator)
    Write-Host " -> Starting V2 Device Simulator..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "Write-Host '--- Aegis V2 ESP32 Simulator ---' -ForegroundColor Magenta; cd version-two; ..\.venv\Scripts\python.exe simulator.py"

    # 4. Launch browser
    Write-Host "[+] Launching web browser..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:5000"
}
elseif ($choice -eq "3") {
    Write-Host "[*] Terminating running Aegis services..." -ForegroundColor Yellow
    
    # Kill Mosquitto Broker
    Get-Process -Name "mosquitto" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Kill Python processes running servers/simulators
    Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object { 
        $_.CommandLine -like "*server.api.app*" -or 
        $_.CommandLine -like "*simulator.py*" -or 
        $_.CommandLine -like "*app.py*" 
    } | Stop-Process -Force
    
    Write-Host "[+] All running services have been stopped." -ForegroundColor Green
}
else {
    Write-Host "Exiting."
}
