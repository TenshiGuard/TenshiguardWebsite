if (-not (Test-Path $root)) {
    New-Item -ItemType Directory -Path $root | Out-Null
}

# Check for Python
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) {
    Write-Host "Python not found. Attempting to install via winget..."
    try {
        winget install -e --id Python.Python.3.11 --scope machine --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        $py = (Get-Command python -ErrorAction SilentlyContinue)
    }
    catch {
        Write-Host "Winget failed. Please install Python 3 manually and re-run."
        exit 1
    }
}

if (-not $py) {
    Write-Host "Python still not found. Please restart PowerShell or install Python manually."
    exit 1
}

Write-Host "Setting up virtual environment..."
Set-Location $root
if (-not (Test-Path "$root\venv")) {
    & $py.Source -m venv venv
}

Write-Host "Installing dependencies..."
& "$root\venv\Scripts\pip" install --upgrade pip requests psutil

Write-Host "Fetching agent client..."
$client = "http://127.0.0.1:5002/install/agent/client/$OrgToken"
Invoke-WebRequest -Uri $client -OutFile "$root\agent_client.py"

Write-Host "Registering scheduled task (SYSTEM)..."
$taskName = "TenshiGuardAgent"
$action = New-ScheduledTaskAction -Execute "$root\venv\Scripts\python.exe" -Argument "$root\agent_client.py"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Write-Host "Installed successfully. Starting agent..."
Start-ScheduledTask -TaskName $taskName
