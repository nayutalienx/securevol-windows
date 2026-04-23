[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step {
    param([string]$Message)
    Write-Host "[SecureVol] $Message"
}

if (-not (Test-IsAdministrator)) {
    Write-Step 'Re-launching updater elevated'
    $arguments = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', ('"{0}"' -f $PSCommandPath)
    )

    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments | Out-Null
    exit 0
}

function Wait-ForServiceState {
    param(
        [string]$Name,
        [string]$DesiredState,
        [int]$TimeoutSeconds = 8
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            return $DesiredState -eq 'Absent'
        }

        if ($svc.State -eq $DesiredState) {
            return $true
        }

        Start-Sleep -Milliseconds 350
    } while ((Get-Date) -lt $deadline)

    return $false
}

function Stop-ServiceHard {
    param([string]$Name)

    $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        return
    }

    if ($svc.State -ne 'Stopped') {
        Write-Step "Stopping $Name"
        sc.exe stop $Name | Out-Null
        if (-not (Wait-ForServiceState -Name $Name -DesiredState 'Stopped' -TimeoutSeconds 6)) {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.ProcessId -ne 0) {
                Write-Step "Force-stopping $Name PID $($svc.ProcessId)"
                taskkill /F /T /PID $svc.ProcessId | Out-Null
            }

            if (-not (Wait-ForServiceState -Name $Name -DesiredState 'Stopped' -TimeoutSeconds 6)) {
                throw "$Name did not reach the Stopped state."
            }
        }
    }

    $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.ProcessId -ne 0) {
        throw "$Name still has a live process (PID $($svc.ProcessId)) after stop."
    }
}

function Copy-WithRetry {
    param(
        [string]$Source,
        [string]$Destination
    )

    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            Copy-Item -Path (Join-Path $Source '*') -Destination $Destination -Recurse -Force
            return
        }
        catch {
            if ($attempt -eq 4) {
                throw
            }

            Start-Sleep -Seconds 1
        }
    }
}

$root = Split-Path -Parent $PSScriptRoot
$sourceDir = Join-Path $root 'out\service-update'
$targetDir = Join-Path $root 'out\service'

if (-not (Test-Path $sourceDir)) {
    throw "Service update payload not found at '$sourceDir'."
}

Stop-ServiceHard -Name 'SecureVolSvc'

Write-Step 'Copying updated service payload'
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
Copy-WithRetry -Source $sourceDir -Destination $targetDir

Write-Step 'Starting SecureVolSvc'
Start-Service -Name SecureVolSvc
if (-not (Wait-ForServiceState -Name 'SecureVolSvc' -DesiredState 'Running' -TimeoutSeconds 8)) {
    throw 'SecureVolSvc did not reach the Running state after the update.'
}

$final = Get-Service -Name SecureVolSvc
Write-Step "SecureVolSvc status: $($final.Status)"
